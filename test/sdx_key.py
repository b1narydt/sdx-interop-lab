"""LAB_SELF_TEST_ONLY: a Python standard-library oracle for VA-KEY, the KEYS §1.12 known-answer
tests under the laboratory deployment profile. Curve arithmetic, HKDF and HMAC come from
test/sdx_ec.py. It shares no code with the Node.js oracle and imports no generator code."""

import json
import os
import re
import unicodedata

import sdx_ec

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CURVES = {'p256': sdx_ec.P256, 'secp256k1': sdx_ec.SECP256K1}


class KeyRefusal(Exception):
    def __init__(self, detail):
        super().__init__(detail)
        self.detail = detail


def space_form(name):
    return isinstance(name, str) and re.fullmatch(r'[a-z0-9 ]{5,280}', name) is not None and '  ' not in name and re.search(r'(^| )protocol$', name) is None


def split(profile, ikm):
    if len(ikm) != 64:
        raise KeyRefusal('root-length')
    labels = profile['derivation']['curveLabels']
    k1 = sdx_ec.hkdf_sha256(ikm, b'', labels['secp256k1'].encode(), 32)
    p = sdx_ec.hkdf_sha256(ikm, b'', labels['p256'].encode(), 32)
    for curve, seed in ((sdx_ec.SECP256K1, k1), (sdx_ec.P256, p)):
        if not 1 <= int.from_bytes(seed, 'big') < curve.n:
            raise KeyRefusal('seed-out-of-range')
    return k1, p


def check_offset(curve_name, mac):
    h = int.from_bytes(mac, 'big')
    if h == 0 or h >= CURVES[curve_name].n:
        raise KeyRefusal(f'offset-out-of-range:{curve_name}')
    return h


def validate(profile, key_path):
    kw = profile['derivation']['keyPath']['keywords']
    purposes = [p['purpose'] for p in profile['derivation']['keyPath']['purposes']]
    if not 1 <= len(key_path.encode('utf-8')) <= 1033:
        return 'length'
    s = key_path.split('/')
    if any(not x for x in s):
        return 'segment'
    if len(s) % 2:
        return 'structure'
    if s[0] != kw['level1'] or (len(s) >= 4 and s[2] != kw['level2']):
        return 'keyword'
    if len(s) >= 6:
        if s[4] == kw['level3Session']:
            return None if len(s) == 6 else 'structure'
        if s[4] == kw['level3Delegation']:
            return None if len(s) == 8 and s[6] == kw['delegationActor'] else 'structure'
        if s[4] != kw['level3']:
            return 'keyword'
    if len(s) == 8:
        if s[6] not in purposes:
            return 'purpose'
        if s[6] == 'field' and len(s[7].encode('utf-8')) > 256:
            return 'field-name'
    if len(s) > 8:
        return 'structure'
    return None


def derive(profile, req, side=None):
    side = side or req['side']
    curve = CURVES[req['curve']]
    k1, p = split(profile, bytes.fromhex(req['rootIkm']))
    seed = int.from_bytes(p if req['curve'] == 'p256' else k1, 'big')
    key_path = unicodedata.normalize('NFC', req['keyPath'])
    bad = validate(profile, key_path)
    if bad:
        raise KeyRefusal(f'key-path:{bad}')
    ns = profile['derivation']['namespaces']
    role = next((r for r, v in ns.items() if v == req['namespace']), None)
    if role is None:
        raise KeyRefusal('namespace')
    if (profile['derivation'].get('namespaceUse') or {}).get(role, '').startswith('Reserved'):
        raise KeyRefusal('namespace-reserved')
    identifier = f"{profile['derivation']['securityLevel']}-{req['namespace']}-{key_path}"
    own_pub = sdx_ec.base_mul(curve, seed)
    cp = own_pub if req['counterparty'] == 'self' else sdx_ec.decode_point(curve, bytes.fromhex(req['counterparty']))
    shared = sdx_ec.compress(curve, sdx_ec.mul(curve, seed, cp))
    h = check_offset(req['curve'], sdx_ec.hmac_sha256(shared, identifier.encode('utf-8')))
    if side == 'own':
        child = (seed + h) % curve.n
        return identifier, child, sdx_ec.base_mul(curve, child)
    return identifier, None, sdx_ec.add(curve, cp, sdx_ec.base_mul(curve, h))


def profile_failures(doc):
    d = doc['derivation']
    out = []
    ns = d['namespaces']
    for role in ('encryption', 'signing', 'delegation', 'transportAuthentication', 'rotation', 'handoff'):
        if not space_form(ns.get(role)):
            out.append(f'namespace-grammar:{role}')
    if len(set(ns.values())) != len(ns):
        out.append('namespaces-distinct')
    for c in ('secp256k1', 'p256'):
        if re.fullmatch(r'[\x21-\x7e]+', d['curveLabels'].get(c) or '') is None:
            out.append(f'label:{c}')
    if d['curveLabels'].get('secp256k1') and d['curveLabels']['secp256k1'] == d['curveLabels'].get('p256'):
        out.append('labels-distinct')
    for k, w in d['keyPath']['keywords'].items():
        if not w or '/' in w:
            out.append(f'keyword:{k}')
    purposes = [p['purpose'] for p in d['keyPath']['purposes']]
    for p in purposes:
        if not p or '/' in p:
            out.append(f'purpose:{p}')
    if len(set(purposes)) != len(purposes):
        out.append('purposes-distinct')
    if not (d.get('credentialType') or {}).get('value'):
        out.append('credential-type')
    return out


def perform(profile, req):
    try:
        op = req['op']
        if op == 'split':
            k1, p = split(profile, bytes.fromhex(req['rootIkm']))
            return {'secp256k1Seed': k1.hex(), 'p256Seed': p.hex()}
        if op == 'derive':
            curve = CURVES[req['curve']]
            identifier, child, pub = derive(profile, req)
            out = {'identifier': identifier, 'publicKey': sdx_ec.compress(curve, pub).hex()}
            if req['side'] == 'own':
                out['privateKey'] = sdx_ec.int32(child).hex()
            return out
        if op == 'symmetric':
            curve = CURVES[req['curve']]
            identifier, child, _ = derive(profile, req, 'own')
            _, _, theirs = derive(profile, req, 'counterparty')
            return {'identifier': identifier, 'key': sdx_ec.int32(sdx_ec.mul(curve, child, theirs)[0]).hex()}
        if op == 'validate':
            bad = validate(profile, req['keyPath'])
            return {'verdict': 'refused', 'detail': bad} if bad else {'verdict': 'accepted'}
        if op == 'offset':
            return {'scalar': sdx_ec.int32(check_offset(req['curve'], bytes.fromhex(req['hmac']))).hex()}
        if op == 'profile':
            if isinstance(req['profile'], str):
                with open(os.path.join(ROOT, req['profile']), 'rb') as handle:
                    doc = json.loads(handle.read())
            else:
                doc = req['profile']['inline']
            failures = profile_failures(doc)
            return {'verdict': 'nonconforming' if failures else 'conforming', 'failures': failures}
        raise ValueError(op)
    except KeyRefusal as error:
        return {'refusal': {'class': 'key', 'detail': error.detail}}


def run_case(profile, kase):
    actual = perform(profile, kase['request'])
    return actual == kase['expect'], actual
