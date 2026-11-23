"""LAB_SELF_TEST_ONLY: a Python standard-library oracle for SDX v0.1 record envelopes and
record signatures (VA-ENV, VA-SIG) under the laboratory deployment profile.

It is an ORACLE, not an implementation: ENV §16 requires implementations to use a JOSE
implementation, and this module performs the JOSE steps by hand (ECDH on P-256, the RFC 7518
Concat KDF, AES key unwrap, AES-GCM and ES256 verification) on the pure-Python primitives of
test/sdx_ec.py, with the deterministic CBOR of test/sdx_anc.py. LZMA uses the standard
library's lzma module (FORMAT_ALONE), which decodes a stream with or without an end-of-stream
marker and cannot tell them apart; the Node oracle's own decoder checks the marker.

It shares no code with the Node.js oracle in src/sdx/ and imports no generator code. It reads
only the suite files and the laboratory deployment profile.
"""

import base64
import hashlib
import hmac
import json
import lzma
import re
import struct
import unicodedata

import sdx_anc
import sdx_ec

P256 = sdx_ec.P256
ECDH_ALG = 'ECDH-ES+A256KW'
GCMKW_ALG = 'A256GCMKW'
MIN_ITERATIONS = 200000
TWO_32 = 2 ** 32


class Refusal(Exception):
    def __init__(self, cls, detail):
        super().__init__(f'{cls}: {detail}')
        self.cls = cls
        self.detail = detail


def refuse(cls, detail):
    raise Refusal(cls, detail)


def is_map(v):
    return isinstance(v, sdx_anc.CborMap)


def has(m, k):
    return any(type(x) is str and x == k for x in m.keys())


def is_text(v):
    return isinstance(v, str)


def is_uint(v):
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= sdx_anc.MAX_SAFE or (isinstance(v, float) and v.is_integer() and 0 <= v <= sdx_anc.MAX_SAFE)


def is_bytes(v, n=None):
    return isinstance(v, bytes) and (n is None or len(v) == n)


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def b64u_canonical(text):
    """Canonical base64url: the alphabet, no padding, no stray bits (ENV §9.1 rule 2)."""
    if not isinstance(text, str) or not re.fullmatch(r'[A-Za-z0-9_-]*', text) or len(text) % 4 == 1:
        return None
    data = base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
    return data if b64u(data) == text else None


def plain(v):
    if is_map(v):
        return {k: plain(x) for k, x in v.pairs}
    return v


# ---------------------------------------------------------------- KEYS §1.4.2 and §1.8.2

def split_root(profile, ikm):
    labels = profile['derivation']['curveLabels']
    k1, p = sdx_ec.split_ikm(ikm, labels['secp256k1'].encode(), labels['p256'].encode())
    seed = int.from_bytes(p, 'big')
    return {'seed': seed, 'R': sdx_ec.base_mul(P256, seed)}


def key_path(profile, acct, rid, aid):
    kw = profile['derivation']['keyPath']['keywords']
    return f"{kw['level1']}/{acct}/{kw['level2']}/{rid}/{kw['level3']}/{aid}"


def outer_id(profile, acct, rid, aid):
    d = profile['derivation']
    return f"{d['securityLevel']}-{d['namespaces']['encryption']}-{key_path(profile, acct, rid, aid)}"


def field_id(profile, acct, rid, aid, name):
    return f'{outer_id(profile, acct, rid, aid)}/field/{name}'


def sign_id(profile, acct, rid, aid):
    d = profile['derivation']
    return f"{d['securityLevel']}-{d['namespaces']['signing']}-{key_path(profile, acct, rid, aid)}"


def own_child(seed, counterparty, identifier):
    d = sdx_ec.sdx_child_private(P256, seed, counterparty, identifier)
    return d, sdx_ec.compress(P256, sdx_ec.base_mul(P256, d)).hex()


def their_child(seed, counterparty, identifier):
    return sdx_ec.compress(P256, sdx_ec.sdx_child_public(P256, seed, counterparty, identifier)).hex()


# ---------------------------------------------------------------- JOSE steps by hand (oracle)

def jwk_point(jwk):
    if not isinstance(jwk, dict) or jwk.get('kty') != 'EC' or jwk.get('crv') != 'P-256' or 'd' in jwk:
        return None
    x, y = b64u_canonical(jwk.get('x')), b64u_canonical(jwk.get('y'))
    if x is None or y is None or len(x) != 32 or len(y) != 32:
        return None
    point = (int.from_bytes(x, 'big'), int.from_bytes(y, 'big'))
    return point if point[0] < P256.p and point[1] < P256.p and sdx_ec.is_on_curve(P256, point) else None


def protected_object(text):
    data = b64u_canonical(text)
    if data is None:
        return None
    try:
        value = json.loads(data.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def validate_for_decline(jwe, in_record):
    """ENV §9.1 rule 2: everything decryption would validate, before a decline is honoured."""
    def bad(what):
        refuse('integrity', f'slot-validation:{what}')
    if not is_map(jwe):
        bad('jwe-shape')
    members = ['protected', 'recipients', 'iv', 'ciphertext', 'tag'] if in_record else ['protected', 'recipients', 'iv', 'tag']
    for m in members:
        if not has(jwe, m):
            bad(f'missing-{m}')
    if not in_record and has(jwe, 'ciphertext'):
        bad('detached-ciphertext')
    for m in ['protected', 'iv', 'tag'] + (['ciphertext'] if in_record else []):
        if b64u_canonical(jwe.get(m)) is None:
            bad(f'base64url-{m}')
    if len(b64u_canonical(jwe.get('iv'))) != 12:
        bad('iv-length')
    if len(b64u_canonical(jwe.get('tag'))) != 16:
        bad('tag-length')
    prot = protected_object(jwe.get('protected'))
    if prot is None:
        bad('protected')
    if prot.get('enc') != 'A256GCM':
        bad('enc')
    shared = plain(jwe.get('unprotected')) if has(jwe, 'unprotected') else {}
    if not isinstance(shared, dict):
        bad('unprotected')
    recipients = jwe.get('recipients')
    if not isinstance(recipients, list) or not recipients:
        bad('recipients')
    for r in recipients:
        if not is_map(r):
            bad('recipient-shape')
        header = plain(r.get('header')) if has(r, 'header') else {}
        if not isinstance(header, dict):
            bad('recipient-header')
        names = list(prot) + list(shared) + list(header)
        if len(set(names)) != len(names):
            bad('header-union-repeats')
        union = {**prot, **shared, **header}
        ek = b64u_canonical(r.get('encrypted_key'))
        if ek is None:
            bad('base64url-encrypted_key')
        if union.get('alg') == ECDH_ALG:
            kid = union.get('kid')
            if not isinstance(kid, str) or not re.fullmatch(r'[0-9a-f]{66}', kid):
                bad('kid')
            try:
                sdx_ec.decode_point(P256, bytes.fromhex(kid))
            except sdx_ec.EcError:
                bad('kid-point')
            if jwk_point(union.get('epk')) is None:
                bad('epk')
            if len(ek) != 40:
                bad('encrypted_key-length')
        elif union.get('alg') == GCMKW_ALG:
            kwiv, kwtag = b64u_canonical(union.get('iv')), b64u_canonical(union.get('tag'))
            if kwiv is None or len(kwiv) != 12 or kwtag is None or len(kwtag) != 16:
                bad('gcmkw-iv-tag')
            if len(ek) != 32:
                bad('encrypted_key-length')
        else:
            bad('alg')


def open_jwe(jwe, d, kid, what):
    """Opens a JWE through the identity slot named kid with child private key d."""
    def bad(detail):
        refuse('integrity', f'{what}:{detail}')
    if not is_map(jwe):
        bad('jwe-shape')
    protected_text = jwe.get('protected')
    prot = protected_object(protected_text)
    if prot is None:
        bad('protected')
    if prot.get('enc') != 'A256GCM':
        bad('enc')
    iv, tag, ciphertext = b64u_canonical(jwe.get('iv')), b64u_canonical(jwe.get('tag')), b64u_canonical(jwe.get('ciphertext'))
    if iv is None or len(iv) != 12 or tag is None or len(tag) != 16 or ciphertext is None:
        bad('members')
    shared = plain(jwe.get('unprotected')) if has(jwe, 'unprotected') else {}
    for r in jwe.get('recipients'):
        if not is_map(r):
            continue
        header = plain(r.get('header')) or {}
        union = {**prot, **shared, **header}
        if union.get('alg') != ECDH_ALG or union.get('kid') != kid:
            continue
        epk = jwk_point(union.get('epk'))
        if epk is None:
            bad('epk')
        ek = b64u_canonical(r.get('encrypted_key'))
        if ek is None or len(ek) != 40:
            bad('encrypted_key')
        try:
            z = sdx_ec.ecdh_x(P256, d, epk)
            cek = sdx_ec.aes_key_unwrap(sdx_ec.concat_kdf_sha256(z, 256, ECDH_ALG.encode()), ek)
            return sdx_ec.aes_gcm_decrypt(cek, iv, protected_text.encode('ascii'), ciphertext, tag)
        except sdx_ec.EcError:
            bad('decrypt')
    bad('no-slot')


def open_convergent(jwe, kek):
    for r in jwe.get('recipients'):
        header = plain(r.get('header')) or {}
        if header.get('alg') != GCMKW_ALG:
            continue
        cek = sdx_ec.aes_gcm_decrypt(kek, b64u_canonical(header['iv']), b'', b64u_canonical(r.get('encrypted_key')), b64u_canonical(header['tag']))
        return sdx_ec.aes_gcm_decrypt(cek, b64u_canonical(jwe.get('iv')), jwe.get('protected').encode('ascii'), b64u_canonical(jwe.get('ciphertext')), b64u_canonical(jwe.get('tag')))
    return None


# ---------------------------------------------------------------- ES256 and the ENV §8.3 candidates

def encode_superseded(value, depth=0, position='top'):
    """ENV §8.3 superseded shape: integers needing the 8-byte head written as binary64."""
    if isinstance(value, bool) or value is None or value is sdx_anc.UNDEFINED or isinstance(value, (str, bytes)):
        return sdx_anc.encode(value, depth, position)
    if isinstance(value, (int, float)):
        integral = isinstance(value, int) or (value == value and value.is_integer() and abs(value) <= sdx_anc.MAX_SAFE)
        if integral and (int(value) >= TWO_32 or int(value) < -TWO_32):
            return b'\xfb' + struct.pack('>d', float(value))
        return sdx_anc.encode(value, depth, position)
    if isinstance(value, list):
        return sdx_anc._head(4, len(value)) + b''.join(encode_superseded(v, depth + 1, 'element') for v in value)
    pairs = value.pairs if is_map(value) else list(value.items())
    encoded = sorted((sdx_anc.encode(k, depth + 1, 'key'), encode_superseded(v, depth + 1, 'member')) for k, v in pairs if v is not sdx_anc.UNDEFINED)
    return sdx_anc._head(5, len(encoded)) + b''.join(k + v for k, v in encoded)


def es256_verify(kid, message, signature):
    if not isinstance(kid, str) or not re.fullmatch(r'[0-9a-f]{66}', kid) or len(signature) != 64:
        return False
    try:
        point = sdx_ec.decode_point(P256, bytes.fromhex(kid))
    except sdx_ec.EcError:
        return False
    r, s = int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:], 'big')
    return sdx_ec.ecdsa_verify(P256, point, hashlib.sha256(message).digest(), r, s)


def verify_signatures(sigs, hdr, au, pr):
    if not is_map(sigs):
        refuse('signature', 'sigs-shape')
    if sigs.get('payload') != '':
        refuse('signature', 'payload-not-empty')
    entries = sigs.get('signatures')
    if not isinstance(entries, list):
        refuse('signature', 'signatures-shape')
    if not entries:
        refuse('signature', 'empty-signature-list')
    signed = {'hdr': hdr, 'au': au, 'pr': pr}
    for shape, build in (('current', sdx_anc.encode), ('superseded', encode_superseded)):
        payload = b64u(build(signed))
        verified = []
        for entry in entries:
            if not is_map(entry):
                continue
            prot = protected_object(entry.get('protected'))
            sig = b64u_canonical(entry.get('signature'))
            if prot is None or prot.get('alg') != 'ES256' or sig is None:
                continue
            if es256_verify(prot.get('kid'), f"{entry.get('protected')}.{payload}".encode('ascii'), sig):
                verified.append({'kid': prot['kid'], 'shape': shape, 'signature': sig})
        if verified:
            return verified
    refuse('signature', 'no-signature-verifies')


# ---------------------------------------------------------------- slots

ALLOWED_SCHEMES = ('overlay', 's3', 'gs', 'file', 'https')


def to_json(v):
    if isinstance(v, bytes):
        return {'$bytes': v.hex()}
    if is_map(v):
        return {k: to_json(x) for k, x in sorted(v.pairs, key=lambda p: p[0])}
    if isinstance(v, list):
        return [to_json(x) for x in v]
    if isinstance(v, float) and v.is_integer():
        return int(v)
    return v


def marker_rules(slot):
    if not has(slot, 'u'):
        return False
    for m in ('v', 'jwe', 'im', 'je'):
        if has(slot, m):
            refuse('structure', 'marker-with-value')
    if slot.get('u') is not True:
        refuse('structure', 'marker-not-true')
    if len(slot.keys()) != 2:
        refuse('structure', 'marker-members')
    return True


def check_manifest(im):
    if not is_map(im) or len(im.keys()) != 3 or not is_bytes(im.get('sha'), 32) or not is_text(im.get('u')) or not is_uint(im.get('sz')):
        refuse('integrity', 'manifest-shape')
    scheme = im.get('u').split(':', 1)[0] if ':' in im.get('u') else ''
    if scheme not in ALLOWED_SCHEMES:
        refuse('integrity', 'uri-scheme')
    return scheme


def plain_slot(slot):
    if not is_map(slot) or not is_text(slot.get('n')):
        refuse('structure', 'slot-shape')
    if marker_rules(slot):
        return {'n': slot.get('n'), 'state': 'unset'}
    if has(slot, 'v') and (has(slot, 'im') or has(slot, 'jwe') or has(slot, 'je')):
        refuse('structure', 'slot-mixes-members')
    if has(slot, 'v'):
        return {'n': slot.get('n'), 'state': 'value', 'value': slot.get('v')}
    if has(slot, 'im'):
        if check_manifest(slot.get('im')) == 'overlay':
            refuse('integrity', 'overlay-could-not-ask')
        return {'n': slot.get('n'), 'state': 'unavailable'}
    refuse('structure', 'slot-without-value')


def slot_names(slots, where):
    names = set()
    for s in slots:
        if not is_map(s) or not is_text(s.get('n')):
            refuse('structure', f'{where}-slot-shape')
        if s.get('n') in names:
            refuse('structure', f'duplicate-{where}-slot')
        names.add(s.get('n'))


def check_header(hdr):
    def need(ok, what):
        if not ok:
            refuse('structure', f'hdr-{what}')
    need(is_map(hdr), 'shape')
    need(is_text(hdr.get('aid')), 'aid')
    need(is_uint(hdr.get('ep')), 'ep')
    need(is_text(hdr.get('f')), 'f')
    need(is_uint(hdr.get('mv')), 'mv')
    need(is_uint(hdr.get('tm')), 'tm')
    need(is_bytes(hdr.get('pk'), 33), 'pk')
    need(isinstance(hdr.get('ds'), bool), 'ds')
    if hdr.get('pks') not in ('root', 'delegate'):
        refuse('structure', 'pks')
    dref = hdr.get('dref') if has(hdr, 'dref') else []
    need(isinstance(dref, list) and all(is_bytes(x, 16) for x in dref), 'dref')
    fields = hdr.get('fields')
    need(isinstance(fields, list) and len(fields) > 0, 'fields')
    seen = set()
    for d in fields:
        need(is_map(d) and is_text(d.get('n')), 'descriptor')
        if d.get('sn') not in ('pu', 'au', 'pr'):
            refuse('structure', 'sn')
        if d.get('pl') not in ('ch', 'ov', 'ex'):
            refuse('structure', 'pl')
        if has(d, 'cv'):
            if d.get('cv') is not True:
                refuse('structure', 'cv-not-true')
            if d.get('sn') != 'pr':
                refuse('structure', 'cv-not-private')
        if d.get('n') in seen:
            refuse('structure', 'duplicate-field-name')
        seen.add(d.get('n'))
    return fields, dref


def has_convergent_material(jwe):
    if not is_map(jwe):
        return False
    prot = protected_object(jwe.get('protected'))
    slot = any(is_map(r) and (plain(r.get('header')) or {}).get('alg') == GCMKW_ALG for r in (jwe.get('recipients') or []))
    if prot is None or not slot:
        return False
    it = prot.get('iter')
    return isinstance(it, int) and not isinstance(it, bool) and it >= MIN_ITERATIONS and 'salt' in prot and prot['salt'] not in ('', None)


# ---------------------------------------------------------------- the decode flow (ENV §14)

def read_envelope(profile, request):
    ctx = {'tier': 'nothing', 'aid': None}
    try:
        return _read(profile, request, ctx)
    except Refusal as error:
        return {'tier': ctx['tier'], 'verdict': 'refused', 'refusal': {'class': error.cls, 'detail': error.detail}, 'aid': ctx['aid'], 'fields': []}


def _read(profile, request, ctx):
    reader = split_root(profile, bytes.fromhex(request['reader']['rootIkm']))
    counterparty = reader['R'] if request['as'] == 'writer' else sdx_ec.decode_point(P256, bytes.fromhex(request['writer']['R']))
    acct, rid = request['writer']['acct'], request['writer']['rid']
    try:
        env = sdx_anc.decode(bytes.fromhex(request['envelope']))
    except sdx_anc.CborError as error:
        refuse('format', f'envelope-cbor:{error.code}')
    # The keyless ANC §11.1 gate, which is the reader's own pre-unwrap gate.
    if not is_map(env):
        refuse('format', 'envelope-shape')
    if env.get('proto') != profile['formatIdentifier']['value']:
        refuse('format', 'proto')
    pu, outer = env.get('pu'), env.get('outer')
    if not isinstance(pu, list):
        refuse('format', 'pu')
    if not is_map(outer) or not all(is_text(outer.get(m)) for m in ('iv', 'ciphertext', 'tag')):
        refuse('format', 'outer-shape')
    slot_names(pu, 'pu')
    public = [plain_slot(s) for s in pu]
    prot = protected_object(outer.get('protected'))
    if prot is None or not is_text(prot.get('aid')):
        refuse('integrity', 'protected-aid')
    ctx['aid'] = prot['aid']
    d, kid = own_child(reader['seed'], counterparty, outer_id(profile, acct, rid, prot['aid']))
    recipients = outer.get('recipients') if isinstance(outer.get('recipients'), list) else []
    mine = any(is_map(r) and is_map(r.get('header')) and r.get('header').get('kid') == kid and r.get('header').get('alg') == ECDH_ALG for r in recipients)
    if not mine:
        return {'tier': 'nothing', 'verdict': 'accepted', 'aid': prot['aid'], 'fields': [project(s['n'], 'pu', s) for s in public]}
    audit_bytes = open_jwe(outer, d, kid, 'outer')
    ctx['tier'] = 'audit'
    try:
        audit = sdx_anc.decode(audit_bytes)
    except sdx_anc.CborError as error:
        refuse('decode', f'audit-cbor:{error.code}')
    if not is_map(audit):
        refuse('structure', 'audit-shape')
    for k in audit.keys():
        if k not in ('hdr', 'sigs', 'au', 'pr'):
            refuse('structure', 'audit-member')
    for k in ('hdr', 'sigs', 'au', 'pr'):
        if not has(audit, k):
            refuse('structure', f'audit-missing-{k}')
    hdr, au, pr = audit.get('hdr'), audit.get('au'), audit.get('pr')
    if not is_map(hdr):
        refuse('structure', 'hdr-shape')
    if hdr.get('aid') != prot['aid']:
        refuse('integrity', 'aid-mismatch')
    verified = verify_signatures(audit.get('sigs'), hdr, au, pr)
    fields, dref = check_header(hdr)
    pk = hdr.get('pk').hex()
    if hdr.get('pks') == 'root':
        if dref:
            refuse('delegation-invalid', 'mixed-scope')
        if verified[0]['kid'] != pk:
            refuse('root-pk-mismatch', 'pk-not-signer')
        if request['as'] == 'writer':
            _, expected = own_child(reader['seed'], reader['R'], sign_id(profile, acct, rid, hdr.get('aid')))
            if verified[0]['kid'] != expected:
                refuse('root-pk-mismatch', 'kid-not-derived')
    else:
        if len(dref) != 1:
            refuse('delegation-invalid', 'bad-dref-length')
        if len(verified) != 1 or verified[0]['kid'] != pk:
            refuse('delegation-invalid', 'signer-binding')
    if not isinstance(au, list) or not isinstance(pr, list):
        refuse('structure', 'slot-arrays')
    slot_names(au, 'au')
    slot_names(pr, 'pr')
    descriptors = {d.get('n'): d for d in fields}
    placed = {}
    for array, sn in ((pu, 'pu'), (au, 'au'), (pr, 'pr')):
        for s in array:
            desc = descriptors.get(s.get('n'))
            if desc is None:
                refuse('structure', 'undeclared-slot')
            if desc.get('sn') != sn:
                refuse('structure', 'slot-sensitivity')
            if has(s, 'u') and desc.get('pl') != 'ch':
                refuse('structure', 'marker-not-in-record')
            placed[s.get('n')] = s
    for desc in fields:
        if desc.get('n') not in placed:
            refuse('structure', 'descriptor-without-slot')
    cv_declared = [desc for desc in fields if desc.get('cv') is True]
    for desc in cv_declared:
        s = placed[desc.get('n')]
        if has(s, 'u'):
            continue
        if not has_convergent_material(s.get('jwe') if has(s, 'jwe') else s.get('je')):
            refuse('structure', 'cv-backing-field')
    if cv_declared and not has_convergent_material(outer):
        refuse('structure', 'cv-backing-outer')
    values = {s['n']: s for s in public}
    for s in au:
        values[s.get('n')] = plain_slot(s)
    keys = {'reader': reader, 'counterparty': counterparty, 'acct': acct, 'rid': rid, 'aid': hdr.get('aid')}
    for s in pr:
        values[s.get('n')] = private_slot(profile, s, descriptors[s.get('n')], keys)
    dref_hex = [x.hex() for x in dref]
    return {
        'tier': 'audit', 'verdict': 'accepted', 'aid': prot['aid'],
        'hdr': {'f': hdr.get('f'), 'mv': hdr.get('mv'), 'ep': hdr.get('ep'), 'tm': to_json(hdr.get('tm')), 'pks': hdr.get('pks'), 'pk': pk, 'dref': dref_hex},
        'fields': [project(d.get('n'), d.get('sn'), values[d.get('n')]) for d in fields],
        'signature': {'kid': verified[0]['kid'], 'shape': verified[0]['shape']},
    }


def project(n, sn, slot):
    out = {'n': n, 'sn': sn, 'state': slot['state']}
    if slot['state'] == 'value':
        out['value'] = to_json(slot['value'])
        for k in ('filename', 'mediaType', 'meta'):
            if slot.get(k) is not None:
                out[k] = to_json(slot[k])
    return out


def lzma_alone(data):
    """Decompresses an alone stream; returns (declared size or None, output)."""
    declared = int.from_bytes(data[5:13], 'little') if len(data) >= 13 else None
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    out = decoder.decompress(data)
    if not decoder.eof or decoder.unused_data:
        raise lzma.LZMAError('stream does not end where the data ends')
    return (None if declared == 2 ** 64 - 1 else declared), out


def private_slot(profile, slot, desc, keys):
    n = slot.get('n')
    if marker_rules(slot):
        return {'n': n, 'state': 'unset'}
    in_record = has(slot, 'jwe')
    if in_record and (has(slot, 'v') or has(slot, 'im') or has(slot, 'je')):
        refuse('structure', 'slot-mixes-members')
    if not in_record and not (has(slot, 'je') and has(slot, 'im')):
        refuse('structure', 'private-slot-shape')
    if in_record != (desc.get('pl') == 'ch'):
        refuse('structure', 'slot-placement')
    jwe = slot.get('jwe') if in_record else slot.get('je')
    if not in_record:
        check_manifest(slot.get('im'))
    if not is_map(jwe) or not isinstance(jwe.get('recipients'), list):
        refuse('integrity', 'slot-validation:jwe-shape')
    if not jwe.get('recipients'):
        refuse('integrity', 'recipient-less')
    kids = [r.get('header').get('kid') for r in jwe.get('recipients') if is_map(r) and is_map(r.get('header')) and r.get('header').get('alg') == ECDH_ALG and is_text(r.get('header').get('kid'))]
    d, kid = own_child(keys['reader']['seed'], keys['counterparty'], field_id(profile, keys['acct'], keys['rid'], keys['aid'], n))
    if kid not in kids:
        validate_for_decline(jwe, in_record)
        return {'n': n, 'state': 'redacted'}
    if not in_record:
        return {'n': n, 'state': 'unavailable'}
    compressed = open_jwe(jwe, d, kid, f'field {n}')
    try:
        _, plaintext = lzma_alone(compressed)
    except lzma.LZMAError:
        refuse('decode', 'lzma:corrupt')
    try:
        t = sdx_anc.decode(plaintext)
    except sdx_anc.CborError as error:
        refuse('decode', f'tuple-cbor:{error.code}')
    if not isinstance(t, list) or not 1 <= len(t) <= 4:
        refuse('decode', 'tuple-shape')
    t = t + [None] * (4 - len(t))
    return {'n': n, 'state': 'value', 'value': t[0], 'filename': t[1], 'mediaType': t[2], 'meta': t[3]}


# ---------------------------------------------------------------- writer-side input rules

def write_refusal(request):
    seen = set()

    def recipients_of(name):
        for k, v in (request.get('fieldRecipients') or {}).items():
            if unicodedata.normalize('NFC', k) == name:
                return v
        return []
    for f in request['record']['fields']:
        name = unicodedata.normalize('NFC', f['n'])
        if not 1 <= len(name.encode('utf-8')) <= 256:
            return 'field-name-length'
        if '/' in name:
            return 'field-name-separator'
        if name in seen:
            return 'duplicate-field-name'
        seen.add(name)
        if 'cv' in f and f['cv'] is not True:
            return 'cv-not-true'
        if 'cv' in f and f['sn'] != 'pr':
            return 'cv-not-private'
        if f.get('blind') is True:
            if f['sn'] != 'pr':
                return 'blind-not-private'
            if 'cv' in f:
                return 'blind-cv'
            if not recipients_of(name):
                return 'blind-without-recipient'
        if f['sn'] == 'pr' and 'value' not in f:
            if f['pl'] != 'ch':
                return 'unset-externalised-private'
            if any(k in f for k in ('filename', 'mediaType', 'meta')):
                return 'unset-with-metadata'
        if f['sn'] == 'pr' and 'value' in f and (1 if f.get('cv') is True else 0) + (0 if f.get('blind') is True else 1) + len(recipients_of(name)) == 0:
            return 'unopenable-slot'
    return None


# ---------------------------------------------------------------- ENV §4

def secrets(data, iterations=MIN_ITERATIONS):
    if not isinstance(iterations, int) or iterations < MIN_ITERATIONS:
        return None
    digest = hashlib.sha256(data).digest()
    key = hashlib.pbkdf2_hmac('sha256', data, digest, iterations, 64)
    s1, s2 = key[:32], key[32:]
    return {'hash': digest, 's1': s1, 's2': s2, 'cek': hmac.new(s2, s1, hashlib.sha256).digest()}


# ---------------------------------------------------------------- write-direction checks

def from_json(v):
    if isinstance(v, list):
        return [from_json(x) for x in v]
    if isinstance(v, dict):
        if list(v) == ['$bytes']:
            return bytes.fromhex(v['$bytes'])
        return {k: from_json(x) for k, x in v.items()}
    return v


def tuple_bytes(field):
    rest = ['filename', 'mediaType', 'meta']
    last = max([-1] + [i for i, k in enumerate(rest) if k in field])
    t = [from_json(field['value'])] + [from_json(field[rest[i]]) if rest[i] in field else None for i in range(last + 1)]
    return sdx_anc.encode(t)


def check_write(profile, kase, envelope_hex):
    results = []

    def check(name, tag, ok, detail='', random=False):
        entry = {'check': name, 'tag': tag, 'ok': bool(ok), 'detail': detail}
        if random:
            entry['random'] = True
        results.append(entry)
    try:
        _check_write(profile, kase, envelope_hex, check)
    except (Refusal, sdx_anc.CborError, sdx_ec.EcError, TypeError, AttributeError, KeyError) as error:
        check('envelope-readable', 'required', False, str(error))
    return results


def _check_write(profile, kase, envelope_hex, check):
    req = kase['request']
    data = bytes.fromhex(envelope_hex)
    env = sdx_anc.decode(data)
    check('envelope-deterministic', 'required', sdx_anc.encode(env) == data)
    check('envelope-members', 'required', is_map(env) and sorted(env.keys()) == ['outer', 'proto', 'pu'] and env.get('proto') == profile['formatIdentifier']['value'])
    writer = split_root(profile, bytes.fromhex(req['writer']['rootIkm']))
    acct, rid, aid = req['writer']['acct'], req['writer']['rid'], req['record']['aid']
    outer = env.get('outer')
    prot = protected_object(outer.get('protected'))
    fields = [dict(f, n=unicodedata.normalize('NFC', f['n'])) for f in req['record']['fields']]
    convergent = any(f['sn'] == 'pr' and f.get('cv') is True for f in fields)
    want = ['aid', 'enc', 'iter', 'proto', 'salt'] if convergent else ['aid', 'enc', 'proto']
    check('outer-protected-members', 'required', sorted(prot) == want and prot['enc'] == 'A256GCM' and prot['proto'] == profile['formatIdentifier']['value'] and prot['aid'] == aid)
    oid = outer_id(profile, acct, rid, aid)
    self_d, self_kid = own_child(writer['seed'], writer['R'], oid)
    expected_outer = [self_kid] + [their_child(writer['seed'], sdx_ec.decode_point(P256, bytes.fromhex(r)), oid) for r in req['auditRecipients']]
    headers = [plain(r.get('header')) for r in outer.get('recipients')]
    identity = [h for h in headers if h.get('alg') == ECDH_ALG]
    check('outer-self-recipient', 'required', any(h.get('kid') == self_kid for h in identity))
    check('outer-recipient-kids', 'required', sorted(h.get('kid') for h in identity) == sorted(expected_outer))
    check('outer-recipient-order', 'labChoice', [h.get('kid') for h in identity] == expected_outer)
    check('outer-epk-per-recipient', 'required', all(jwk_point(h.get('epk')) is not None and sorted(h) == ['alg', 'epk', 'kid'] for h in identity))
    check('outer-convergent-slot', 'required', any(h.get('alg') == GCMKW_ALG for h in headers) == convergent)
    if not any(h.get('kid') == self_kid for h in identity):
        return
    audit_bytes = open_jwe(outer, self_d, self_kid, 'outer')
    audit = sdx_anc.decode(audit_bytes)
    check('audit-deterministic', 'required', sdx_anc.encode(audit) == audit_bytes)
    check('audit-members', 'required', sorted(audit.keys()) == ['au', 'hdr', 'pr', 'sigs'])
    hdr = audit.get('hdr')
    _, sign_kid = own_child(writer['seed'], writer['R'], sign_id(profile, acct, rid, aid))
    want_fields = [(f['n'], f['sn'], f['pl'], f.get('cv') is True) for f in fields]
    got_fields = [(d.get('n'), d.get('sn'), d.get('pl'), d.get('cv') is True) for d in (hdr.get('fields') or [])]
    check('hdr-values', 'required', hdr.get('aid') == aid and hdr.get('ep') == req['writer']['ep'] and hdr.get('f') == req['record']['f'] and hdr.get('mv') == req['record']['mv'] and hdr.get('tm') == req['record']['tm'])
    check('hdr-fields', 'required', got_fields == want_fields)
    check('hdr-signer', 'required', hdr.get('pk').hex() == sign_kid and hdr.get('pks') == 'root' and hdr.get('ds') is False and hdr.get('dref') == [])
    sigs = audit.get('sigs')
    try:
        verified = verify_signatures(sigs, hdr, audit.get('au'), audit.get('pr'))
    except Refusal:
        verified = None
    entries = sigs.get('signatures')
    sig_prot = protected_object(entries[0].get('protected')) if len(entries) == 1 else None
    check('signature-shape', 'required', sigs.get('payload') == '' and len(entries) == 1 and sig_prot is not None and sorted(sig_prot) == ['alg', 'kid'] and sig_prot['alg'] == 'ES256' and len(b64u_canonical(entries[0].get('signature')) or b'') == 64)
    check('signature-kid', 'required', sig_prot is not None and sig_prot.get('kid') == sign_kid)
    check('signature-verifies-current', 'required', verified is not None and verified[0]['shape'] == 'current')
    if verified is not None:
        check('signature-low-s', 'labChoice', int.from_bytes(verified[0]['signature'][32:], 'big') <= P256.n // 2)
    if convergent:
        rec = secrets(audit_bytes)
        try:
            opened = open_convergent(outer, rec['s1'])
        except sdx_ec.EcError:
            opened = None
        check('outer-convergent-opens', 'required', opened == audit_bytes)
        check('outer-convergent-header', 'required', prot.get('iter') == MIN_ITERATIONS and isinstance(prot.get('salt'), str) and len(prot['salt']) > 0)
        check('outer-convergent-salt', 'labChoice', prot.get('salt') == b64u(rec['hash']))
    pr_slots = {s.get('n'): s for s in audit.get('pr')}
    for f in [f for f in fields if f['sn'] == 'pr' and 'value' in f]:
        s = pr_slots.get(f['n'])
        jwe = s.get('jwe') if s is not None else None
        if jwe is None:
            check(f"field-{f['n']}-slot", 'required', False)
            continue
        fprot = protected_object(jwe.get('protected'))
        check(f"field-{f['n']}-protected", 'required', sorted(fprot) == (['enc', 'iter', 'salt'] if f.get('cv') is True else ['enc']) and fprot['enc'] == 'A256GCM')
        fid = field_id(profile, acct, rid, aid, f['n'])
        ext = []
        for k, v in (req.get('fieldRecipients') or {}).items():
            if unicodedata.normalize('NFC', k) == f['n']:
                ext = [their_child(writer['seed'], sdx_ec.decode_point(P256, bytes.fromhex(r)), fid) for r in v]
        sd, skid = own_child(writer['seed'], writer['R'], fid)
        expected = ([] if f.get('blind') is True else [skid]) + ext
        fh = [plain(r.get('header')) for r in jwe.get('recipients')]
        check(f"field-{f['n']}-kids", 'required', [h.get('kid') for h in fh if h.get('alg') == ECDH_ALG] == expected)
        check(f"field-{f['n']}-epk-per-recipient", 'required', all(jwk_point(h.get('epk')) is not None for h in fh if h.get('alg') == ECDH_ALG))
        check(f"field-{f['n']}-convergent-slot", 'required', any(h.get('alg') == GCMKW_ALG for h in fh) == (f.get('cv') is True))
        tb = tuple_bytes(f)
        if f.get('cv') is True:
            try:
                ok = open_convergent(jwe, secrets(tb)['cek']) is not None
            except sdx_ec.EcError:
                ok = False
            check(f"field-{f['n']}-convergent-opens", 'required', ok)
        if f.get('blind') is not True:
            compressed = open_jwe(jwe, sd, skid, f"field {f['n']}")
            try:
                declared, out = lzma_alone(compressed)
            except lzma.LZMAError:
                declared, out = None, None
            # The end-of-stream marker is checked by the Node oracle only (src/sdx/lzma.mjs).
            check(f"field-{f['n']}-lzma-alone-size", 'labChoice', declared == len(tb))
            check(f"field-{f['n']}-plaintext", 'required', out == tb)
    det = (kase.get('expect') or {}).get('deterministic')
    if det:
        check('outer-iv', 'required', outer.get('iv') == det['outer']['iv'], random=True)
        check('outer-encrypted-keys', 'required', [r.get('encrypted_key') for r in outer.get('recipients')] == det['outer']['encryptedKeys'], random=True)
        for name, want_f in (det.get('fields') or {}).items():
            jwe = pr_slots.get(name).get('jwe') if pr_slots.get(name) is not None else None
            check(f'field-{name}-encrypted-keys', 'required', jwe is not None and jwe.get('iv') == want_f['iv'] and [r.get('encrypted_key') for r in jwe.get('recipients')] == want_f['encryptedKeys'], random=True)


# ---------------------------------------------------------------- cases

def run_case(profile, kase):
    """Returns (ok, actual, failures). Refusals are compared by class and laboratory detail."""
    req = kase['request']
    if req['op'] == 'read':
        actual = read_envelope(profile, req)
        exp = kase['expect']
        if exp['verdict'] != actual['verdict']:
            return False, actual, [f"verdict {actual['verdict']} {actual.get('refusal')}"]
        if exp['verdict'] == 'refused':
            ok = actual['refusal'] == exp['refusal']
            return ok, actual, [] if ok else [f"refusal {actual['refusal']}"]
        ok = actual == exp
        return ok, actual, [] if ok else ['projection differs']
    if req['op'] == 'write':
        refusal = write_refusal(req)
        if 'refusal' in kase['expect']:
            ok = refusal == kase['expect']['refusal']['detail']
            return ok, refusal, [] if ok else [f'writer rule {refusal}']
        if refusal is not None:
            return False, refusal, [f'writer rule refused {refusal}']
        results = check_write(profile, kase, kase['expect']['envelope'])
        failures = [r['check'] for r in results if not r['ok']]
        return not failures, results, failures
    if req['op'] == 'secrets':
        s = secrets(bytes.fromhex(req['data']), req['iterations'])
        actual = {'refusal': {'class': 'input', 'detail': 'iterations-below-floor'}} if s is None else {k: s[k].hex() for k in ('hash', 's1', 's2', 'cek')}
        ok = actual == kase['expect']
        return ok, actual, [] if ok else ['secrets differ']
    raise ValueError(req['op'])
