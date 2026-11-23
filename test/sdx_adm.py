"""LAB_SELF_TEST_ONLY: a Python standard-library oracle for VA-ADM, an SDX admission service and
per-topic index (ANC §10-§12) as the laboratory states them. Transactions, the ANC §2.1
container and the ENV §3 decoder come from test/sdx_anc.py. It holds no key, shares no code with
the Node.js oracle and imports no generator code."""

import hashlib
import json
import re

import sdx_anc

QUERY_KEYS = ['limit', 'outpoint', 'since', 'topic']
PAGE_CEILING = 1000


def is_map(v):
    return isinstance(v, sdx_anc.CborMap)


def admissible(profile, script):
    """ANC §11.1: the keyless, position-agnostic format gate."""
    ok, _, record, _ = sdx_anc.check_container(script)
    if not ok:
        return None
    try:
        env = sdx_anc.decode(record)
    except sdx_anc.CborError:
        return None
    if not is_map(env) or env.get('proto') != profile['formatIdentifier']['value'] or not isinstance(env.get('pu'), list):
        return None
    outer = env.get('outer')
    if not is_map(outer) or not all(isinstance(outer.get(m), str) for m in ('ciphertext', 'iv', 'tag')):
        return None
    return env


def overlay_manifests(env):
    out = []
    for slot in env.get('pu'):
        im = slot.get('im') if is_map(slot) else None
        if is_map(im) and isinstance(im.get('u'), str) and im.get('u').startswith('overlay://') and isinstance(im.get('sz'), int) and isinstance(im.get('sha'), bytes):
            out.append((im.get('sz'), im.get('sha')))
    return out


def apply_rule(rule, pristine):
    if not rule:
        return pristine
    copy = list(pristine)
    if rule['kind'] == 'drop':
        answer = [i for i in copy if i not in rule['outputs']]
    elif rule['kind'] == 'inject':
        answer = copy + rule['outputs']
    elif rule['kind'] == 'mutate':
        copy.extend(rule['outputs'])
        answer = copy
    else:
        raise ValueError(rule['kind'])
    return [i for i in pristine if i in answer]


def valid_ref(r):
    return isinstance(r, dict) and sorted(r) == ['outputIndex', 'txid'] and isinstance(r['txid'], str) and re.fullmatch(r'[0-9a-f]{64}', r['txid']) is not None \
        and isinstance(r['outputIndex'], int) and not isinstance(r['outputIndex'], bool) and r['outputIndex'] >= 0


class Engine:
    def __init__(self, profile, setup):
        self.profile = profile
        self.topics = {t: {'rows': [], 'done': {}, 'fault': False, 'rule': (setup.get('rules') or {}).get(t)} for t in setup['topics']}
        self.runs = {}

    def submit(self, req):
        r = sdx_anc._Bytes(bytes.fromhex(req['tx']))
        tx = sdx_anc.read_transaction(r)
        if r.remaining():
            raise ValueError('trailing bytes')
        txid = sdx_anc.display(tx['txid'])
        run = bytes.fromhex(req['offChain']) if 'offChain' in req else None
        result = {}
        for name in req['topics']:
            topic = self.topics[name]
            if txid in topic['done']:
                result[name] = topic['done'][txid]
                continue
            decoded = [admissible(self.profile, o['script']) for o in tx['outputs']]
            pristine = [i for i, env in enumerate(decoded) if env is not None]
            admitted = apply_rule(topic['rule'], pristine)
            declined, side = False, None
            if run is not None:
                manifests = [m for i in admitted for m in overlay_manifests(decoded[i])]
                total = sum(size for size, _ in manifests)
                if total > len(run):
                    declined = True
                elif len(admitted) == 1 and total == len(run):
                    at = 0
                    for size, digest in manifests:
                        piece = run[at:at + size]
                        at += size
                        if len(piece) != size or hashlib.sha256(piece).digest() != digest:
                            declined = True
                    if not declined:
                        side = {'accounting': 'verified', 'publicEntriesVerified': len(manifests)}
                else:
                    side = {'accounting': 'unverified', 'publicEntriesVerified': 0}
            if declined:
                entry = {'admitted': [], 'retained': [], 'declined': True}
            else:
                keys = {(x['txid'], x['outputIndex']) for x in topic['rows']}
                retained = [{'txid': sdx_anc.display(i['prev']), 'outputIndex': i['vout']} for i in tx['inputs'] if (sdx_anc.display(i['prev']), i['vout']) in keys]
                for i in admitted:
                    topic['rows'].append({'txid': txid, 'outputIndex': i})
                if run is not None and admitted:
                    self.runs[txid] = run
                entry = {'admitted': admitted, 'retained': retained, 'declined': False}
                if side is not None:
                    entry['sideChannel'] = side
            topic['done'][txid] = entry
            result[name] = entry
        return {'topics': result}

    def row(self, r):
        out = dict(r)
        if r['txid'] in self.runs:
            out['offChain'] = self.runs[r['txid']].hex()
        return out

    def lookup(self, req):
        def refusal(detail):
            return {'refusal': {'class': 'query', 'detail': detail}}
        service = req.get('service')
        bound = 'tm_' + service[3:] if isinstance(service, str) and service.startswith('ls_') else None
        if bound not in self.topics:
            return refusal('service')
        q = req['query']
        if not isinstance(q, dict):
            return refusal('not-object')
        if any(k not in QUERY_KEYS for k in q):
            return refusal('unknown-key:' + ','.join(QUERY_KEYS))
        if not isinstance(q.get('topic'), str) or not q['topic']:
            return refusal('topic')
        if q['topic'] != bound:
            return refusal('topic-not-bound')
        topic = self.topics[bound]
        if 'outpoint' in q:
            if 'since' in q or 'limit' in q:
                return refusal('outpoint-with-cursor')
            if not valid_ref(q['outpoint']):
                return refusal('outpoint')
            if topic['fault']:
                return refusal('index-fault')
            return {'rows': [self.row(r) for r in topic['rows'] if r == q['outpoint']]}
        if 'since' not in q:
            return refusal('since-absent')
        if q['since'] is not None and not valid_ref(q['since']):
            return refusal('since')
        if 'limit' in q and not (isinstance(q['limit'], int) and not isinstance(q['limit'], bool) and q['limit'] > 0):
            return refusal('limit')
        if topic['fault']:
            return refusal('index-fault')
        start = 0
        if q['since'] is not None:
            matches = [i for i, r in enumerate(topic['rows']) if r == q['since']]
            if not matches:
                return refusal('since-unknown')
            start = matches[0] + 1
        return {'rows': [self.row(r) for r in topic['rows'][start:start + q.get('limit', PAGE_CEILING)]]}

    def step(self, req):
        if req['op'] == 'submit':
            return self.submit(req)
        if req['op'] == 'lookup':
            return self.lookup(req)
        if req['op'] == 'fault':
            self.topics[req['topic']]['fault'] = True
            return {'ok': True}
        raise ValueError(req['op'])


def run_case(profile, kase):
    engine = Engine(profile, kase['setup'])
    for i, step in enumerate(kase['steps']):
        actual = engine.step(step['request'])
        if json.dumps(actual, sort_keys=True) != json.dumps(step['expect'], sort_keys=True):
            return False, i, actual
    return True, None, None
