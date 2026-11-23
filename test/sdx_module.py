"""LAB_SELF_TEST_ONLY: standard-library reference semantics of the `p sdx` module.

The Python oracle of the module suites (test/test_sdx_p256.py and
test/test_sdx_k1.py) replays requests against this model of a wallet that
holds SDX accounts on both curves: strict CBOR inputs, root selection by
logical protocol ID and epoch, the namespace and key-path rules, grants, and
every operation, including `decrypt`'s JWE decryption with the AES of
test/sdx_ec.py. It imports only the standard library and test/sdx_ec.py, so it
stays independent of every generator and of the node:crypto checkers.
"""

import base64
import json
import os
import re

import sdx_ec as ec

SCHEME = 'p sdx '
OPERATIONS = {
    'open': 'encrypt', 'key': 'encrypt', 'peer': 'encrypt', 'sign': 'encrypt', 'decrypt': 'decrypt',
    'k1key': 'encrypt', 'k1peer': 'encrypt', 'k1sign': 'encrypt',
}
CURVE_OF = {
    'key': ec.P256, 'peer': ec.P256, 'sign': ec.P256, 'decrypt': ec.P256,
    'k1key': ec.SECP256K1, 'k1peer': ec.SECP256K1, 'k1sign': ec.SECP256K1,
}
MEMBERS = {
    'open': ({'acct'}, {'ep'}),
    'key': (set(), {'path', 'peer', 'ep'}),
    'peer': ({'path', 'peer'}, {'ep'}),
    'sign': ({'path', 'msg'}, {'peer', 'ep'}),
    'decrypt': ({'path', 'peer', 'jwe'}, {'ep'}),
    'k1key': (set(), {'path', 'peer', 'ep'}),
    'k1peer': ({'path', 'peer'}, {'ep'}),
    'k1sign': ({'path', 'hash'}, {'peer', 'ep'}),
}
MEMBER_TYPES = {'path': 'tstr', 'acct': 'tstr', 'ep': 'uint', 'jwe': 'map'}
MAX_KEY_PATH_BYTES = 1033  # KEYS §1.3
MARKERS = ('tstr', 'bstr', 'uint', 'nint')
ACCOUNT_ROLES = ('write', 'read', 'root')
NAMED_METHODS = {
    'createAction': lambda a: [o.get('basket') for o in a.get('outputs', [])] + a.get('labels', []),
    'internalizeAction': lambda a: [(o.get('insertionRemittance') or {}).get('basket') for o in a.get('outputs', [])] + a.get('labels', []),
    'listOutputs': lambda a: [a.get('basket')],
    'listActions': lambda a: a.get('labels', []),
    'relinquishOutput': lambda a: [a.get('basket')],
}
LOGICAL = re.compile(r'(write|read|root|actor|session) ([0-9a-f]{32})')
IDENTIFIER = re.compile(r'([0-2])-([a-z0-9 ]+)-(.+)', re.S)
SESSION = re.compile(r'/session/([0-9a-f]{32})(?:/|$)')
HEX = re.compile(r'(?:[0-9a-f]{2})*')


def member_type(name):
    return MEMBER_TYPES.get(name, 'bstr')


def unhex(text):
    if not isinstance(text, str) or not HEX.fullmatch(text):
        raise AssertionError(f'lowercase even-length hex expected: {text!r}')
    return bytes.fromhex(text)


def account_tag(acct):
    return ec.sha256(acct.encode('utf-8'))[:16].hex()


def parse_logical(text):
    match = LOGICAL.fullmatch(text)
    return (match.group(1), match.group(2)) if match else None


# -- deterministic CBOR: text keys to text, byte strings or integers -----------

def cbor_head(major, value):
    if value < 24:
        return bytes([major << 5 | value])
    for info, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if value < 1 << (8 * width):
            return bytes([major << 5 | info]) + value.to_bytes(width, 'big')
    raise ValueError('length')


def cbor_item(value):
    if isinstance(value, dict):
        return cbor_input(value)
    if isinstance(value, str):
        data = value.encode('utf-8')
        return cbor_head(3, len(data)) + data
    if isinstance(value, int) and not isinstance(value, bool):
        return cbor_head(0, value) if value >= 0 else cbor_head(1, -1 - value)
    return cbor_head(2, len(value)) + bytes(value)


def cbor_input(fields):
    """Deterministic CBOR (RFC 8949 §4.2.1) of a map of text keys."""
    entries = sorted((cbor_item(name), cbor_item(value)) for name, value in fields.items())
    return cbor_head(5, len(entries)) + b''.join(k + v for k, v in entries)


def decode_input(data):
    """Strict decoder: definite shortest lengths and integers, sorted unique keys, UTF-8 text, nothing trailing.

    A nested map (text keys, as in `jwe`) decodes to a dict."""
    position = 0

    def take(count):
        nonlocal position
        if position + count > len(data):
            raise ec.EcError('input-encoding')
        chunk = data[position:position + count]
        position += count
        return chunk

    def read_head(majors):
        first = take(1)[0]
        major, info = first >> 5, first & 31
        if major not in majors:
            raise ec.EcError('input-encoding')
        if info < 24:
            return major, info
        width = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
        if width is None:
            raise ec.EcError('input-encoding')
        value = int.from_bytes(take(width), 'big')
        if value < (24 if width == 1 else 1 << (4 * width)):
            raise ec.EcError('input-encoding')
        return major, value

    def text(raw):
        try:
            return raw.decode('utf-8')
        except UnicodeDecodeError:
            raise ec.EcError('input-encoding') from None

    def read_map(count, depth):
        fields, previous = {}, None
        for _ in range(count):
            start = position
            name = text(take(read_head((3,))[1]))
            encoded_key = data[start:position]
            if previous is not None and previous >= encoded_key:
                raise ec.EcError('input-encoding')
            previous = encoded_key
            major, value = read_head((0, 1, 2, 3, 5) if depth < 3 else (0, 1, 2, 3))
            if major == 0:
                fields[name] = value
            elif major == 1:
                fields[name] = -1 - value
            elif major == 5:
                fields[name] = read_map(value, depth + 1)
            else:
                raw = take(value)
                fields[name] = text(raw) if major == 3 else raw
        return fields

    _, count = read_head((5,))
    fields = read_map(count, 0)
    if position != len(data):
        raise ec.EcError('input-encoding')
    return fields


def input_from_json(view):
    """The vectors' JSON view: path and acct text, ep a number, jwe the map, other members hex; marker objects for other types."""
    fields = {}
    for name, value in view.items():
        natural = member_type(name)
        if natural == 'map' and isinstance(value, dict) and not (len(value) == 1 and next(iter(value)) in MARKERS):
            fields[name] = json.loads(json.dumps(value))
        elif isinstance(value, str):
            fields[name] = value if natural == 'tstr' else unhex(value)
        elif isinstance(value, int) and not isinstance(value, bool) and natural == 'uint' and value >= 0:
            fields[name] = value
        elif 'tstr' in value:
            fields[name] = value['tstr']
        elif 'bstr' in value:
            fields[name] = unhex(value['bstr'])
        elif 'uint' in value:
            fields[name] = value['uint']
        else:
            fields[name] = value['nint']
    return fields


def type_ok(name, value):
    kind = member_type(name)
    if kind == 'tstr':
        return isinstance(value, str)
    if kind == 'uint':
        return isinstance(value, int) and not isinstance(value, bool) and value >= 0
    if kind == 'map':
        return isinstance(value, dict)
    return isinstance(value, (bytes, bytearray))


# -- roots ----------------------------------------------------------------------

class Root:
    """One 64-byte root, split per KEYS §1.4.2, with both root public keys."""

    def __init__(self, ikm, labels):
        k1, r1 = ec.split_ikm(ikm, labels['secp256k1'].encode(), labels['p256'].encode())
        self.ikm, self.secp256k1_seed, self.p256_seed = ikm, k1, r1
        self.r, self.k = int.from_bytes(r1, 'big'), int.from_bytes(k1, 'big')
        self.R = ec.compress(ec.P256, ec.base_mul(ec.P256, self.r))
        self.K = ec.compress(ec.SECP256K1, ec.base_mul(ec.SECP256K1, self.k))

    def scalar(self, curve):
        return self.r if curve is ec.P256 else self.k

    def public(self, curve):
        return self.R if curve is ec.P256 else self.K


def wallet_derived_ikm(wallet_root, derivation, key_id):
    """Draft §Canonical derivation step 1: d = BRC-42 child under [2, "admin sdx root"], then HKDF."""
    w = int.from_bytes(wallet_root, 'big')
    invoice = f"{derivation['protocolID'][0]}-{derivation['protocolID'][1]}-{key_id}"
    d = ec.brc42_child_private(w, ec.base_mul(ec.SECP256K1, w), invoice)
    return ec.hkdf_sha256(ec.int32(d), derivation['salt'].encode(), derivation['info'].encode(), derivation['length'])


def derive(curve, own, counterparty, path, inject=None):
    """Shared point, HMAC and offset h; `inject` replaces the HMAC output (KEYS §1.12 item 7)."""
    shared = ec.compress(curve, ec.mul(curve, own, ec.decode_point(curve, counterparty)))
    digest = ec.hmac_sha256(shared, path.encode('utf-8'))
    return shared, digest, ec.check_offset(curve, digest if inject is None else inject)


def own_child(curve, own, counterparty, path, inject=None):
    _, _, h = derive(curve, own, counterparty, path, inject)
    child = (own + h) % curve.n
    if child == 0:
        raise ec.EcError('child-zero', curve.name)
    return child


def their_child(curve, own, counterparty, path, inject=None):
    _, _, h = derive(curve, own, counterparty, path, inject)
    child = ec.add(curve, ec.decode_point(curve, counterparty), ec.base_mul(curve, h))
    if child is None:
        raise ec.EcError('point-infinity')
    return ec.compress(curve, child)


B64U = re.compile(r'[A-Za-z0-9_-]*')
JWE_MEMBERS = {'protected': True, 'header': True, 'encrypted_key': True, 'iv': True, 'ciphertext': True, 'tag': True, 'aad': False}
HEADER_MEMBERS = ('alg', 'epk', 'kid', 'apu', 'apv')


def b64u_decode(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def check_jwe_shape(jwe):
    """The flattened entry SDX writes, before any key is used; returns (joint header, ephemeral point bytes)."""
    def shape(what):
        return ec.EcError('jwe-shape', what)
    if not isinstance(jwe, dict):
        raise shape('jwe is not a map')
    if set(jwe) - set(JWE_MEMBERS) or any(required and name not in jwe for name, required in JWE_MEMBERS.items()):
        raise shape('members')
    for name, value in jwe.items():
        if name != 'header' and (not isinstance(value, str) or not B64U.fullmatch(value)):
            raise shape(f'{name} is not base64url text')
    header = jwe['header']
    if not isinstance(header, dict) or set(header) - set(HEADER_MEMBERS):
        raise shape('header')
    try:
        protected = json.loads(b64u_decode(jwe['protected']).decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        raise shape('protected is not base64url JSON') from None
    if not isinstance(protected, dict) or set(header) & set(protected):
        raise shape('protected header')
    joint = {**protected, **header}
    if joint.get('alg') != 'ECDH-ES+A256KW':
        raise shape('alg')
    if 'kid' in header and not isinstance(header['kid'], str):
        raise shape('kid')
    for name in ('apu', 'apv'):
        if name in joint and (not isinstance(joint[name], str) or not B64U.fullmatch(joint[name])):
            raise shape(name)
    epk = joint.get('epk')
    if not isinstance(epk, dict) or set(epk) != {'kty', 'crv', 'x', 'y'} or epk['kty'] != 'EC' or epk['crv'] != 'P-256':
        raise shape('epk')
    if not all(isinstance(epk[k], str) and B64U.fullmatch(epk[k]) for k in ('x', 'y')):
        raise shape('epk coordinates')
    x, y = b64u_decode(epk['x']), b64u_decode(epk['y'])
    if len(x) != 32 or len(y) != 32:
        raise shape('epk coordinate length')
    ephemeral = bytes([2 | (y[31] & 1)]) + x
    point = ec.decode_point(ec.P256, ephemeral)
    if point[1] != int.from_bytes(y, 'big'):
        raise ec.EcError('point-not-on-curve', 'epk y')
    return joint, ephemeral


def jwe_decrypt(child_private, jwe):
    """The JWE decryption step with one candidate key: ECDH, Concat KDF, AES key unwrap, A256GCM."""
    joint, ephemeral = check_jwe_shape(jwe)
    if joint.get('enc') != 'A256GCM' or 'zip' in joint or 'crit' in joint:
        raise ec.EcError('decrypt-failed', 'content algorithm')
    z = ec.ecdh_x(ec.P256, child_private, ec.decode_point(ec.P256, ephemeral))
    kek = ec.concat_kdf_sha256(z, 256, b'ECDH-ES+A256KW', b64u_decode(joint.get('apu', '')), b64u_decode(joint.get('apv', '')))
    cek = ec.aes_key_unwrap(kek, b64u_decode(jwe['encrypted_key']))
    aad = (jwe['protected'] + ('.' + jwe['aad'] if 'aad' in jwe else '')).encode('ascii')
    plaintext = ec.aes_gcm_decrypt(cek, b64u_decode(jwe['iv']), aad, b64u_decode(jwe['ciphertext']), b64u_decode(jwe['tag']))
    return {'z': z, 'kek': kek, 'cek': cek, 'plaintext': plaintext}


def invoice(protocol_id, key_id):
    return f'{protocol_id[0]}-{protocol_id[1].strip().lower()}-{key_id}'


def check_key_path(key_path, role, namespace_role, profile):
    """KEYS §1.3 and §1.6.1 with the profile's keywords and purposes; role actor derives only actor/<index>."""
    length = len(key_path.encode('utf-8'))
    if length == 0 or length > MAX_KEY_PATH_BYTES:
        raise ec.EcError('key-path-length')
    kw, purposes = profile['keywords'], profile['purposes']
    seg = key_path.split('/')
    if role == 'actor':
        if namespace_role != 'delegation' or len(seg) != 2 or seg[0] != kw['actor'] or not re.fullmatch(r'0|[1-9][0-9]*', seg[1]):
            raise ec.EcError('key-path-grammar')
        return
    if any(part == '' for part in seg) or seg[0] != kw['account']:
        raise ec.EcError('key-path-grammar')
    if len(seg) == 2:
        return
    if seg[2] != kw['runtime'] or len(seg) < 4:
        raise ec.EcError('key-path-grammar')
    if len(seg) == 4 or (seg[4] in (kw['action'], kw['session']) and len(seg) == 6):
        return
    if seg[4] == kw['action'] and len(seg) == 8:
        if seg[6] not in purposes:
            raise ec.EcError('purpose-unregistered')
        return
    raise ec.EcError('key-path-grammar')


class Wallet:
    """A wallet with the module installed, built from one entry of a vectors file's `wallets` table."""

    def __init__(self, entry, profile, derivation):
        self.profile, self.labels, self.derivation = profile, profile['labels'], derivation
        self.namespaces = {row['namespace']: row for row in profile['namespaces']}
        self.wallet_root = unhex(entry['walletRoot']) if 'walletRoot' in entry else None
        self.accounts = {}
        for account in entry['accounts']:
            epochs = {}
            for epoch in account['epochs']:
                if epoch.get('derived'):
                    ikm = wallet_derived_ikm(unhex(epoch['walletRoot']), derivation, f"{account['acct']} {epoch['ep']}")
                else:
                    ikm = unhex(epoch['ikm'])
                epochs[epoch['ep']] = Root(ikm, self.labels)
            self.accounts[account['tag']] = {'acct': account['acct'], 'current': account['current'], 'epochs': epochs}
        self.actor = Root(unhex(entry['actor']['ikm']), self.labels) if 'actor' in entry else None
        self.sessions = {sid: Root(unhex(s['ikm']), self.labels) for sid, s in entry.get('sessions', {}).items()}
        self.grants = entry.get('grants', [])

    def select_request(self, operation, role, fields):
        """Roots and selection, the part that reads only the request (decision D-ERRORS). It runs
        before the grant check. Returns the session ID a role-session request names, or None."""
        if operation == 'open' or role in ACCOUNT_ROLES:
            return None
        if 'ep' in fields:
            raise ec.EcError('epoch-not-allowed')
        if role == 'actor':
            return None
        match = SESSION.search(fields['path']) if 'path' in fields else None
        if match is None:
            raise ec.EcError('session-not-selected')
        return match.group(1)

    def open_creates(self, tag, fields):
        """Whether `open` creates an account or an epoch. Read before authorization only to
        require the prompt: creating never runs under a standing grant."""
        held = self.accounts.get(tag)
        account = held if held and held['acct'] == fields['acct'] else None
        ep = fields.get('ep', account['current'] if account else 0)
        return account is None or ep not in account['epochs']

    def select(self, operation, role, tag, fields, session_id=None):
        """Roots and selection, the part that reads what the wallet holds. It runs only once the
        request is authorized. Returns the root, or for `open` the epoch it creates."""
        if operation == 'open':
            account = self.accounts.get(tag)
            if account and account['acct'] != fields['acct']:
                raise ec.EcError('account-tag-collision')
            ep = fields.get('ep', account['current'] if account else 0)
            if account and ep in account['epochs']:
                return account['epochs'][ep]
            if self.wallet_root is None:
                raise ec.EcError('cannot-create')
            return Root(wallet_derived_ikm(self.wallet_root, self.derivation, f"{fields['acct']} {ep}"), self.labels)
        if role in ACCOUNT_ROLES:
            account = self.accounts.get(tag)
            if account is None:
                raise ec.EcError('unknown-account')
            root = account['epochs'].get(fields.get('ep', account['current']))
            if root is None:
                raise ec.EcError('unknown-epoch')
            return root
        if role == 'actor':
            if self.actor is None:
                raise ec.EcError('no-actor-root')
            return self.actor
        if session_id not in self.sessions:
            self.sessions[session_id] = Root(os.urandom(64), self.labels)
        return self.sessions[session_id]


def read_input(operation, carried):
    fields = decode_input(carried)
    required, optional = MEMBERS[operation]
    if set(fields) - required - optional:
        raise ec.EcError('unknown-member')
    if required - set(fields) or (operation in ('key', 'k1key') and 'peer' in fields and 'path' not in fields):
        raise ec.EcError('missing-member')
    for name, value in fields.items():
        if not type_ok(name, value):
            raise ec.EcError('member-type')
    curve = CURVE_OF.get(operation)
    if 'peer' in fields:
        ec.decode_point(curve, fields['peer'])
    if 'hash' in fields and len(fields['hash']) != 32:
        raise ec.EcError('hash-length')
    if 'jwe' in fields:
        check_jwe_shape(fields['jwe'])
    return fields


def dispatch(wallet, method, args, approve=False, inject=None):
    """The module rules, in the laboratory's check order (decision D-ERRORS)."""
    names = NAMED_METHODS.get(method, lambda a: [])(args)
    if any(isinstance(n, str) and (n == 'p sdx' or n.startswith(SCHEME)) for n in names):
        raise ec.EcError('reserved-namespace')
    protocol = args.get('protocolID') or [None, None]
    name = protocol[1]
    if not isinstance(name, str) or not name.startswith(SCHEME):
        raise ec.EcError('not-sdx-request')
    if method not in ('encrypt', 'decrypt'):
        raise ec.EcError('method-not-permitted')
    operation, _, logical = name[len(SCHEME):].partition(' ')
    if operation not in OPERATIONS:
        raise ec.EcError('unknown-operation')
    if OPERATIONS[operation] != method:
        raise ec.EcError('wrong-carrier')
    if protocol[0] != 2:
        raise ec.EcError('security-level')
    if args.get('privileged') is True:
        raise ec.EcError('privileged-not-supported')
    parsed = parse_logical(logical)
    if parsed is None:
        raise ec.EcError('logical-protocol-id')
    role, tag = parsed
    if args.get('counterparty', 'self') != 'self':
        raise ec.EcError('counterparty-not-self')
    fields = read_input(operation, unhex(args['plaintext' if method == 'encrypt' else 'ciphertext']))
    if operation == 'open':
        if role != 'root':
            raise ec.EcError('open-role')
        if account_tag(fields['acct']) != tag:
            raise ec.EcError('account-tag-mismatch')
    curve = CURVE_OF.get(operation)
    if 'path' in fields:
        match = IDENTIFIER.fullmatch(fields['path'])
        if match is None or match.group(1) != '2':
            raise ec.EcError('path-identifier')
        registered = wallet.namespaces.get(match.group(2))
        if registered is None:
            raise ec.EcError('namespace-unregistered')
        if curve.name not in registered['curves']:
            raise ec.EcError('namespace-curve')
        if registered['role'] == 'rotation':
            raise ec.EcError('namespace-rotation')
        if operation == 'decrypt' and registered['role'] != 'encryption':
            raise ec.EcError('namespace-decrypt')
        if operation in ('sign', 'k1sign') and registered['role'] == 'encryption':
            raise ec.EcError('namespace-encryption')
        check_key_path(match.group(3), role, registered['role'], wallet.profile)
    session_id = wallet.select_request(operation, role, fields)
    # The grant and its prefixes, or the user's approval. Creating never runs under a grant.
    if not approve:
        grant = next((g for g in wallet.grants if g['protocolID'] == [2, name]), None)
        if grant is None:
            raise ec.EcError('no-grant')
        if operation == 'open' and wallet.open_creates(tag, fields):
            raise ec.EcError('prompt-required')
        if 'path' in fields and not any(fields['path'].encode('utf-8').startswith(p.encode('utf-8')) for p in grant['prefixes']):
            raise ec.EcError('path-not-granted')
    root = wallet.select(operation, role, tag, fields, session_id)
    if operation == 'open':
        return root.R + root.K
    own, self_public = root.scalar(curve), root.public(curve)
    path, peer = fields.get('path'), fields.get('peer') or self_public
    if operation in ('key', 'k1key'):
        return self_public if path is None else ec.compress(curve, ec.base_mul(curve, own_child(curve, own, peer, path, inject)))
    if operation in ('peer', 'k1peer'):
        return their_child(curve, own, fields['peer'], path, inject)
    if operation == 'sign':
        r, s, _ = ec.ecdsa_sign_rfc6979(ec.P256, own_child(curve, own, peer, path, inject), ec.sha256(fields['msg']), low_s=True)
        return ec.int32(r) + ec.int32(s)
    if operation == 'k1sign':
        r, s, _ = ec.ecdsa_sign_rfc6979(ec.SECP256K1, own_child(curve, own, peer, path, inject), fields['hash'], low_s=True)
        return ec.der_encode(r, s)
    if operation == 'decrypt':
        return jwe_decrypt(own_child(curve, own, fields['peer'], path, inject), fields['jwe'])['plaintext']
    raise AssertionError(f'operation {operation}')


def request_fields(test, request):
    """Decodes the carried CBOR strictly and checks it against the JSON view."""
    carried = unhex(request['args']['ciphertext' if request['method'] == 'decrypt' else 'plaintext'])
    fields = input_from_json(request['input'])
    test.assertEqual(cbor_input(fields), carried, 'deterministic CBOR of the input')
    test.assertEqual(decode_input(carried), fields)
    return fields


def selected_root(doc, wallets, wallet_name, request):
    """The root a well-formed module request selects, without permission checks."""
    fields = input_from_json(request['input'])
    role, tag = parse_logical(request['args']['protocolID'][1].split(' ', 3)[3])
    wallet = wallets[wallet_name]
    return wallet.select('key', role, tag, fields, wallet.select_request('key', role, fields))


def check_header(test, doc, suite, requirements):
    """Document checks shared by the module suites; returns the test roots and the wallets."""
    test.assertEqual((doc['schema'], doc['suite'], doc['claim'], doc['status']), ('tpnil-sdx-vectors@0.1.0', suite, 'LAB_SELF_TEST_ONLY', 'PROPOSED'))
    test.assertEqual(doc['requirements'], requirements)
    ids = [entry['id'] for entry in doc['cases']]
    test.assertEqual(len(ids), len(set(ids)))
    test.assertEqual({entry['requirement'] for entry in doc['cases']}, set(requirements))
    test.assertIn({'path': 'test/sdx_ec.py', 'basis': 'python stdlib'}, [{'path': o['path'], 'basis': o['basis']} for o in doc['oracles']])
    for acct, tag in doc['profile']['accountTags'].items():
        test.assertEqual(account_tag(acct), tag)
    tag = account_tag(doc['profile']['identifiers']['accountId'])
    for role, logical in doc['profile']['logicalProtocolIDs'].items():
        test.assertEqual(logical, f'{role} {tag}')
    table = doc['wallets']
    test.assertEqual(len({row['namespace'] for row in table['profile']['namespaces']}), 6)
    keywords, purposes = table['profile']['keywords'], table['profile']['purposes']
    test.assertTrue(all(isinstance(keywords.get(k), str) and keywords[k] and '/' not in keywords[k] for k in ('account', 'runtime', 'action', 'session', 'actor')))
    test.assertNotEqual(keywords['action'], keywords['session'])
    test.assertTrue(purposes and len(set(purposes)) == len(purposes) and all(p and '/' not in p for p in purposes))
    test.assertEqual((doc['profile']['keywords'], doc['profile']['purposes'], doc['profile']['labels']), (keywords, purposes, table['profile']['labels']))
    test.assertTrue(isinstance(doc['profile']['formatIdentifier'], str) and doc['profile']['formatIdentifier'] and doc['profile']['formatIdentifier'] != 'sdx:record:v1')
    derivation = table['walletRootDerivation']
    test.assertEqual((derivation['protocolID'], derivation['counterparty'], derivation['salt'], derivation['info'], derivation['length']), ([2, 'admin sdx root'], 'self', 'p sdx v1', 'sdx root', 64))
    labels = doc['testKeys']['labels']
    roots = {}
    for name, listed in doc['testKeys']['roots'].items():
        if listed.get('usable') is False:
            with test.assertRaises(ec.EcError) as raised:
                ec.split_ikm(unhex(listed['ikm']), labels['secp256k1'].encode(), labels['p256'].encode())
            test.assertEqual((raised.exception.code, str(raised.exception)), ('ikm-unusable', 'ikm-unusable: P-256'))
            continue
        root = Root(unhex(listed['ikm']), labels)
        test.assertEqual((root.secp256k1_seed.hex(), root.p256_seed.hex()), (listed['secp256k1Seed'], listed['p256Seed']))
        test.assertEqual((root.K.hex(), root.R.hex()), (listed['secp256k1PublicKey'], listed['p256PublicKey']))
        roots[name] = root
    wallets = {}
    for name, entry in table['entries'].items():
        wallet = Wallet(entry, table['profile'], derivation)
        for account in entry['accounts']:
            test.assertEqual(account_tag(account['acct']), account['tag'])
            test.assertEqual(account['current'], max(epoch['ep'] for epoch in account['epochs']))
            for epoch in account['epochs']:
                test.assertTrue(('ikm' in epoch) != (epoch.get('derived') is True))
                if epoch.get('derived'):
                    test.assertEqual(epoch['walletRoot'], entry['walletRoot'])
                root = wallet.accounts[account['tag']]['epochs'][epoch['ep']]
                test.assertEqual((root.R.hex(), root.K.hex()), (epoch['R'], epoch['K']))
        if 'actor' in entry:
            test.assertEqual((wallet.actor.R.hex(), wallet.actor.K.hex()), (entry['actor']['R'], entry['actor']['K']))
        for sid, session in entry.get('sessions', {}).items():
            test.assertEqual((wallet.sessions[sid].R.hex(), wallet.sessions[sid].K.hex()), (session['R'], session['K']))
        for grant in entry['grants']:
            protocol_name = grant['protocolID'][1]
            test.assertEqual(grant['protocolID'][0], 2)
            test.assertTrue(protocol_name.startswith(SCHEME) and protocol_name.split(' ')[2] in OPERATIONS)
            test.assertIsNotNone(parse_logical(protocol_name.split(' ', 3)[3]))
            test.assertTrue(all(p.endswith('/') for p in grant['prefixes']))
            test.assertTrue(grant['prefixes'] or protocol_name.split(' ')[2] == 'open')
        wallets[name] = wallet
    return roots, wallets
