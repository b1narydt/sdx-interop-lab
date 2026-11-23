"""LAB_SELF_TEST_ONLY: an independent SDX v0.1 anchoring checker for VA-ANC, written for the
Python standard library only. It shares no code with the Node.js checker in src/sdx/ and reads
nothing but the suite file and the laboratory deployment profile.

It covers what the VA-ANC cases exercise: the ENV §3 semantic decoder and deterministic
encoder, transactions, scripts and the ANC §2.1/§2.2 container, BEEF V1 and Atomic BEEF
(BRC-62, BRC-95), BUMP roots (BRC-74), a header source over a pinned header list, the KEYS
§1.4.2 split, BRC-42 self-derivation on secp256k1 (KEYS §1.8.2), BIP 143 SIGHASH_FORKID ECDSA
verification accepting either S (KEYS §1.8.3), the ANC §6.1 reference check and the ANC §7.1
walk with the §6.2 integrity check and the §4.2 tip rule.
"""

import hashlib
import hmac
import re
import struct

# ---------------------------------------------------------------- ENV §3 deterministic CBOR


class CborError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class Undefined:
    """CBOR undefined (0xf7): the ENV §3 absent value."""

    def __repr__(self):
        return 'undefined'


UNDEFINED = Undefined()
MAX_SAFE = 2 ** 53 - 1
DEPTH = 64


class CborMap:
    """A decoded map, in the order its pairs were read."""

    def __init__(self, pairs):
        self.pairs = pairs

    def get(self, key, default=None):
        for k, v in self.pairs:
            if type(k) is type(key) and k == key:
                return v
        return default

    def keys(self):
        return [k for k, _ in self.pairs]


def _head(major, value):
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 0x100:
        return bytes([(major << 5) | 24, value])
    if value < 0x10000:
        return bytes([(major << 5) | 25]) + struct.pack('>H', value)
    if value < 0x100000000:
        return bytes([(major << 5) | 26]) + struct.pack('>I', value)
    return bytes([(major << 5) | 27]) + struct.pack('>Q', value)


def _encode_number(value):
    if isinstance(value, bool):
        raise CborError('unsupported-type')
    if isinstance(value, int):
        if abs(value) > MAX_SAFE:
            raise CborError('integer-out-of-domain')
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if value != value:
        return bytes.fromhex('fb7ff8000000000000')
    if value.is_integer() and abs(value) <= MAX_SAFE:
        return _encode_number(int(value))
    return b'\xfb' + struct.pack('>d', value)


def _encode_map(pairs, depth):
    encoded = []
    for key, value in pairs:
        if value is UNDEFINED:
            continue  # an absent map member is elided (ENV §3 rule 9)
        encoded.append((encode(key, depth + 1, 'key'), encode(value, depth + 1, 'member')))
    encoded.sort(key=lambda pair: pair[0])
    for i in range(1, len(encoded)):
        if encoded[i - 1][0] == encoded[i][0]:
            raise CborError('duplicate-key')
    return _head(5, len(encoded)) + b''.join(k + v for k, v in encoded)


def encode(value, depth=0, position='top'):
    if depth > DEPTH:
        raise CborError('depth')
    if value is UNDEFINED:
        if position == 'top':
            return b'\xf7'
        if position == 'element':
            return b'\xf6'
        raise CborError('unsupported-type')
    if value is None:
        return b'\xf6'
    if value is True:
        return b'\xf5'
    if value is False:
        return b'\xf4'
    if isinstance(value, (int, float)):
        return _encode_number(value)
    if isinstance(value, str):
        data = value.encode('utf-8')
        return _head(3, len(data)) + data
    if isinstance(value, (bytes, bytearray)):
        return _head(2, len(value)) + bytes(value)
    if isinstance(value, list):
        return _head(4, len(value)) + b''.join(encode(item, depth + 1, 'element') for item in value)
    if isinstance(value, CborMap):
        return _encode_map(value.pairs, depth)
    if isinstance(value, dict):
        return _encode_map(list(value.items()), depth)
    raise CborError('unsupported-type')


def encode_set(items):
    """ENV §3 rule 6: a set is an array sorted by its members' canonical encodings."""
    encoded = sorted(encode(item, 1, 'element') for item in items)
    return _head(4, len(encoded)) + b''.join(encoded)


def _half(bits):
    exponent = (bits >> 10) & 0x1f
    fraction = bits & 0x3ff
    sign = -1.0 if bits & 0x8000 else 1.0
    if exponent == 0:
        return sign * fraction * 2.0 ** -24
    if exponent == 31:
        return float('nan') if fraction else sign * float('inf')
    return sign * (1 + fraction / 1024) * 2.0 ** (exponent - 15)


class _Reader:
    def __init__(self, data):
        self.data = bytes(data)
        self.pos = 0

    def remaining(self):
        return len(self.data) - self.pos

    def take(self, n):
        if n > self.remaining():
            raise CborError('truncated')
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def argument(self, info):
        if info < 24:
            return info
        if info in (24, 25, 26, 27):
            return int.from_bytes(self.take(1 << (info - 24)), 'big')
        if info == 31:
            raise CborError('indefinite-length')
        raise CborError('not-well-formed')


def _item(reader, depth):
    if depth > DEPTH:
        raise CborError('depth')
    initial = reader.take(1)[0]
    major, info = initial >> 5, initial & 0x1f
    if major in (0, 1):
        if info == 31:
            raise CborError('not-well-formed')
        n = reader.argument(info)
        if major == 0:
            if n > MAX_SAFE:
                raise CborError('integer-out-of-domain')
            return n
        if n > MAX_SAFE - 1:
            raise CborError('integer-out-of-domain')
        return -1 - n
    if major in (2, 3):
        n = reader.argument(info)
        data = reader.take(n)
        if major == 2:
            return data
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            raise CborError('invalid-utf8')
    if major == 4:
        n = reader.argument(info)
        if n > reader.remaining():
            raise CborError('truncated')
        return [_item(reader, depth + 1) for _ in range(n)]
    if major == 5:
        n = reader.argument(info)
        if 2 * n > reader.remaining():
            raise CborError('truncated')
        pairs, seen = [], set()
        for _ in range(n):
            key = _item(reader, depth + 1)
            value = _item(reader, depth + 1)
            ident = encode(key, 1, 'key') if key is not UNDEFINED else b'\xf7'
            if ident in seen:
                raise CborError('duplicate-key')
            seen.add(ident)
            pairs.append((key, value))
        return CborMap(pairs)
    if major == 6:
        raise CborError('tag')
    if info == 20:
        return False
    if info == 21:
        return True
    if info == 22:
        return None
    if info == 23:
        return UNDEFINED
    if info == 24:
        simple = reader.take(1)[0]
        raise CborError('not-well-formed' if simple < 32 else 'simple-value')
    if info == 25:
        return _half(int.from_bytes(reader.take(2), 'big'))
    if info == 26:
        return struct.unpack('>f', reader.take(4))[0]
    if info == 27:
        return struct.unpack('>d', reader.take(8))[0]
    if info == 31:
        raise CborError('not-well-formed')
    if info < 20:
        raise CborError('simple-value')
    raise CborError('not-well-formed')


def decode(data):
    """The ENV §3 semantic decoder."""
    reader = _Reader(data)
    value = _item(reader, 0)
    if reader.remaining():
        raise CborError('trailing-bytes')
    return value


def decode_strict(data):
    """A laboratory choice beyond ENV §3: the input must be its value's deterministic encoding."""
    value = decode(data)
    if encode(value) != bytes(data):
        raise CborError('non-deterministic')
    return value


# ---------------------------------------------------------------- hashes and secp256k1

P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
G = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
     0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)


def sha256(data):
    return hashlib.sha256(data).digest()


def sha256d(data):
    return sha256(sha256(data))


def _jacobian_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    z1z1, z2z2 = z1 * z1 % P, z2 * z2 % P
    u1, u2 = x1 * z2z2 % P, x2 * z1z1 % P
    s1, s2 = y1 * z2 * z2z2 % P, y2 * z1 * z1z1 % P
    if u1 == u2:
        if s1 != s2:
            return None
        return _jacobian_double(p1)
    h = (u2 - u1) % P
    r = (s2 - s1) % P
    hh = h * h % P
    hhh = h * hh % P
    v = u1 * hh % P
    x3 = (r * r - hhh - 2 * v) % P
    y3 = (r * (v - x3) - s1 * hhh) % P
    return (x3, y3, z1 * z2 * h % P)


def _jacobian_double(p1):
    if p1 is None:
        return None
    x, y, z = p1
    if y == 0:
        return None
    yy = y * y % P
    s = 4 * x * yy % P
    m = 3 * x * x % P
    x3 = (m * m - 2 * s) % P
    y3 = (m * (s - x3) - 8 * yy * yy) % P
    return (x3, y3, 2 * y * z % P)


def _affine(point):
    if point is None:
        return None
    x, y, z = point
    zi = pow(z, -1, P)
    return (x * zi * zi % P, y * zi * zi * zi % P)


def point_mul(k, point=G):
    result, addend = None, (point[0], point[1], 1)
    while k:
        if k & 1:
            result = _jacobian_add(result, addend)
        addend = _jacobian_double(addend)
        k >>= 1
    return _affine(result)


def point_add(a, b):
    return _affine(_jacobian_add((a[0], a[1], 1), (b[0], b[1], 1)))


def compress(point):
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, 'big')


def decompress(data):
    if len(data) == 33 and data[0] in (2, 3):
        x = int.from_bytes(data[1:], 'big')
        if x >= P:
            return None
        y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
        if (y * y - x * x * x - 7) % P:
            return None
        if (y & 1) != (data[0] & 1):
            y = P - y
        return (x, y)
    if len(data) == 65 and data[0] == 4:
        x, y = int.from_bytes(data[1:33], 'big'), int.from_bytes(data[33:], 'big')
        return (x, y) if x < P and y < P and (y * y - x * x * x - 7) % P == 0 else None
    return None


class KeyError_(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def hkdf_sha256(ikm, salt, info, length):
    """RFC 5869."""
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    out, block, counter = b'', b'', 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def secp256k1_seed(root, label):
    """KEYS §1.4.2, §1.4.3."""
    if len(root) != 64:
        raise KeyError_('root-length')
    seed = hkdf_sha256(root, b'', label.encode('ascii'), 32)
    if not 0 < int.from_bytes(seed, 'big') < N:
        raise KeyError_('seed-invalid')
    return seed


def self_derived_public_key(seed, derivation_identifier):
    """BRC-42 with counterparty self (KEYS §1.8.2). An offset of 0 or at least n is refused."""
    d = int.from_bytes(seed, 'big')
    shared = compress(point_mul(d, point_mul(d)))
    offset = int.from_bytes(hmac.new(shared, derivation_identifier.encode('utf-8'), hashlib.sha256).digest(), 'big')
    if offset == 0 or offset >= N:
        raise KeyError_('scalar-rejected')
    child = point_add(point_mul(offset), point_mul(d))
    if child is None:
        raise KeyError_('scalar-rejected')
    return compress(child)


def commitment_identifier(profile, account_id, runtime_id, aid):
    protocol = profile['recordKeyIdentifiers']['commitment']['protocolID']
    words = profile['derivation']['keyPath']['keywords']
    path = '/'.join([words['level1'], account_id, words['level2'], runtime_id, words['level3'], aid])
    return '%d-%s-%s' % (protocol[0], protocol[1], path)


def commitment_key(profile, root, account_id, runtime_id, aid):
    seed = secp256k1_seed(root, profile['derivation']['curveLabels']['secp256k1'])
    return self_derived_public_key(seed, commitment_identifier(profile, account_id, runtime_id, aid))


# ---------------------------------------------------------------- transactions and scripts


class ChainError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class _Bytes:
    def __init__(self, data):
        self.data = bytes(data)
        self.pos = 0

    def remaining(self):
        return len(self.data) - self.pos

    def take(self, n):
        if n < 0 or n > self.remaining():
            raise ChainError('truncated')
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self):
        return self.take(1)[0]

    def u32(self):
        return struct.unpack('<I', self.take(4))[0]

    def u64(self):
        return struct.unpack('<Q', self.take(8))[0]

    def varint(self):
        first = self.u8()
        if first < 0xfd:
            return first
        if first == 0xfd:
            v = struct.unpack('<H', self.take(2))[0]
            if v < 0xfd:
                raise ChainError('varint-non-canonical')
            return v
        if first == 0xfe:
            v = self.u32()
            if v < 0x10000:
                raise ChainError('varint-non-canonical')
            return v
        v = self.u64()
        if v < 0x100000000:
            raise ChainError('varint-non-canonical')
        return v


def varint(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)


def read_transaction(r):
    start = r.pos
    version = r.u32()
    inputs = []
    count = r.varint()
    if count == 0:
        raise ChainError('tx-no-inputs')
    for _ in range(count):
        prev, vout = r.take(32), r.u32()
        script = r.take(r.varint())
        inputs.append({'prev': prev, 'vout': vout, 'script': script, 'sequence': r.u32()})
    outputs = []
    count = r.varint()
    if count == 0:
        raise ChainError('tx-no-outputs')
    for _ in range(count):
        o_start = r.pos
        value = r.u64()
        script = r.take(r.varint())
        outputs.append({'satoshis': value, 'script': script, 'raw': r.data[o_start:r.pos]})
    lock_time = r.u32()
    raw = r.data[start:r.pos]
    return {'version': version, 'inputs': inputs, 'outputs': outputs, 'lockTime': lock_time, 'raw': raw, 'txid': sha256d(raw)}


def parse_script(script):
    """Chunks; a push running past the end makes the script malformed."""
    chunks, pos = [], 0
    while pos < len(script):
        op = script[pos]
        pos += 1
        data = None
        if op <= 0x4e:
            width = {0x4c: 1, 0x4d: 2, 0x4e: 4}.get(op, 0)
            if pos + width > len(script):
                return chunks, True
            length = op if width == 0 else int.from_bytes(script[pos:pos + width], 'little')
            pos += width
            if pos + length > len(script):
                return chunks, True
            data = script[pos:pos + length]
            pos += length
        chunks.append((op, data))
    return chunks, False


def minimal_push(op, data):
    if len(data) == 0:
        return op == 0
    if len(data) == 1 and (1 <= data[0] <= 16 or data[0] == 0x81):
        return False
    if len(data) <= 75:
        return op == len(data)
    if len(data) <= 0xff:
        return op == 0x4c
    if len(data) <= 0xffff:
        return op == 0x4d
    return op == 0x4e


def strict_key(key):
    return (len(key) == 33 and key[0] in (2, 3)) or (len(key) == 65 and key[0] == 4)


def check_container(script):
    """ANC §2.1, §2.2: (ok, reason, record, key)."""
    chunks, malformed = parse_script(script)
    if malformed:
        return False, 'container-script-malformed', None, None
    fields = 0
    while fields < len(chunks) and chunks[fields][1] is not None:
        fields += 1
    i, dropped = fields, 0
    while i < len(chunks) and chunks[i][0] in (0x75, 0x6d):
        dropped += 1 if chunks[i][0] == 0x75 else 2
        i += 1
    keyed = len(chunks) == i + 2 and chunks[i][1] is not None and strict_key(chunks[i][1]) and chunks[i + 1][0] == 0xac
    if not keyed or fields == 0 or dropped != fields:
        return False, 'container-template', None, None
    if fields != 1 or chunks[1][0] != 0x75:
        return False, 'container-field-count', None, None
    if not minimal_push(*chunks[0]):
        return False, 'container-push-not-minimal', None, None
    return True, None, chunks[0][1], chunks[2][1]


# ---------------------------------------------------------------- BUMP, BEEF and headers


def read_bump(r):
    height = r.varint()
    tree = r.u8()
    if tree == 0 or tree > 64:
        raise ChainError('bump-tree-height')
    levels = []
    for level in range(tree):
        leaves = {}
        for _ in range(r.varint()):
            offset, flags = r.varint(), r.u8()
            if flags > 2:
                raise ChainError('bump-flags')
            if offset in leaves:
                raise ChainError('bump-duplicate-offset')
            leaves[offset] = None if flags == 1 else r.take(32)
        levels.append(leaves)
    if not levels[0]:
        raise ChainError('bump-empty-level-0')
    return {'height': height, 'tree': tree, 'levels': levels}


_DUP = object()


def _bump_node(bump, height, offset):
    level = bump['levels'][height] if height < len(bump['levels']) else {}
    if offset in level:
        return _DUP if level[offset] is None else level[offset]
    if height == 0:
        return None
    left = _bump_node(bump, height - 1, offset * 2)
    if left is None or left is _DUP:
        return None
    right = _bump_node(bump, height - 1, offset * 2 + 1)
    if right is None:
        return None
    return sha256d(left + (left if right is _DUP else right))


def bump_root(bump, txid):
    index = next((o for o, h in bump['levels'][0].items() if h is not None and h == txid), None)
    if index is None:
        raise ChainError('bump-txid-absent')
    if bump['tree'] == 1 and len(bump['levels'][0]) == 1 and index == 0:
        return txid
    working = txid
    for height in range(bump['tree']):
        position = index >> height
        right = position % 2 == 1
        sibling = _bump_node(bump, height, position - 1 if right else position + 1)
        if sibling is None:
            raise ChainError('bump-missing-node')
        if sibling is _DUP and right:
            raise ChainError('bump-invalid-duplicate')
        other = working if sibling is _DUP else sibling
        working = sha256d(other + working if right else working + other)
    return working


def parse_beef(data):
    r = _Bytes(data)
    magic = r.take(4).hex()
    subject = None
    if magic == '01010101':
        subject = r.take(32)
        magic = r.take(4).hex()
    if magic == '0200beef':
        raise ChainError('beef-v2-unsupported')
    if magic != '0100beef':
        raise ChainError('beef-version')
    bumps = [read_bump(r) for _ in range(r.varint())]
    count = r.varint()
    if count == 0:
        raise ChainError('beef-empty')
    txs, order = {}, []
    for position in range(count):
        tx = read_transaction(r)
        flag = r.u8()
        if flag > 1:
            raise ChainError('beef-bump-flag')
        index = r.varint() if flag == 1 else None
        if tx['txid'] in txs:
            raise ChainError('beef-duplicate-tx')
        if index is not None:
            if index >= len(bumps):
                raise ChainError('beef-bump-index')
            if not any(h == tx['txid'] for h in bumps[index]['levels'][0].values() if h is not None):
                raise ChainError('beef-bump-mismatch')
        txs[tx['txid']] = {'tx': tx, 'bump': index, 'position': position}
        order.append(tx['txid'])
    if r.remaining():
        raise ChainError('trailing-bytes')
    for key in order:
        for inp in txs[key]['tx']['inputs']:
            parent = txs.get(inp['prev'])
            if parent and parent['position'] > txs[key]['position']:
                raise ChainError('beef-order')
    if subject is not None:
        if subject not in txs:
            raise ChainError('beef-atomic-subject-absent')
        related, stack = {subject}, [subject]
        while stack:
            for inp in txs[stack.pop()]['tx']['inputs']:
                if inp['prev'] in txs and inp['prev'] not in related:
                    related.add(inp['prev'])
                    stack.append(inp['prev'])
        if len(related) != len(txs):
            raise ChainError('beef-atomic-unrelated')
    return {'subject': subject, 'bumps': bumps, 'txs': txs, 'order': order}


def header_source(entries):
    """A pinned, contiguous header list: proof of work and links are checked."""
    roots, previous = {}, None
    for entry in entries:
        header = bytes.fromhex(entry['header'])
        if len(header) != 80:
            raise ChainError('header-length')
        digest = sha256d(header)
        bits = struct.unpack('<I', header[72:76])[0]
        target = (bits & 0x7fffff) << (8 * ((bits >> 24) - 3))
        if int.from_bytes(digest[::-1], 'big') > target:
            raise ChainError('header-pow')
        if previous is not None:
            if entry['height'] != previous[0] + 1:
                raise ChainError('header-gap')
            if header[4:36] != previous[1]:
                raise ChainError('header-link')
        roots[entry['height']] = header[36:68]
        previous = (entry['height'], digest)
    if previous is None:
        raise ChainError('header-empty')
    return roots


# ---------------------------------------------------------------- spends (BIP 143, either S)


def _der(sig):
    """(r, s, sighash) of a DER signature with its sighash byte, or None."""
    if len(sig) < 9 or len(sig) > 73 or sig[0] != 0x30 or sig[1] != len(sig) - 3 or sig[2] != 2:
        return None
    len_r = sig[3]
    if 5 + len_r >= len(sig) or sig[4 + len_r] != 2:
        return None
    len_s = sig[5 + len_r]
    if len_r + len_s + 7 != len(sig):
        return None
    r = int.from_bytes(sig[4:4 + len_r], 'big')
    s = int.from_bytes(sig[6 + len_r:6 + len_r + len_s], 'big')
    return r, s, sig[-1]


def sighash_preimage(tx, index, script_code, satoshis, sighash):
    base = sighash & 0x1f
    anyone = sighash & 0x80
    zero = bytes(32)
    prevouts = zero if anyone else sha256d(b''.join(i['prev'] + struct.pack('<I', i['vout']) for i in tx['inputs']))
    sequences = zero if anyone or base in (2, 3) else sha256d(b''.join(struct.pack('<I', i['sequence']) for i in tx['inputs']))
    if base not in (2, 3):
        outputs = sha256d(b''.join(o['raw'] for o in tx['outputs']))
    elif base == 3 and index < len(tx['outputs']):
        outputs = sha256d(tx['outputs'][index]['raw'])
    else:
        outputs = zero
    inp = tx['inputs'][index]
    return (struct.pack('<I', tx['version']) + prevouts + sequences + inp['prev'] + struct.pack('<I', inp['vout'])
            + varint(len(script_code)) + script_code + struct.pack('<Q', satoshis) + struct.pack('<I', inp['sequence'])
            + outputs + struct.pack('<I', tx['lockTime']) + struct.pack('<I', sighash))


def recheck_spend(tx, index, prev_output):
    """The consuming input of a `<record> DROP <key> CHECKSIG` entry; either S is accepted."""
    lock, malformed = parse_script(prev_output['script'])
    if malformed or len(lock) != 4 or lock[0][1] is None or lock[1][0] != 0x75 or lock[2][1] is None or lock[3][0] != 0xac:
        return 'spend-template'
    key = decompress(lock[2][1])
    unlock, malformed = parse_script(tx['inputs'][index]['script'])
    if malformed or not unlock or any(data is None for _, data in unlock):
        return 'spend-unlocking-form'
    parsed = _der(unlock[-1][1])
    if parsed is None or key is None:
        return 'spends-signature-encoding'
    r, s, sighash = parsed
    if sighash not in (0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3):
        return 'spends-sighash-unsupported'
    if not (0 < r < N and 0 < s < N):
        return 'spends-signature-invalid'
    z = int.from_bytes(sha256d(sighash_preimage(tx, index, prev_output['script'], prev_output['satoshis'], sighash)), 'big')
    w = pow(s, -1, N)
    point = point_add(point_mul(z * w % N), point_mul(r * w % N, key))
    if point is None or point[0] % N != r:
        return 'spends-signature-invalid'
    return None


# ---------------------------------------------------------------- the record header (stand-in)

STAND_IN_PROTO = 'tpnil-sdx-lab-stand-in@0.1.0'
ULID = re.compile(r'^[0-7][0-9A-HJKMNP-TV-Z]{25}$')


def decode_stand_in(record):
    """(aid, ep) or the reason the stand-in does not decode."""
    try:
        value = decode(record)
    except CborError:
        return None, 'record-not-decodable'
    if not isinstance(value, CborMap) or value.get('proto') != STAND_IN_PROTO:
        return None, 'record-not-stand-in'
    header = value.get('hdr')
    if not isinstance(header, CborMap):
        return None, 'header-missing'
    aid, ep = header.get('aid'), header.get('ep')
    if not isinstance(aid, str) or not ULID.match(aid):
        return None, 'header-aid'
    if isinstance(ep, bool) or not isinstance(ep, int) or ep < 0:
        return None, 'header-ep'
    return (aid, ep), None


# ---------------------------------------------------------------- ANC §6.1 steps 1-3


def proved_transaction(beef_bytes, roots):
    """(status, label, tx). Status is proved, refused or inconclusive."""
    try:
        beef = parse_beef(beef_bytes)
    except ChainError as error:
        if error.code == 'beef-v2-unsupported':
            return 'inconclusive', 'beef-v2-unsupported', None
        return 'refused', 'beef-malformed', None
    key = beef['subject'] if beef['subject'] is not None else beef['order'][-1]
    entry = beef['txs'][key]
    tx = entry['tx']
    if len(tx['raw']) == 64:
        return 'refused', 'block-64-byte-tx', tx
    if entry['bump'] is None:
        return 'refused', 'block-no-merkle-path', tx
    bump = beef['bumps'][entry['bump']]
    try:
        root = bump_root(bump, tx['txid'])
    except ChainError:
        return 'refused', 'block-path-invalid', tx
    if bump['height'] not in roots:
        return 'inconclusive', 'header-range-unknown', tx
    if roots[bump['height']] != root:
        return 'refused', 'block-root-mismatch', tx
    return 'proved', None, tx


def verify_reference(reference, roots, recipient):
    refuse = lambda label: {'result': 'REJECT', 'class': 'cross-ref-invalid', 'label': label}
    try:
        value = decode_strict(reference)
    except CborError as error:
        return refuse('reference-not-deterministic' if error.code == 'non-deterministic' else 'reference-malformed')
    keys = value.keys() if isinstance(value, CborMap) else []
    if sorted(k for k in keys if isinstance(k, str)) != sorted(['v', 'aid', 'tx', 'out', 'beef']) or len(keys) != 5:
        return refuse('reference-malformed')
    if value.get('v') != 1 or isinstance(value.get('v'), bool):
        return refuse('reference-version')
    aid, cited, out, beef = value.get('aid'), value.get('tx'), value.get('out'), value.get('beef')
    if not isinstance(aid, str) or not ULID.match(aid) or not isinstance(cited, bytes) or len(cited) != 32:
        return refuse('reference-malformed')
    if isinstance(out, bool) or not isinstance(out, int) or out < 0 or not isinstance(beef, bytes) or not beef:
        return refuse('reference-malformed')
    status, label, tx = proved_transaction(beef, roots)
    if status == 'inconclusive':
        return {'result': 'INCONCLUSIVE', 'label': label}
    if status == 'refused':
        return refuse(label)
    if cited != tx['txid']:
        return refuse('txid-mismatch')
    if out >= len(tx['outputs']):
        return refuse('output-missing')
    ok, reason, record, _ = check_container(tx['outputs'][out]['script'])
    if not ok:
        return refuse(reason)
    if recipient:
        header, why = decode_stand_in(record)
        if header is None:
            return refuse('citation-undecodable')
        if header[0] != aid:
            return refuse('citation-mismatch')
    return {'result': 'ACCEPT'}


# ---------------------------------------------------------------- ANC §7.1 walk

def display(txid):
    return txid[::-1].hex()


def walk_chain(profile, account_id, runtime_id, keyring, start_kind, start_txid, start_vout, rows, roots):
    txs, refused = {}, []
    for beef in rows:
        status, label, tx = proved_transaction(beef, roots)
        if tx['txid'] in txs:
            continue
        txs[tx['txid']] = (status, label, tx)
        if status == 'refused':
            refused.append({'txid': display(tx['txid']), 'label': label})
    usable = [item for item in txs.values() if item[0] != 'refused']
    cache = {}

    def entry_of(tx, vout):
        key = (tx['txid'], vout)
        if key not in cache:
            result = ('not-container', None)
            if vout < len(tx['outputs']):
                ok, _, record, commitment = check_container(tx['outputs'][vout]['script'])
                if ok:
                    header, why = decode_stand_in(record)
                    if header is None:
                        result = ('decode-fail', why)
                    elif header[1] not in keyring:
                        result = ('key-missing', header[0])
                    else:
                        expected = commitment_key(profile, keyring[header[1]], account_id, runtime_id, header[0])
                        result = ('match' if expected == commitment else 'mismatch', header[0])
            cache[key] = result
        return cache[key]

    def is_chain_entry(txid, vout):
        item = txs.get(txid)
        return bool(item and item[0] != 'refused' and entry_of(item[2], vout)[0] == 'match')

    dispatched, letters, linked = [], [], set()
    state = {'current': None}

    def finish(inconclusive=None):
        current = state['current']
        out = {'result': 'INCONCLUSIVE' if inconclusive else 'DEAD-LETTERED' if letters else 'COMPLETE'}
        if inconclusive:
            out['reason'] = inconclusive
        out.update({'dispatched': dispatched, 'tip': {'txid': display(current[0]), 'outputIndex': current[1]} if current else None,
                    'deadLetters': letters, 'refused': refused})
        return out

    def letter(tx, cls, label):
        letters.append({'txid': display(tx['txid']), 'class': cls, 'label': label})

    def failure(evaluations):
        kinds = [e[0] for e in evaluations]
        if 'key-missing' in kinds:
            return 'key-missing', 'epoch-root-not-held'
        if 'decode-fail' in kinds:
            return 'decode-fail', next(e[1] for e in evaluations if e[0] == 'decode-fail')
        return 'integrity-fail', 'no-output-matches'

    start = txs.get(start_txid)
    if start is None or start[0] == 'refused':
        return finish('start-not-held')
    if start[0] == 'inconclusive':
        return finish(start[1])
    if start_kind == 'origin':
        kind, aid = entry_of(start[2], start_vout)
        if kind != 'match':
            cls, label = ('integrity-fail', 'origin-not-derived') if kind in ('mismatch', 'not-container') else failure([(kind, aid)])
            letter(start[2], cls, label)
            return finish()
        dispatched.append(aid)
    elif start_kind != 'last-processed':
        raise ValueError(start_kind)
    state['current'] = (start_txid, start_vout)
    linked.add(state['current'])
    item = start
    while item:
        back = next((i for i in item[2]['inputs'] if is_chain_entry(i['prev'], i['vout']) and (i['prev'], i['vout']) not in linked), None)
        if back is None:
            break
        linked.add((back['prev'], back['vout']))
        item = txs.get(back['prev'])

    while True:
        current = state['current']
        consumers = [i for i in usable if any(inp['prev'] == current[0] and inp['vout'] == current[1] for inp in i[2]['inputs'])]
        if not consumers:
            break
        if len(consumers) > 1:
            return finish('consumer-ambiguous')
        status, label, tx = consumers[0]
        if status == 'inconclusive':
            return finish(label)
        tips = [inp for inp in tx['inputs'] if (inp['prev'] == current[0] and inp['vout'] == current[1]) or is_chain_entry(inp['prev'], inp['vout'])]
        if len(tips) != 1:
            letter(tx, 'unlisted', 'two-tips-consumed')
            return finish()
        problem = recheck_spend(tx, tx['inputs'].index(tips[0]), txs[current[0]][2]['outputs'][current[1]])
        if problem:
            return finish('spend-recheck-' + problem)
        evaluations = [entry_of(tx, vout) + (vout,) for vout in range(len(tx['outputs']))]
        matches = [e for e in evaluations if e[0] == 'match']
        if len(matches) > 1:
            letter(tx, 'unlisted', 'two-successors')
            return finish()
        if not matches:
            letter(tx, *failure(evaluations))
            return finish()
        dispatched.append(matches[0][1])
        state['current'] = (tx['txid'], matches[0][2])
        linked.add(state['current'])

    for status, _, tx in usable:
        if status != 'proved':
            continue
        for vout in range(len(tx['outputs'])):
            if (tx['txid'], vout) not in linked and entry_of(tx, vout)[0] == 'match':
                letter(tx, 'chain-break-timeout', 'entry-not-linked')
    return finish()


# ---------------------------------------------------------------- suite runner


def run_case(suite, profile, item):
    headers = suite['chain']['headers']
    through = item['input'].get('headersThrough')
    roots = header_source([h for h in headers if through is None or h['height'] <= through])
    if item['verifier'] == 'reference':
        return verify_reference(bytes.fromhex(item['input']['reference']), roots, item['input']['recipient'])
    inp = item['input']
    chain = suite['chains'][inp['chain']]
    keyring = {ep: bytes.fromhex(suite['testKeys']['roots']['participant'][str(ep)]['root']) for ep in inp['keyring']}
    start = suite['transactions'][inp['start']['transaction']]
    return walk_chain(profile, chain['accountId'], chain['runtimeId'], keyring, inp['start']['kind'],
                      bytes.fromhex(start['txidDisplay'])[::-1], inp['start']['outputIndex'],
                      [bytes.fromhex(suite['transactions'][name]['beef']) for name in inp['rows']], roots)
