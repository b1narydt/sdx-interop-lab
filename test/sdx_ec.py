"""LAB_SELF_TEST_ONLY: standard-library elliptic-curve oracle for the SDX vector suites.

The module implements short-Weierstrass arithmetic over P-256 and secp256k1 in
plain Python integers, with the primitives the SDX checks recompute: point
validation and compression, scalar multiplication, ECDSA verification, RFC 6979
deterministic nonces, DER signature encoding, HKDF-SHA-256, the SDX KEYS §1.4.2 root split, the
KEYS §1.8.2 child derivation with scalar rejection, the RFC 7518 §4.6.2 Concat
KDF, the BRC-42/BRC-2 key derivation on secp256k1, and the AES-256 steps of an
ECDH-ES+A256KW / A256GCM JWE: the AES block cipher (FIPS 197), AES key unwrap
(RFC 3394) and GCM decryption (NIST SP 800-38D), which the standard library
lacks.

It imports no third-party package and no project code, so it stays independent
of every generator. The arithmetic is not constant-time and is for test vectors
only.
"""

import hashlib
import hmac


class Curve:
    """Parameters of y^2 = x^3 + a*x + b over GF(p) with a prime-order group."""

    def __init__(self, name, p, a, b, n, gx, gy):
        self.name, self.p, self.a, self.b, self.n = name, p, a % p, b, n
        self.g = (gx, gy)
        if pow(gy, 2, p) != (gx ** 3 + self.a * gx + b) % p or p % 4 != 3:
            raise ValueError('curve parameters')

    def __repr__(self):
        return self.name


P256 = Curve(
    'P-256',
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=-3,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)

SECP256K1 = Curve(
    'secp256k1',
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

CURVES = {'p256': P256, 'secp256k1': SECP256K1}


class EcError(ValueError):
    """A rejection with a stable reason code, such as 'point-x-range'."""

    def __init__(self, code, detail=''):
        super().__init__(f'{code}: {detail}' if detail else code)
        self.code = code


# -- field and group arithmetic (None is the point at infinity) --------------

def is_on_curve(c, point):
    if point is None:
        return False
    x, y = point
    return 0 <= x < c.p and 0 <= y < c.p and (y * y - (x ** 3 + c.a * x + c.b)) % c.p == 0


def neg(c, point):
    return None if point is None else (point[0], (-point[1]) % c.p)


def add(c, p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2:
        if (y1 + y2) % c.p == 0:
            return None
        slope = (3 * x1 * x1 + c.a) * pow(2 * y1, -1, c.p) % c.p
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, c.p) % c.p
    x3 = (slope * slope - x1 - x2) % c.p
    return (x3, (slope * (x1 - x3) - y1) % c.p)


def mul(c, k, point):
    """k * point by double-and-add on affine coordinates."""
    k %= c.n
    result, addend = None, point
    while k:
        if k & 1:
            result = add(c, result, addend)
        addend = add(c, addend, addend)
        k >>= 1
    return result


def base_mul(c, k):
    return mul(c, k, c.g)


def sqrt_mod(c, value):
    """Square root modulo p (p = 3 mod 4 on both curves), or None for a non-residue."""
    root = pow(value % c.p, (c.p + 1) // 4, c.p)
    return root if root * root % c.p == value % c.p else None


def compress(c, point):
    if point is None:
        raise EcError('point-infinity')
    x, y = point
    return bytes([2 | (y & 1)]) + x.to_bytes(32, 'big')


def decode_point(c, data):
    """Validate a SEC1 compressed point in the order the sdx module draft and BRC-229 state.

    Exactly 33 bytes; prefix 02 or 03; x < p checked on the encoded integer
    before any reduction; x^3 + a*x + b a quadratic residue (on the curve); the
    result finite. A compressed encoding cannot name infinity, so the last check
    is satisfied by construction for every input that passes the others.
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) != 33:
        raise EcError('point-length', f'{len(data)} bytes')
    if data[0] not in (2, 3):
        raise EcError('point-prefix', f'{data[0]:02x}')
    x = int.from_bytes(data[1:], 'big')
    if x >= c.p:
        raise EcError('point-x-range')
    y = sqrt_mod(c, x ** 3 + c.a * x + c.b)
    if y is None:
        raise EcError('point-not-on-curve')
    if (y & 1) != (data[0] & 1):
        y = c.p - y
    point = (x, y)
    if not is_on_curve(c, point):
        raise EcError('point-not-on-curve')
    return point


def scalar(c, data, code='scalar-range'):
    """A big-endian scalar that must lie in [1, n - 1]; never reduced or clamped."""
    value = int.from_bytes(data, 'big') if isinstance(data, (bytes, bytearray)) else data
    if not 1 <= value < c.n:
        raise EcError(code, c.name)
    return value


def int32(value):
    return value.to_bytes(32, 'big')


# -- hashes and KDFs ----------------------------------------------------------

def sha256(data):
    return hashlib.sha256(data).digest()


def hmac_sha256(key, message):
    return hmac.new(key, message, hashlib.sha256).digest()


def hkdf_sha256(ikm, salt, info, length):
    """RFC 5869 HKDF with SHA-256. An empty salt is the zero-length HMAC key."""
    prk = hmac_sha256(salt, ikm)
    okm, block, counter = b'', b'', 1
    while len(okm) < length:
        block = hmac_sha256(prk, block + info + bytes([counter]))
        okm += block
        counter += 1
    return okm[:length]


def concat_kdf_sha256(z, keydatalen_bits, algorithm_id, apu=b'', apv=b''):
    """RFC 7518 §4.6.2 Concat KDF (NIST SP 800-56A single-step, SHA-256)."""
    def field(value):
        return len(value).to_bytes(4, 'big') + value
    other = field(algorithm_id) + field(apu) + field(apv) + keydatalen_bits.to_bytes(4, 'big')
    out, counter = b'', 1
    while len(out) * 8 < keydatalen_bits:
        out += sha256(counter.to_bytes(4, 'big') + z + other)
        counter += 1
    return out[:keydatalen_bits // 8]


# -- SDX KEYS §1.4 and §1.8 ---------------------------------------------------

def split_ikm(ikm, secp256k1_label, p256_label):
    """KEYS §1.4.2 split. Both seeds are validated (§1.4.3) before either is returned."""
    if len(ikm) != 64:
        raise EcError('ikm-length', f'{len(ikm)} bytes')
    k1 = hkdf_sha256(ikm, b'', secp256k1_label, 32)
    r1 = hkdf_sha256(ikm, b'', p256_label, 32)
    for curve, seed in ((SECP256K1, k1), (P256, r1)):
        if not 1 <= int.from_bytes(seed, 'big') < curve.n:
            raise EcError('ikm-unusable', curve.name)
    return k1, r1


def check_offset(c, hmac_bytes):
    """KEYS §1.8.2 scalar rejection: 0 or >= n fails; the value is never reduced mod n."""
    h = int.from_bytes(hmac_bytes, 'big')
    if h == 0 or h >= c.n:
        raise EcError('scalar-rejected', c.name)
    return h


def sdx_offset(c, own_private, counterparty_point, identifier):
    """Shared point, HMAC and offset h for one derivation identifier."""
    shared = compress(c, mul(c, own_private, counterparty_point))
    digest = hmac_sha256(shared, identifier.encode('utf-8'))
    return shared, digest, check_offset(c, digest)


def sdx_child_private(c, own_private, counterparty_point, identifier):
    _, _, h = sdx_offset(c, own_private, counterparty_point, identifier)
    child = (own_private + h) % c.n
    if child == 0:
        raise EcError('child-zero', c.name)
    return child


def sdx_child_public(c, own_private, counterparty_point, identifier):
    """The counterparty's child public key: counterparty + h*G."""
    _, _, h = sdx_offset(c, own_private, counterparty_point, identifier)
    child = add(c, counterparty_point, base_mul(c, h))
    if child is None:
        raise EcError('point-infinity')
    return child


# -- ECDSA --------------------------------------------------------------------

def bits2int(c, data):
    value = int.from_bytes(data, 'big')
    excess = len(data) * 8 - c.n.bit_length()
    return value >> excess if excess > 0 else value


def rfc6979_nonces(c, private, digest):
    """RFC 6979 §3.2 HMAC-DRBG candidates with SHA-256 (qlen = hlen = 256 here)."""
    x = int32(private)
    h1 = int32(bits2int(c, digest) % c.n)
    v, k = b'\x01' * 32, b'\x00' * 32
    k = hmac_sha256(k, v + b'\x00' + x + h1)
    v = hmac_sha256(k, v)
    k = hmac_sha256(k, v + b'\x01' + x + h1)
    v = hmac_sha256(k, v)
    while True:
        t = b''
        while len(t) < 32:
            v = hmac_sha256(k, v)
            t += v
        candidate = bits2int(c, t)
        if 1 <= candidate < c.n:
            yield candidate
        k = hmac_sha256(k, v + b'\x00')
        v = hmac_sha256(k, v)


def ecdsa_sign_rfc6979(c, private, digest, low_s=False):
    """Deterministic ECDSA. Returns (r, s, k). low_s=False leaves s as computed."""
    z = bits2int(c, digest) % c.n
    for k in rfc6979_nonces(c, private, digest):
        r = base_mul(c, k)[0] % c.n
        if r == 0:
            continue
        s = pow(k, -1, c.n) * (z + r * private) % c.n
        if s == 0:
            continue
        if low_s and s > c.n // 2:
            s = c.n - s
        return r, s, k
    raise AssertionError('unreachable')


def der_encode(r, s):
    """DER (X.690) SEQUENCE of two minimal positive INTEGERs, as BRC-100 createSignature returns."""
    def integer(value):
        data = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
        if data[0] & 0x80:
            data = b'\x00' + data
        return b'\x02' + bytes([len(data)]) + data
    body = integer(r) + integer(s)
    return b'\x30' + bytes([len(body)]) + body


def der_decode(data):
    """Strict DER decoding of an ECDSA signature; raises EcError('signature-encoding')."""
    if len(data) < 8 or data[0] != 0x30 or data[1] != len(data) - 2:
        raise EcError('signature-encoding')
    values, position = [], 2
    for _ in range(2):
        if position + 2 > len(data) or data[position] != 0x02:
            raise EcError('signature-encoding')
        length = data[position + 1]
        value = data[position + 2:position + 2 + length]
        if length == 0 or len(value) != length or value[0] & 0x80 or (length > 1 and value[0] == 0 and not value[1] & 0x80):
            raise EcError('signature-encoding')
        values.append(int.from_bytes(value, 'big'))
        position += 2 + length
    if position != len(data):
        raise EcError('signature-encoding')
    return tuple(values)


def ecdsa_verify(c, public_point, digest, r, s):
    """Plain ECDSA verification; accepts either s (no low-S rule)."""
    if not (1 <= r < c.n and 1 <= s < c.n) or not is_on_curve(c, public_point):
        return False
    w = pow(s, -1, c.n)
    z = bits2int(c, digest) % c.n
    point = add(c, base_mul(c, z * w % c.n), mul(c, r * w % c.n, public_point))
    return point is not None and point[0] % c.n == r


def ecdh_x(c, private, public_point):
    point = mul(c, private, public_point)
    if point is None:
        raise EcError('point-infinity')
    return int32(point[0])


# -- BRC-42 / BRC-2 on secp256k1 ----------------------------------------------

def brc42_child_private(private, counterparty_point, invoice):
    return sdx_child_private(SECP256K1, private, counterparty_point, invoice)


def brc42_child_public(private, counterparty_point, invoice):
    return sdx_child_public(SECP256K1, private, counterparty_point, invoice)


def brc2_symmetric_key(own_private, counterparty_point, invoice):
    """BRC-2: x of (own child private) * (counterparty child public), 32 bytes.

    BRC-42 reduces the offset mod n where KEYS §1.8.2 rejects it; on secp256k1 an
    offset >= n has probability about 2^-128, so the two agree on every reachable
    input.
    """
    own_child = brc42_child_private(own_private, counterparty_point, invoice)
    their_child = brc42_child_public(own_private, counterparty_point, invoice)
    return ecdh_x(SECP256K1, own_child, their_child)


# -- AES-256 (FIPS 197), AES key unwrap (RFC 3394) and GCM (SP 800-38D) ---------

def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _gf256_tables():
    exp, log, x = [0] * 510, [0] * 256, 1
    for i in range(255):
        exp[i], log[x] = x, i
        x ^= _xtime(x)  # times 3, a generator of GF(2^8)*
    for i in range(255, 510):
        exp[i] = exp[i - 255]
    return exp, log


_EXP, _LOG = _gf256_tables()


def _gmul(a, b):
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _sbox_value(a):
    """FIPS 197 §5.1.1: the multiplicative inverse in GF(2^8), then the affine map."""
    b = 0 if a == 0 else _EXP[255 - _LOG[a]]
    s = b
    for k in range(1, 5):
        s ^= ((b << k) | (b >> (8 - k))) & 0xFF
    return s ^ 0x63


SBOX = bytes(_sbox_value(a) for a in range(256))
INV_SBOX = bytes(SBOX.index(a) for a in range(256))
_MUL = {c: bytes(_gmul(c, a) for a in range(256)) for c in (1, 2, 3, 9, 11, 13, 14)}


def aes256_round_keys(key):
    """FIPS 197 §5.2 key expansion for a 256-bit key: 15 round keys of 16 bytes."""
    if len(key) != 32:
        raise ValueError('AES-256 takes a 32-byte key')
    words = [list(key[4 * i:4 * i + 4]) for i in range(8)]
    rcon = 1
    for i in range(8, 60):
        t = list(words[i - 1])
        if i % 8 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % 8 == 4:
            t = [SBOX[b] for b in t]
        words.append([a ^ b for a, b in zip(words[i - 8], t)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(15)]


def _mix_columns(state, coefficients):
    out = []
    for c in range(4):
        column = state[4 * c:4 * c + 4]
        for i in range(4):
            value = 0
            for j in range(4):
                value ^= _MUL[coefficients[(j - i) % 4]][column[j]]
            out.append(value)
    return out


def aes256_encrypt_block(round_keys, block):
    """The AES cipher (FIPS 197 §5.1); the state is column-major, byte r + 4c."""
    state = [b ^ k for b, k in zip(block, round_keys[0])]
    for rnd in range(1, 15):
        state = [SBOX[b] for b in state]
        state = [state[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]
        if rnd != 14:
            state = _mix_columns(state, (2, 3, 1, 1))
        state = [b ^ k for b, k in zip(state, round_keys[rnd])]
    return bytes(state)


def aes256_decrypt_block(round_keys, block):
    """The inverse cipher (FIPS 197 §5.3)."""
    state = [b ^ k for b, k in zip(block, round_keys[14])]
    for rnd in range(13, -1, -1):
        state = [state[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]
        state = [INV_SBOX[b] for b in state]
        state = [b ^ k for b, k in zip(state, round_keys[rnd])]
        if rnd != 0:
            state = _mix_columns(state, (14, 11, 13, 9))
    return bytes(state)


AES_KW_IV = bytes.fromhex('a6a6a6a6a6a6a6a6')


def aes_key_unwrap(kek, wrapped):
    """RFC 3394 §2.2.2 key unwrap with AES-256; a failed integrity check raises decrypt-failed."""
    if len(wrapped) % 8 or len(wrapped) < 24:
        raise EcError('decrypt-failed', 'AES key unwrap length')
    keys = aes256_round_keys(kek)
    n = len(wrapped) // 8 - 1
    a, r = wrapped[:8], [wrapped[8 * (i + 1):8 * (i + 2)] for i in range(n)]
    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            b = aes256_decrypt_block(keys, (int.from_bytes(a, 'big') ^ (n * j + i)).to_bytes(8, 'big') + r[i - 1])
            a, r[i - 1] = b[:8], b[8:]
    if not hmac.compare_digest(a, AES_KW_IV):
        raise EcError('decrypt-failed', 'AES key unwrap integrity')
    return b''.join(r)


def _gf128_mul(x, y):
    """SP 800-38D §6.3 multiplication in GF(2^128), bit 0 the most significant."""
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
    return z


def _ghash(h, data):
    y = 0
    for i in range(0, len(data), 16):
        y = _gf128_mul(y ^ int.from_bytes(data[i:i + 16], 'big'), h)
    return y


def aes_gcm_decrypt(key, iv, aad, ciphertext, tag):
    """SP 800-38D §7.2 GCM-AD with AES-256 and a 96-bit IV; a bad tag raises decrypt-failed."""
    if len(iv) != 12 or len(tag) != 16:
        raise EcError('decrypt-failed', 'A256GCM IV or tag length')
    keys = aes256_round_keys(key)
    h = int.from_bytes(aes256_encrypt_block(keys, bytes(16)), 'big')

    def pad(data):
        return data + bytes(-len(data) % 16)
    s = _ghash(h, pad(aad) + pad(ciphertext) + (8 * len(aad)).to_bytes(8, 'big') + (8 * len(ciphertext)).to_bytes(8, 'big'))
    j0 = iv + (1).to_bytes(4, 'big')
    expected = bytes(a ^ b for a, b in zip(aes256_encrypt_block(keys, j0), s.to_bytes(16, 'big')))
    if not hmac.compare_digest(expected, tag):
        raise EcError('decrypt-failed', 'A256GCM authentication')
    out = bytearray()
    for index, start in enumerate(range(0, len(ciphertext), 16)):
        stream = aes256_encrypt_block(keys, iv + ((2 + index) & 0xFFFFFFFF).to_bytes(4, 'big'))
        out += bytes(a ^ b for a, b in zip(ciphertext[start:start + 16], stream))
    return bytes(out)
