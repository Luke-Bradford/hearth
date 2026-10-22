"""The two ciphers TP-Link's local web API needs, in plain Python (Hearth uses only the
standard library): AES-128-CBC with PKCS#7 padding, and RSA PKCS#1 v1.5 encryption with a
public key. Checked against FIPS-197 / NIST SP 800-38A test vectors and OpenSSL in the tests.

Not constant-time: fine for talking to a device on your own network, not for general use."""
import os


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a, b = _xtime(a), b >> 1
    return r


def _make_sbox():
    sbox, inv = [0] * 256, [0] * 256
    for x in range(256):
        # multiplicative inverse in GF(2^8), then the affine transform
        y = next((c for c in range(1, 256) if _mul(x, c) == 1), 0) if x else 0
        s = y
        for _ in range(4):
            y = ((y << 1) | (y >> 7)) & 0xFF
            s ^= y
        s ^= 0x63
        sbox[x], inv[s] = s, x
    return sbox, inv


SBOX, INV_SBOX = _make_sbox()


def _expand_key(key):
    if len(key) != 16:
        raise ValueError("AES-128 needs a 16-byte key")
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum(w[r * 4:r * 4 + 4], []) for r in range(11)]


def _add(s, k):
    return [a ^ b for a, b in zip(s, k)]


def _shift(s, inverse=False):
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            src = (c + r) % 4 if not inverse else (c - r) % 4
            out[c * 4 + r] = s[src * 4 + r]
    return out


def _mix(s, m):
    out = []
    for c in range(4):
        col = s[c * 4:c * 4 + 4]
        for r in range(4):
            v = 0
            for k in range(4):
                v ^= _mul(m[r][k], col[k])
            out.append(v)
    return out


_M = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
_IM = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]


def aes_encrypt_block(rk, block):
    s = _add(list(block), rk[0])
    for r in range(1, 10):
        s = _add(_mix(_shift([SBOX[b] for b in s]), _M), rk[r])
    return bytes(_add(_shift([SBOX[b] for b in s]), rk[10]))


def aes_decrypt_block(rk, block):
    s = _add(list(block), rk[10])
    for r in range(9, 0, -1):
        s = [INV_SBOX[b] for b in _shift(s, inverse=True)]
        s = _mix(_add(s, rk[r]), _IM)
    s = [INV_SBOX[b] for b in _shift(s, inverse=True)]
    return bytes(_add(s, rk[0]))


def aes_cbc_encrypt(key, iv, data):
    rk = _expand_key(key)
    pad = 16 - len(data) % 16
    data += bytes([pad]) * pad
    out, prev = [], iv
    for i in range(0, len(data), 16):
        prev = aes_encrypt_block(rk, bytes(a ^ b for a, b in zip(data[i:i + 16], prev)))
        out.append(prev)
    return b"".join(out)


def aes_cbc_decrypt(key, iv, data):
    if not data or len(data) % 16:
        raise ValueError("ciphertext is not a whole number of blocks")
    rk = _expand_key(key)
    out, prev = [], iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        out.append(bytes(a ^ b for a, b in zip(aes_decrypt_block(rk, block), prev)))
        prev = block
    plain = b"".join(out)
    pad = plain[-1]
    if not 1 <= pad <= 16 or plain[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad padding")
    return plain[:-pad]


def rsa_encrypt(n_hex, e_hex, message, chunked=False):
    """RSA PKCS#1 v1.5 encryption with a public key given as hex. With chunked=True a long
    message is split into pieces that fit the key and the hex results are concatenated (how
    TP-Link signs requests)."""
    n, e = int(n_hex, 16), int(e_hex, 16)
    k = (n.bit_length() + 7) // 8
    size = k - 11
    pieces = [message[i:i + size] for i in range(0, len(message), size)] if chunked else [message]
    if any(len(p) > size for p in pieces):
        raise ValueError("message too long for this key")
    out = []
    for p in pieces:
        ps = b""
        while len(ps) < k - 3 - len(p):  # non-zero random padding
            ps += bytes(b for b in os.urandom(k) if b)
        block = b"\x00\x02" + ps[:k - 3 - len(p)] + b"\x00" + p
        out.append(format(pow(int.from_bytes(block, "big"), e, n), "0{}x".format(k * 2)))
    return "".join(out)
