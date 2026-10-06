#!/usr/bin/env python3
"""eth_abi_lite — Ethereum ABI encoder/decoder in pure Python, zero dependencies.

Implements the head/tail encoding scheme from the Solidity ABI specification:
elementary types (uint<N>, int<N>, address, bool, bytes<M>, function),
string, bytes, static arrays T[k], dynamic arrays T[], and tuples (T1,...,Tn).

Also computes 4-byte function selectors via a self-contained Keccak-256
(the pre-NIST variant Ethereum uses — *not* hashlib.sha3_256).
"""

import re

# ---------------------------------------------------------------------------
# Keccak-256 (Keccak-f[1600], pad10*1, domain byte 0x01 — Ethereum's variant)
# ---------------------------------------------------------------------------

_MASK64 = (1 << 64) - 1

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_R = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rot(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & _MASK64 if n else x & _MASK64


def _keccak_f(st):
    for rc in _RC:
        c = [st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rot(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                st[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rot(st[x + 5 * y], _R[x][y])
        for x in range(5):
            for y in range(5):
                st[x + 5 * y] = (b[x + 5 * y]
                                 ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])) & _MASK64
        st[0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136  # bytes (1088-bit rate)
    padded = data + b"\x01" + b"\x00" * ((rate - len(data) - 2) % rate) + b"\x80"
    st = [0] * 25
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _keccak_f(st)
    return b"".join(st[i].to_bytes(8, "little") for i in range(4))


# ---------------------------------------------------------------------------
# Type parsing: "uint256", "bytes3[2]", "(uint256,string)[]", ...
# ---------------------------------------------------------------------------

_TYPE_RE = re.compile(r"[a-z]+")


def _parse(s, i=0):
    if s[i] == "(":
        i += 1
        elems = []
        if s[i] != ")":
            while True:
                t, i = _parse(s, i)
                elems.append(t)
                if s[i] == ",":
                    i += 1
                    continue
                break
        assert s[i] == ")", "unbalanced ')' in %r" % s
        i += 1
        base = ("tuple", elems)
    else:
        m = _TYPE_RE.match(s, i)
        assert m, "bad type at %r" % s[i:]
        name = m.group(0)
        i = m.end()
        m2 = re.match(r"\d+", s[i:])
        if m2:
            name += m2.group(0)
            i += m2.end()
        base = (name,)
    while i < len(s) and s[i] == "[":
        j = s.index("]", i)
        num = s[i + 1:j]
        base = ("static_array" if num else "dynamic_array",
                base, int(num) if num else None)
        i = j + 1
    return base, i


def parse_type(s):
    t, i = _parse(s)
    assert i == len(s), "trailing characters in %r" % s
    return t


def is_dynamic(t):
    k = t[0]
    if k in ("string", "dynamic_array"):
        return True
    if k == "bytes" and len(t) == 1:
        return True
    if k == "tuple":
        return any(is_dynamic(e) for e in t[1])
    if k == "static_array":
        return is_dynamic(t[1])
    return False


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def _pad(b):
    return b + b"\x00" * ((-len(b)) % 32)


def _len_word(n):
    return n.to_bytes(32, "big")


def _enc_word(t, v):
    name = t[0]
    if name.startswith("uint"):
        bits = int(name[4:]) or 256
        v = int(v)
        assert 0 <= v < 1 << bits, "uint%d out of range" % bits
        return v.to_bytes(32, "big")
    if name.startswith("int"):
        bits = int(name[3:]) or 256
        v = int(v)
        assert -(1 << (bits - 1)) <= v < 1 << (bits - 1), "int%d out of range" % bits
        return (v % (1 << bits)).to_bytes(32, "big")
    if name == "address":
        b = bytes.fromhex(str(v).removeprefix("0x").removeprefix("0X"))
        assert len(b) == 20, "address must be 20 bytes"
        return b"\x00" * 12 + b
    if name == "bool":
        assert v in (True, False, 0, 1)
        return (1 if v else 0).to_bytes(32, "big")
    if name.startswith("bytes") and name != "bytes":
        m = int(name[5:])
        assert 1 <= m <= 32
        b = bytes(v)
        assert len(b) == m, "bytes%d must be %d bytes" % (m, m)
        return b + b"\x00" * (32 - m)
    if name == "function":
        b = bytes(v)
        assert len(b) == 24, "function type is 24 bytes"
        return b + b"\x00" * 8
    raise ValueError("unsupported type %r" % (name,))


def _enc_seq(types, values):
    """Encode a tuple's worth of values: heads, then tails."""
    assert len(types) == len(values)
    heads, tails = [], []
    offset = 32 * len(types)
    for t, v in zip(types, values):
        head, tail, dyn = _enc_one(t, v)
        if dyn:
            heads.append(_len_word(offset))
            offset += len(tail)
        else:
            heads.append(head)
        tails.append(tail)
    return b"".join(heads + tails)


def _enc_one(t, v):
    """-> (head_bytes | None, tail_bytes, is_dynamic_head)."""
    if is_dynamic(t):
        return None, _enc_full(t, v), True
    k = t[0]
    if k == "tuple":
        return _enc_seq(t[1], v), b"", False
    if k == "static_array":
        return _enc_seq([t[1]] * t[2], v), b"", False
    return _enc_word(t, v), b"", False


def _enc_full(t, v):
    k = t[0]
    if k == "string":
        b = v.encode("utf-8") if isinstance(v, str) else bytes(v)
        return _len_word(len(b)) + _pad(b)
    if k == "bytes":  # ('bytes',) — dynamic bytes
        b = bytes(v)
        return _len_word(len(b)) + _pad(b)
    if k == "dynamic_array":
        return _len_word(len(v)) + _enc_seq([t[1]] * len(v), v)
    elems = t[1] if k == "tuple" else [t[1]] * t[2]
    return _enc_seq(elems, v)


def encode(types, values):
    """Encode values for canonical ABI type strings, e.g. ["uint256","bool"]."""
    return _enc_seq([parse_type(t) for t in types], values)


def encode_call(signature, args):
    """Encode a full calldata blob: 4-byte selector + encoded arguments."""
    name, rest = signature.split("(", 1)
    types = []
    depth = 0
    cur = ""
    for ch in rest:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            types.append(cur)
            cur = ""
        elif ch == ")" and depth < 0:
            break
        else:
            cur += ch
    if cur:
        types.append(cur)
    sel = keccak256(signature.encode())[:4]
    return sel + encode(types, args)


def selector(signature):
    """4-byte function selector, e.g. selector("transfer(address,uint256)")."""
    return keccak256(signature.encode())[:4].hex()


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

def _dec_word(t, word):
    name = t[0]
    if name.startswith("uint"):
        return int.from_bytes(word, "big")
    if name.startswith("int"):
        bits = int(name[3:]) or 256
        v = int.from_bytes(word, "big")
        return v - (1 << bits) if v >= 1 << (bits - 1) else v
    if name == "address":
        assert word[:12] == b"\x00" * 12
        return "0x" + word[12:].hex()
    if name == "bool":
        v = int.from_bytes(word, "big")
        assert v in (0, 1)
        return bool(v)
    if name.startswith("bytes") and name != "bytes":
        m = int(name[5:])
        return word[:m]
    if name == "function":
        return word[:24]
    raise ValueError("unsupported type %r" % (name,))


def _dec_one(t, data, pos, base):
    """Decode one slot at absolute pos; dynamic offsets resolve via base.
    Returns (value, new_pos)."""
    if is_dynamic(t):
        off = int.from_bytes(data[pos:pos + 32], "big")
        return _dec_full(t, data, base + off), pos + 32
    k = t[0]
    if k == "tuple":
        vals = []
        for e in t[1]:
            v, pos = _dec_one(e, data, pos, base)
            vals.append(v)
        return tuple(vals), pos
    if k == "static_array":
        vals = []
        for _ in range(t[2]):
            v, pos = _dec_one(t[1], data, pos, base)
            vals.append(v)
        return vals, pos
    return _dec_word(t, data[pos:pos + 32]), pos + 32


def _dec_full(t, data, pos):
    """Decode a dynamically-encoded value starting at absolute pos."""
    k = t[0]
    if k == "string":
        n = int.from_bytes(data[pos:pos + 32], "big")
        return data[pos + 32:pos + 32 + n].decode("utf-8")
    if k == "bytes":  # ('bytes',) — dynamic bytes
        n = int.from_bytes(data[pos:pos + 32], "big")
        return data[pos + 32:pos + 32 + n]
    if k == "dynamic_array":
        n = int.from_bytes(data[pos:pos + 32], "big")
        vals = []
        p = pos + 32
        for _ in range(n):
            v, p = _dec_one(t[1], data, p, pos + 32)
            vals.append(v)
        return vals
    elems = t[1] if k == "tuple" else [t[1]] * t[2]
    vals = []
    p = pos
    for e in elems:
        v, p = _dec_one(e, data, p, pos)
        vals.append(v)
    return tuple(vals) if k == "tuple" else vals


def decode(types, data):
    """Decode calldata (without selector) back into Python values."""
    types = [parse_type(t) for t in types]
    vals = []
    pos = 0
    for t in types:
        v, pos = _dec_one(t, data, pos, 0)
        vals.append(v)
    return vals


if __name__ == "__main__":
    # Sanity checks against the canonical examples from the Solidity docs.
    assert selector("baz(uint32,bool)") == "cdcd77c0"
    assert selector("bar(bytes3[2])") == "fce353f6"
    assert selector("transfer(address,uint256)") == "a9059cbb"

    call = encode_call("baz(uint32,bool)", [69, True])
    assert call.hex() == (
        "cdcd77c0"
        "0000000000000000000000000000000000000000000000000000000000000045"
        "0000000000000000000000000000000000000000000000000000000000000001"
    ), call.hex()

    # round-trips incl. nested dynamic types
    cases = [
        (["uint256"], [2**256 - 1]),
        (["int8"], [-128]),
        (["address"], ["0x" + "ab" * 20]),
        (["bool", "bool"], [True, False]),
        (["bytes3[2]"], [[b"abc", b"def"]]),
        (["string"], ["Hello, world! \xe2\x9c\xa8"]),
        (["bytes"], [b"\xde\xad\xbe\xef" * 40]),
        (["uint32[]"], [[0x456, 0x789, 0]]),
        (["uint256", "uint32[]", "bytes10", "bytes"],
         [0x123, [0x456, 0x789], b"1234567890", b"Hello, world!"]),
        (["(uint256,string)[]"],
         [[(1, "one"), (2, "two"), (3, "three")]]),
        (["(address,(uint256,bool))"],
         [("0x" + "11" * 20, (42, True))]),
    ]
    for types, vals in cases:
        blob = encode(types, vals)
        back = decode(types, blob)
        assert back == vals, (types, vals, back)
        assert encode(types, back) == blob, (types, vals)
    print("all checks passed")
