# eth-abi-lite

A tiny, zero-dependency Ethereum ABI encoder/decoder in pure Python — a single
file (`abi_codec.py`) with no imports beyond `re`.

What it does:

- **Encode / decode** all ABI types using the head/tail scheme from the
  Solidity ABI spec: `uint<N>`, `int<N>`, `address`, `bool`, `bytes<M>`,
  `function`, `string`, `bytes`, static arrays `T[k]`, dynamic arrays `T[]`,
  and tuples `(T1,T2,...,Tn)` — including nesting (e.g. `(uint256,string)[]`).
- **Function selectors**: first 4 bytes of the Keccak-256 of the canonical
  signature, so `encode_call("baz(uint32,bool)", [69, True])` produces the
  exact calldata from the Solidity docs
  (`cdcd77c0…0045…0001`).
- **Self-contained Keccak-256**: the pre-NIST variant Ethereum uses
  (not `hashlib.sha3_256`, which differs).

Run `python3 example.py` for a demo, `python3 abi_codec.py` for the built-in
sanity checks (they assert the canonical doc examples and a batch of
encode→decode→encode round-trips).

```python
from abi_codec import encode_call, decode, selector

selector("transfer(address,uint256)")          # 'a9059cbb'
call = encode_call("baz(uint32,bool)", [69, True])
decode(["uint32", "bool"], call[4:])          # [69, True]
```
