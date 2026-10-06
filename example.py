#!/usr/bin/env python3
"""Demo for eth_abi_lite."""

from abi_codec import encode, decode, encode_call, selector

# 1. The classic Solidity-docs example: baz(uint32,bool) with (69, true)
call = encode_call("baz(uint32,bool)", [69, True])
print("baz(uint32,bool) calldata:", call.hex())

# 2. Selector of the most famous function in DeFi
print("transfer selector:      ", selector("transfer(address,uint256)"))

# 3. Mixed static + dynamic arguments, then decode them back
types = ["uint256", "uint32[]", "bytes10", "bytes"]
values = [0x123, [0x456, 0x789], b"1234567890", b"Hello, world!"]
blob = encode(types, values)
print("mixed encoding:         ", blob.hex()[:80] + "...")
print("decoded back:           ", decode(types, blob))

# 4. Nested tuples in a dynamic array
types2 = ["(uint256,string)[]"]
values2 = [[(1, "one"), (2, "two")]]
blob2 = encode(types2, values2)
print("nested tuples decoded:  ", decode(types2, blob2))
