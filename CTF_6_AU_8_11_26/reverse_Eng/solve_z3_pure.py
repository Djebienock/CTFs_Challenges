import z3

flag_chars = [z3.BitVec(f'c_{i}', 8) for i in range(24)]
s = z3.Solver()

for c in flag_chars:
    s.add(z3.And(c >= 0x20, c <= 0x7e))

target1 = 0xff51afd7ed558ccd
target2 = 0xc4ceb9fe1a85ec53

# Testons en Big-Endian (sens inverse de l'assemblage)
def build_block_be(chars):
    val = z3.BitVecVal(0, 64)
    for i, c in enumerate(chars):
        val = val | (z3.ZeroExt(56, c) << ((7 - i) * 8))
    return val

block1 = build_block_be(flag_chars[0:8])
block2 = build_block_be(flag_chars[8:16])

s.add(block1 == target1)
s.add(block2 == target2)

if s.check() == z3.sat:
    m = s.model()
    result = bytes([m[c].as_long() for c in flag_chars[:16]])
    print("\n[+] TROUVÉ EN BIG-ENDIAN !")
    print("16 premiers octets :", result.decode('latin1', errors='ignore'))
else:
    print("[-] Toujours pas. Testons d'autres permutations de blocs.")
