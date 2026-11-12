# Valeurs assemblées en little endian depuis le movabs :
# 0x0ff51af7ed558ccd -> inversé en little endian
b1 = (0xff51af7ed558ccd).to_bytes(8, 'little')
b2 = (0xc4ceb9e1a85ec53).to_bytes(8, 'little')
b3 = (0x21).to_bytes(1, 'little') # selon l'offset

full_bytes = b1 + b2
print(full_bytes)
