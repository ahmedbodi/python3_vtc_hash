import vtc_scrypt
from binascii import b2a_hex
from struct import pack
h = vtc_scrypt.getPoWHash(b'\x00')
print(h)
