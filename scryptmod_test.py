import vtc_scrypt
from binascii import b2a_hex
from struct import pack
buf = "a"*68 + pack("<I", 1390849577) + "b"*8
h = vtc_scrypt.getPoWHash(buf)
hhex = b2a_hex(h)
if hhex == 'e537e2504a5c5a4ac654281175555b504a50db5490d1a5fe2d0d16f10a8f5935':
    print "Scrypt module is working properly!"
else:
    print "Scrypt module is not working properly! Hash was: %s," % hhex
    print "but should have been %s" % 'e537e2504a5c5a4ac654281175555b504a50db5490d1a5fe2d0d16f10a8f5935'
