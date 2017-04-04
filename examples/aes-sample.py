# make sure u  : pip install pyCrypto
import base64
from Crypto.Cipher import AES
from Crypto import Random


BLOCK_SIZE=16

class AESCipher:
    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw ):
        
        iv = Random.new().read( BLOCK_SIZE )
        print len(iv)
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        ret=cipher.encrypt( raw )
        return base64.b64encode( iv + ret ) 

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return cipher.decrypt( enc[16:] )



ttt=AESCipher("1231231230123123")  # key  must be  at BLOCK_SIZE

enc=ttt.encrypt("1123456789012345")  #enc value  must be  at BLOCK_SIZE

print enc

print ttt.decrypt(enc)   //dec 

