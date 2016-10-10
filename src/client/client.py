from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Random import random
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import AES
from Crypto.Util import Counter
from pyasn1.type import univ
from pyasn1.codec.der import encoder
import base64
import sys
import chilkat
import urllib2
import json
import binascii

class JMessageClient:
    RSA_secret_key = None
    RSA_pub_key = ''
    DSA_secret_key = None
    DSA_pub_key = ''
    trans_message = None
    userid = 'yguo'
    dsa = None
    pk_rsa = None
    pk_dsa = None

    def __init__(self):
        # init dsa
        self.dsa = chilkat.CkDsa()
        success = self.dsa.UnlockComponent("Anything for 30-day trial")
        if (success != True):
            print(dsa.lastErrorText())
            sys.exit()

        # init pk_dsa
        self.pk_dsa = chilkat.CkDsa()
        success = self.pk_dsa.UnlockComponent("Anything for 30-day trial")
        if (success != True):
            print(dsa.lastErrorText())
            sys.exit()

        self.key_generation()
        self.concatenation_for_trans()
        # self.enum_users()
        # self.key_lookup('xhyu2')
        # self.key_registration()

    def key_generation(self, rsa_key_len=1024, dsa_key_len=1024):
        self.__rsa_key_gen(rsa_key_len)
        self.__dsa_key_gen(dsa_key_len)

    def __rsa_key_gen(self, key_len):
        # generate RSA key pair
        # generate RSA secret key
        self.RSA_secret_key = RSA.generate(key_len)
        # generate RSA public key

        self.RSA_pub_key = self.RSA_secret_key.publickey().exportKey('DER')
        # print len(self.RSA_pub_key), "DER"
        self.RSA_pub_key = base64.b64encode(self.RSA_pub_key)
        # print self.RSA_pub_key, "base64"

    def __dsa_key_gen(self, key_len):
        # generate DSA key pair
        # generate DSA secret key
        success = self.dsa.UnlockComponent("Anything for 30-day trial")
        if (success != True):
            print(self.dsa.lastErrorText())
            sys.exit()

        success = self.dsa.GenKey(key_len)
        if (success != True):
            print(self.dsa.lastErrorText())
            sys.exit()

        # self.DSA_secret_key = dsa.toPem()
        # print self.DSA_secret_key
        self.DSA_pub_key = chilkat.CkByteData()
        self.dsa.ToPublicDer(self.DSA_pub_key)
        self.DSA_pub_key = base64.b64encode(self.DSA_pub_key.getBytes())
        # print len(self.DSA_pub_key)

    def key_registration(self):

        regi_url = 'http://jmessage.server.isi.jhu.edu/registerKey/' + self.userid
        data = {'KeyData': self.trans_message}
        key = json.dumps(data)
        # print key
        request = urllib2.Request(regi_url, key)

        request.add_header('Accept', 'application/json')
        response = urllib2.urlopen(request)
        print response.read()

    def key_lookup(self, username):
        regi_url = 'http://jmessage.server.isi.jhu.edu/lookupKey/' + username
        request = urllib2.Request(regi_url)
        response = urllib2.urlopen(request)
        result = response.read()
        print result
        return result

    def enum_users(self):
        regi_url = 'http://jmessage.server.isi.jhu.edu/lookupUsers'
        request = urllib2.Request(regi_url)

        response = urllib2.urlopen(request)
        print response.read()

    def concatenation_for_trans(self):
        self.trans_message = self.RSA_pub_key + chr(0x25) + self.DSA_pub_key

    def encrypt(self, message='', pk_RSA = None):
        # 1generate random aes128 key
        aeskeylen = AES.block_size
        if aeskeylen!= 16:
            print "aes block size wrong"
        aeskey = "".join(chr(random.randint(0, 0xff)) for i in range(aeskeylen))
        # 2.Encrypt K using the RSA encryption with PKCS 1v1.5
        pk_RSA = RSA.importKey(base64.decodestring(self.RSA_pub_key),'DER')
        signer = PKCS1_v1_5.new(pk_RSA)
        C1 = signer.encrypt(aeskey)
        # C1 = PKCS1_v1_5.new(self.RSA_secret_key.encrypt(aeskey, pk_RSA))
        # 3.Prepend sender userid||ASCII(0x3A) to the message M to obtain Mformatted.
        m_formatted = self.userid + chr(0x3A) + message
        # 4.Compute a CRC32 on the message Mformatted, and append the 4-byte CRC value (in networkbyte order)
        # to the end of Mformatted to create MCRC

        m_crc = m_formatted + self.__crc32(m_formatted)
        # 5.Pad the length of the message MCRC to a multiple of 16 bytes using PKCS5 padding to create Mpadded.
        m_padded = self.__pkcs5(m_crc)

        # 6.Generate a random 16-byte initialization vector IV using a secure random number generator.
        iv = "".join(chr(random.randint(0, 0xff)) for i in range(aeskeylen))

        # 7.Encrypt Mpadded using AES in CTR mode under K and IV . Prepend IV to the resulting
        # ciphertext to obtain C2
        ctr = Counter.new(128, initial_value=long(iv.encode("hex"), aeskeylen))
        cipher = AES.new(aeskey, AES.MODE_CTR, iv, ctr)
        C2 = iv + cipher.encrypt(m_padded)

        #  8.Separately Base64 encode each of C1 and C2 to obtain C1Base64 and C2Base64 (respectively) in UTF8 format.
        C1_base64 = base64.b64encode(C1)
        C1_base64 = C1_base64.encode(encoding='UTF-8', errors='strict')

        C2_base64 = base64.b64encode(C2)
        C2_base64 = C2_base64.encode(encoding='UTF-8', errors='strict')

        # 9.Compute a DSA signature sigma on the UTF8 encoded string C2Base64 ||ASCII(0x20)||C2 Base64
        # 10.Set sigma_b64 to be the Base64 encoding of sigma (in UTF8 encoding).
        sig_str = (C1_base64 + chr(0x20) + C2_base64).encode(encoding='UTF-8', errors='strict')
        sigma_base64 = self.__compute_dsa_sig(sig_str)

        # 11.Output the string C = C1Base64 ||ASCII(0x20)||C2Base64||ASCII(0x20)||sigma_Base64

        C = sig_str + chr(0x20) + sigma_base64
        return C

    def __compute_dsa_sig(self, sig_str):
        crypt = chilkat.CkCrypt2()
        success = crypt.UnlockComponent("Anything for 30-day trial.")
        if (success != True):
            print(crypt.lastErrorText())
            sys.exit()

        crypt.put_EncodingMode("hex")
        crypt.put_HashAlgorithm("sha-1")

        hashStr = crypt.hashStringENC(sig_str)
        success = self.dsa.SetEncodedHash("hex", hashStr)
        if (success != True):
            print(self.dsa.lastErrorText())
            sys.exit()

        # Now that the DSA object contains both the private key and hash,
        #  it is ready to create the signature:
        success = self.dsa.SignHash()
        if (success != True):
            print(self.dsa.lastErrorText())
            sys.exit()

        # If SignHash is successful, the DSA object contains the
        #  signature.  It may be accessed as a hex or base64 encoded
        #  string.  (It is also possible to access directly in byte array form via
        #  the "Signature" property.)
        hexSig = base64.b64encode(self.dsa.getEncodedSignature("hex").encode(encoding='UTF-8', errors='strict'))

        print("Signature:")
        print(hexSig)
        return hexSig

    def __crc32(self, v):
        """
        Generates the crc32 hash of the v.
        @return: str, the str value for the crc32 of the v
        """
        return '0x%x' % (binascii.crc32(v) & 0xffffffff)

    def __pkcs5(self, msg):
        '''get pkcs5'''
        padding = ''
        n = (len(msg)) % 16  # |M| mod 16
        if n != 0:
            for i in range(n, 16):
                padding += chr(16 - n)

        else:
            for i in range(0, 16):
                padding += chr(16)

        return padding

    def decrypt(self, cipher_text = '', username=''):
        # 1.Contact the server to obtain the public key pk DSA for the sender.
        pk_str = (json.loads(self.key_lookup(username)))['keyData']  # json.loads->unicode watch out
        pk_dsa_str = chilkat.CkByteData()
        pk_dsa_str = base64.b64decode(self.__split_rsa_dsa(pk_str, 'dsa'))
        success = self.pk_dsa.FromDer(pk_dsa_str)
        if (success != True):
            print(dsa.lastErrorText())
            sys.exit()

        # 2.Parse the the string C as C1base64||ASCII(0x20)||C2base64||ASCII(0x20)||sigma Base64 .
        c = cipher_text.split(chr(0x20))
        c1_base64 = c[0]
        c2_base64 = c[1]
        sigma_base64 = c[2]
        # 3.Base64 decode each of C1base64,C2base64,sigmabase64 individually to obtain the values C1, C2, sigma.
        c1 = base64.b64decode(c1_base64)
        c2 = base64.b64decode(c2_base64)
        sigma = base64.b64decode(sigma_base64)

        # 4. Verify the DSA signature sigma using pkDSA on the message C1 Base64||ASCII(0x20)||C2 Base64.
        # If verification fails, abort.
        hash_str = c1_base64 + chr(0x20) +c2_base64
        self.__dsa_verify(hash_str, self.pk_dsa, sigma)



    def __split_rsa_dsa(self, pk, key_type="rsa"):
        pk_str = pk.split('%')
        if key_type == "rsa":
            return pk_str[0]
        elif key_type == "dsa":
            return pk_str[1]
        else:
            print 'split error'

    def __dsa_verify(self, hash_str, dsa, sigma):

        # Load the hash to be verified against the signature.
        success = dsa.SetEncodedHash("hex", hash_str)
        if (success != True):
            print(dsa2.lastErrorText())
            sys.exit()

        # Load the signature:
        success = dsa.SetEncodedSignature("hex", sigma)
        if (success != True):
            print(dsa.lastErrorText())
            sys.exit()

        # Verify:
        success = dsa.Verify()
        if (success != True):
            print(dsa2.lastErrorText())
        else:
            print("DSA Signature Verified!")




j = JMessageClient()
j.decrypt('','xhyu2')
# j.encrypt()
