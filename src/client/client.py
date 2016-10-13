from Crypto.Hash import SHA, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import random
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import AES
from Crypto.Util import Counter
from pyasn1.type import univ
from pyasn1.codec.der import encoder
import requests
import base64
import sys
import chilkat
import urllib2
import json
import binascii
import time

class JMessageCrypto:
    RSA_pub_key = ''
    DSA_secret_key = None
    DSA_pub_key = ''
    trans_message = None
    userid = ''
    read_receipt_msg_form = '>>>READMESSAGE'
    rsa = None
    dsa = None
    pk_rsa = None
    pk_dsa = None

    def __init__(self, userid='yguo'):
        # init dsa
        self.userid = userid
        self.dsa = chilkat.CkDsa()
        success = self.dsa.UnlockComponent("Anything for 30-day trial")
        if (success != True):
            print(self.dsa.lastErrorText())
            sys.exit()

        # init pk_dsa
        # self.pk_dsa = chilkat.CkDsa()
        # success = self.pk_dsa.UnlockComponent("Anything for 30-day trial")
        # if (success != True):
        #     print(self.pk_dsa.lastErrorText())
        #     # sys.exit()
        # self.key_regen()
        self.key_generation()
        self.__concatenation_for_trans()
        # self.enum_users()
        # print json.loads(self.key_lookup('ytest'))['keyData'], 'test'
        self.key_registration()

    def key_generation(self, rsa_key_len=1024, dsa_key_len=1024):
        self.__rsa_key_gen(rsa_key_len)
        self.__dsa_key_gen(dsa_key_len)

    def __rsa_key_gen(self, key_len):
        # generate RSA key pair
        # generate RSA secret key
        self.rsa = RSA.generate(key_len)
        # generate RSA public key

        self.RSA_pub_key = self.rsa.publickey().exportKey('DER')
        # print len(self.RSA_pub_key), "DER"
        self.RSA_pub_key = base64.b64encode(self.RSA_pub_key)
        # print self.RSA_pub_key, "base64"

    def __dsa_key_gen(self, key_len):
        # generate DSA key pair
        # generate DSA secret key
        # success = self.dsa.UnlockComponent("Anything for 30-day trial")
        # if (success != True):
        #     print(self.dsa.lastErrorText())
        #     sys.exit()

        success = self.dsa.GenKey(key_len)
        if (success != True):
            print(self.dsa.lastErrorText())
            sys.exit()

        # self.DSA_secret_key = dsa.toPem()
        # print self.DSA_secret_key
        dsa_pub = chilkat.CkByteData()
        self.dsa.ToPublicDer(dsa_pub)
        dsa_pub = base64.b64encode(dsa_pub.getBytes())
        self.DSA_pub_key = dsa_pub
        # print len(self.DSA_pub_key)

    def key_regen(self, rsa_bits=1024, dsa_bits=1024):
        self.rsa = RSA.generate(rsa_bits)
        # self.pk_rsa = self.rsa_key.publickey().exportKey("PEM")
        # self.sk_rsa = self.rsa_key.exportKey("PEM")

        self.dsa.GenKey(dsa_bits)
        # self.dsa_key = DSA.generate(dsa_bits)
        # self.pk_dsa = self.dsa_key.key.y
        # self.sk_dsa = self.dsa_key.key.x
        self.rsa_pk_der = self.rsa.publickey().exportKey('DER')
        dsa_pk = chilkat.CkByteData()
        self.dsa.ToPublicDer(dsa_pk)
        dsa_pk = dsa_pk.getBytes()
        # self.dsa_pk = self.dsa_key.publickey().y
        # rsa_asn1 = self.__encode_asn1der(self.rsa_pk)
        rsa_asn1 = self.rsa_pk_der
        # dsa_asn1 = self.__encode_asn1der(self.dsa_pk)
        rsa_base64 = base64.b64encode(rsa_asn1)
        dsa_base64 = base64.b64encode(dsa_pk)
        self.RSA_pub_key = rsa_base64
        self.DSA_pub_key = dsa_base64

        # print rsa_base64 + chr(0x25) + dsa_base64
        return rsa_base64 + chr(0x25) + dsa_base64
        # return ((pk_rsa, sk_rsa), (pk_dsa, sk_dsa))

    def key_registration(self):

        regi_url = 'http://jmessage.server.isi.jhu.edu/registerKey/' + self.userid
        data = {'keyData': self.__concatenation_for_trans()}
        # print self.__concatenation_for_trans()
        # print self.trans_message
        # key = json.dumps(data)
        header = {'Accept': 'application/json'}
        s = requests.Session()
        r = s.post(regi_url, headers=header, json=data)
        result = json.loads(r.text)['result']
        # print result
        if result == 'True':
            return result
        else:
            print 'register failed, you can use offline mode'
        # key = key.encode('utf-8')
        # print key
        # request = urllib2.Request(regi_url)
        # request.add_header('Accept', 'application/json')
        # request.add_data(key)
        # response = urllib2.urlopen(request)
        # print response.read()

    def key_lookup(self, username):
        regi_url = 'http://jmessage.server.isi.jhu.edu/lookupKey/' + username
        request = urllib2.Request(regi_url)
        request.add_header('Accept', 'application/json')
        response = urllib2.urlopen(request)
        result = response.read()
        # print result
        return result

    def key_fingerprints(self, username):
        key = self.key_lookup(username)
        tem = json.loads(key)
        if tem['keyData'] =='':
            print '''Did not receive a key from the server
Could not find a key for user ''', username
            return 'fail'
        key = key.encode('utf-8')
        h = SHA256.new()
        h.update(key)
        hashed = h.hexdigest()
        # print len(hashed)
        return hashed


    def enum_users(self):
        regi_url = 'http://jmessage.server.isi.jhu.edu/lookupUsers'
        request = urllib2.Request(regi_url)
        request.add_header('Accept', 'application/json')
        response = urllib2.urlopen(request)
        return response.read()

    def obtain_msg(self):
        regi_url = 'http://jmessage.server.isi.jhu.edu/getMessages/' + self.userid
        # regi_url = 'http://jmessage.server.isi.jhu.edu/getMessages/xhyu2'
        request = urllib2.Request(regi_url)
        request.add_header('Accept', 'application/json')
        response = urllib2.urlopen(request)
        return response.read()

    def __concatenation_for_trans(self):
        self.trans_message = self.RSA_pub_key + chr(0x25) + self.DSA_pub_key
        return self.trans_message
        # self.trans_message = self.trans_message.encode('utf-8')

    def encrypt(self, message='', pk_RSA = None):
        # 1generate random aes128 key
        aeskeylen = AES.block_size
        if aeskeylen != 16:
            print "aes block size wrong"
        aeskey = "".join(chr(random.randint(0, 0xff)) for i in range(aeskeylen))

        # 2.Encrypt K using the RSA encryption with PKCS 1v1.5
        # pk_RSA = RSA.importKey(base64.decodestring(self.RSA_pub_key), 'DER')
        pk_RSA = self.rsa
        signer = PKCS1_v1_5.new(pk_RSA)
        # h = SHA.new(aeskey)
        # C1 = signer.encrypt(aeskey+h.digest())
        C1 = signer.encrypt(aeskey)
        # C1 = PKCS1_v1_5.new(self.RSA_secret_key.encrypt(aeskey, pk_RSA))

        # 3.Prepend sender userid||ASCII(0x3A) to the message M to obtain Mformatted.
        m_formatted = self.userid + chr(0x3A) + message
        # 4.Compute a CRC32 on the message Mformatted, and append the 4-byte CRC value (in networkbyte order)
        # to the end of Mformatted to create MCRC
        # print len(self.__crc32(m_formatted))
        m_crc = m_formatted + self.__crc32(m_formatted)
        print m_crc,'m_crc'
        # 5.Pad the length of the message MCRC to a multiple of 16 bytes using PKCS5 padding to create Mpadded.
        m_padded = m_crc + self.__pkcs5(m_crc)
        # print len(m_padded), 'm_padded'

        # 6.Generate a random 16-byte initialization vector IV using a secure random number generator.
        iv = "".join(chr(random.randint(0, 0xff)) for i in range(aeskeylen))
        # print iv,'fuck'

        # 7.Encrypt Mpadded using AES in CTR mode under K and IV . Prepend IV to the resulting
        # ciphertext to obtain C2
        ctr = Counter.new(128, initial_value=long(iv.encode("hex"), aeskeylen))
        cipher = AES.new(aeskey, AES.MODE_CTR, iv, ctr)
        C2 = iv + cipher.encrypt(m_padded)

        #  8.Separately Base64 encode each of C1 and C2 to obtain C1Base64 and C2Base64 (respectively) in UTF8 format.
        C1_base64 = base64.b64encode(C1)
        C1_base64 = C1_base64.encode('utf-8')

        C2_base64 = base64.b64encode(C2)
        C2_base64 = C2_base64.encode('utf-8')

        # 9.Compute a DSA signature sigma on the UTF8 encoded string C2Base64 ||ASCII(0x20)||C2 Base64
        # 10.Set sigma_b64 to be the Base64 encoding of sigma (in UTF8 encoding).
        sig_str = (C1_base64 + chr(0x20) + C2_base64).encode('utf-8')
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

        hash_str = crypt.hashStringENC(sig_str)
        success = self.dsa.SetEncodedHash("hex", hash_str)
        if success != True:
            print(self.dsa.lastErrorText())
            sys.exit()

        # Now that the DSA object contains both the private key and hash,
        #  it is ready to create the signature:
        success = self.dsa.SignHash()
        if success!=True:
            print(self.dsa.lastErrorText())
            sys.exit()

        # If SignHash is successful, the DSA object contains the
        #  signature.  It may be accessed as a hex or base64 encoded
        #  string.  (It is also possible to access directly in byte array form via
        #  the "Signature" property.)
        hex_sig = base64.b64encode(self.dsa.getEncodedSignature("hex").encode('utf-8'))

        # print("Signature:")
        # print(hex_sig)
        return hex_sig

    def __crc32(self, msg):
        """
        Generates the crc32 hash of the v.
        @return: str, the str value for the crc32 of the v
        """
        # result = '0x%x' % (binascii.crc32(v) & 0xffffffff)
        crc_int = binascii.crc32(msg)
        crc_str = "".join(chr(crc_int >> i & 0xff) for i in (24, 16, 8, 0))
        # print len(crc_str)
        return crc_str

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

    def __de_pkcs5(self,msgpp):
        # this is from assignment1 :)
        n = ord(msgpp[-1])
        # print msgpp[-1]
        # print msgpp[:-n]
        # print n
        for i in range(0, n):
            if ord(msgpp[-1 - i]) != n:
                error = 'INVALID PADDING'
                print error
                return error
        # print msgpp[-n:-1]
        msgp = msgpp[:-n]
        # print len(msgp),'tst'
        return msgp

    def decrypt(self, cipher_text='', username=''):
        # 1.Contact the server to obtain the public key pkDSA for the sender.
        pk_str = self.key_lookup(username)  # json.loads->unicode watch out
        self.pk_rsa, self.pk_dsa = self.split_and_init_rsa_dsa(pk_str)
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
        hash_str = c1_base64 + chr(0x20) + c2_base64
        self.__dsa_verify(hash_str, self.pk_dsa, sigma)

        # 5.Decrypt the RSA ciphertext C1 using the recipient's secret key sk RSA to obtain K\
        pk_rsa = self.rsa
        # print aeskey,'shit'
        dsize = SHA.digest_size
        sentinel = Random.new().read(15 + dsize)  # Let's assume that average data length is 15
        cipher = PKCS1_v1_5.new(pk_rsa)
        aeskey = cipher.decrypt(c1, sentinel)
        # print aeskey

        # 6.Parse C2 to obtain the prepended IV . Decrypt C 2 using AES in CTR mode to obtain M padded.
        aeskey_len = AES.block_size
        if aeskey_len != 16:
            print "aes block size wrong"

        iv = c2[:aeskey_len]
        # print iv
        encrypted_m_padded = c2[aeskey_len:]
        ctr = Counter.new(128, initial_value=long(iv.encode("hex"), aeskey_len))
        cipher = AES.new(aeskey, AES.MODE_CTR, iv, ctr)
        m_padded = cipher.decrypt(encrypted_m_padded)
        # print len(m_padded)
        # 7.Verify and remove the PKCS5 padding to obtain M CRC . Abort if the padding is incorrectly structured.
        m_crc = self.__de_pkcs5(m_padded)
        if m_crc == 'INVALID PADDING':
            print "abort"
            return
        # print m_crc

        # 8.Parse M CRC as M formatted ||CRC, where CRC is 4 bytes long. Compute a CRC32 on themessage M ,
        # and compare to CRC. Abort if the comparison fails.
        crc = m_crc[-4:]
        # print len(crc)
        m_formatted = m_crc[:-4]
        test_crc = self.__crc32(m_formatted)
        if crc != test_crc:
            print 'abort'
            return

        # 9.Parse M formatted as sender userid||ASCII(0x3A)||M. Verify that sender userid is the correct userID for S.
        #  Abort if the username does not match.
        print m_formatted
        m_form_split = m_formatted.split(chr(0x3A))
        user_id = m_form_split[0]
        plain_text = m_form_split[1]
        if user_id != username:
            print 'abort'
            return

        msg_test = plain_text.split()
        if msg_test[0] == self.read_receipt_msg_form:
            return self.read_receipt_msg_form

        return plain_text

    def split_and_init_rsa_dsa(self, pk):
        pk_tem = json.loads(pk)['keyData']  # json.loads->unicode watch out
        pk_tem = pk_tem.encode('utf-8')
        pk_str = pk.split(chr(0x25))
        # This method taught by Miracle
        rsa_pk_der = base64.b64decode(pk_str[0])
        rsa_obj = RSA.importKey(rsa_pk_der)

        pk_dsa_der = pk_str[1]
        publicKey = chilkat.CkPublicKey()

        success = publicKey.LoadFromString(pk_dsa_der)
        if not success:
            print 'dsa pk load failed'
            sys.exit(2)
        tmp_dsa_der = chilkat.CkByteData()
        publicKey.GetDer(True, tmp_dsa_der)
        dsa_obj = chilkat.CkDsa()
        success = dsa_obj.UnlockComponent("Anything for 30-day trial")
        if not success:
            print dsa_obj.lastErrorText()
            sys.exit()
        dsa_obj.FromPublicDer(tmp_dsa_der)

        return rsa_obj, dsa_obj

    def __dsa_verify(self, hash_str, dsa, sigma):
        dsa = self.dsa
        crypt = chilkat.CkCrypt2()
        success = crypt.UnlockComponent("Anything for 30-day trial.")
        if not success:
            print crypt.lastErrorText()
            return False
        crypt.put_EncodingMode("hex")
        crypt.put_HashAlgorithm("sha-1")
        hash_str = crypt.hashStringENC(hash_str)
        # Load the hash to be verified against the signature.
        success = dsa.SetEncodedHash("hex", hash_str)
        if (success != True):
            print(dsa.lastErrorText())
            sys.exit()

        # Load the signature:
        success = dsa.SetEncodedSignature("hex", sigma)
        if (success != True):
            print(dsa.lastErrorText())
            sys.exit()
        # Verify:
        success = dsa.Verify()
        if (success != True):
            print(dsa.lastErrorText())
        else:
            print("DSA Signature Verified!")

class JMessageClient:
    __j_msg_crypto = None

    def __init__(self):
        userid = raw_input('Please input your user id:')
        self.__j_msg_crypto = JMessageCrypto(userid)
        # print userid

    def run_client(self):
        while True:
            instruction = raw_input('Type (h)elp for commands.')
            if instruction == 'h' or instruction == 'help':
                print self.__get_help()
            elif instruction == 'get' or instruction == '':
                print self.__obtain_msg()
            elif instruction == 'c' or instruction == 'compose':
                self.__send_message()
            elif instruction == 'f' or instruction == 'fingerprint':
                self.__get_user_fingerprint()
            elif instruction == 'l' or instruction == 'list':
                self.__list_all_user()
            elif instruction == 'q' or instruction == 'quit':
                print 'have a good day! :)'
                break
            else:
                continue

    def __register_key(self):
        self.__j_msg_crypto.key_registration()

    def __obtain_msg(self):
        json_msg = self.__j_msg_crypto.obtain_msg()
        msg = json.loads(json_msg)
        msg_num = msg['numMessages']
        if msg_num == 0:
            print 'No new messages'
            return
        for m in msg['messages']:
            sent_ime = m['sentTime']
            message_id = m['messageID']
            message = m['message']
            sender_id = m['senderID']
            keydata = self.__j_msg_crypto.key_lookup(sender_id)
            if keydata == 'fail':
                return

            message = self.__j_msg_crypto.decrypt(message, sender_id)
            print 'Message ID:', message_id
            print 'From user:', sender_id
            print 'Sent time:', self.__adjust_time_form(sent_ime)
            print 'Content:', message

    def __send_message(self):
        pass

    def __get_user_fingerprint(self):
        user_id = raw_input("Please input user id you want:")
        result = self.__j_msg_crypto.key_fingerprints(user_id)
        if result == 'fail':
            return
        print user_id,"'s fingerprint is:",result


    def __list_all_user(self):
        json_list = self.__j_msg_crypto.enum_users()
        list = json.loads(json_list)
        user_list = list['users']
        print 'There are', list['numUsers'], 'users at all. They are'
        for i in range(len(user_list)):
            print i, ":", user_list[i]

    def __get_help(self):
        help_content = help_content = '''
Available commands:
   get (or empty line)  - check for new messages
   c(ompose)            - compose a message to <user>
   f(ingerprint)        - return the key fingerprint of <user>
   l(ist)               - lists all the users in the system
   h(elp)               - prints this listing
   q(uit)               - exits
        '''
        return help_content

    def __adjust_time_form(self, oldtime):
        x = oldtime.localtime(time)
        return time.strftime("%a %b %d %H:%M:%S %Z %Y", x)


j = JMessageClient()
j.run_client()
# j = JMessageCrypto()
# j.key_fingerprints('xhyu2')
# j.decrypt(j.encrypt("ss"), 'xhyu2')
# j.encrypt()
