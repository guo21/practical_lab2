from Crypto.PublicKey import RSA


class JMessageClient:
    def __init__(self):
        # generate private key
        self.secret_key = RSA.generate(1024)
        # generate public key
        self.pub_key = self.secret_key.publickey()
        f = open("test.pem", 'w')
        f.write(self.secret_key.exportKey())
        print self.pub_key.exportKey()
        f.close()

j = JMessageClient()