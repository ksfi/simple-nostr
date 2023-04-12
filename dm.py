import hashlib
import base64
from Crypto.Cipher import AES
from Crypto import Random
from message import *

class AESCipher:
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode())), iv

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

class DM(Message):
    def __init__(self, relay, privkey, pubkey, message, otherPubkey):
        super().__init__(relay, privkey, pubkey, message, otherPubkey)
        self.otherPubkey = self.from_npub(otherPubkey)
        print(type(self.otherPubkey))
        self.aes = AESCipher(self.otherPubkey)

    def communication(self):
        while (1):
            ipt = input("-> ")
            if ipt == 'q':
                break
            message, iv = self.aes.encrypt(ipt)
            asyncio.run(self.sendNote(message, iv))

if __name__ == "__main__":
    PRIVKEY = secrets.token_bytes(32)
    sk = secp256k1.PrivateKey(PRIVKEY)
    PUBKEY = sk.pubkey.serialize()[1:]
    RELAY = "wss://nostr.massmux.com"
    data = "oui c un dm".encode('utf-8')

#     cipher = AES.new(PUBKEY, AES.MODE_CBC)
#     ct_bytes = cipher.encrypt(pad(data, AES.block_size))
#     iv = base64.b64encode(cipher.iv).decode('utf-8')
#     ct = base64.b64encode(ct_bytes).decode('utf-8')
#     print(ct)

    pbkey = input("npub of your contact:\n")
    aes = AESCipher(PUBKEY)
    dm = DM(RELAY, PRIVKEY, PUBKEY, '', pbkey)
    dm.communication()

