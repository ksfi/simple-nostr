import hashlib
import asyncio
import datetime
import time
import websockets
import json
import struct
import binascii
import secp256k1
import bech32
import secrets
import sys

# message = note
class Message:
    def __init__(self, privkey, pubkey, message, relay):
        if privkey[:4] == "nsec" and pubkey[:4] == "npub":
            self.keytype = "nsec"
            self.privkey = privkey
            self.pubkey = pubkey
        elif type(privkey) is bytes and type(pubkey) is bytes:
            self.keytype = "bytes"
            self.privkey = privkey
            self.pubkey = pubkey
        elif type(privkey) is str and type(pubkey) is str:
            self.keytype = "hex"
            self.privkey = privkey
            self.pubkey= pubkey
        else:
            raise TypeError("keys types must be consistent")
        self.message = message
        self.relay = relay

    def from_npub(self):
        hrp, data, spec = bech32.bech32_decode(self.pubkey)
        raw_secret = bech32.convertbits(data, 5, 8)[:-1]
        return bytes(raw_secret)

    def from_nsec(self):

        hrp, data, spec = bech32.bech32_decode(selfg.privkey)
        raw_secret = bech32.convertbits(data, 5, 8)[:-1]
        return bytes(raw_secret)

    def sign_message_hash(self, hash):
        if self.keytype == "nsec":
            privk = from_nsec(self.privkey)
        elif self.keytype == "bytes":
            privk = self.privkey.hex()
        else:
            privk = self.privkey
#         raw_secret = self.from_npub()
        sk = secp256k1.PrivateKey(bytes.fromhex(privk))
        sig = sk.schnorr_sign(hash, None, raw=True)
        return sig.hex()

    def get_id(self):
        if self.keytype == "nsec":
            privk = from_nsec(self.privkey).hex()
            pubk = from_npub(self.pubkey).hex()
        elif self.keytype == "bytes":
            privk = self.privkey.hex()
            pubk = self.pubkey.hex()
        else:
            pubk = self.privkey
            pubk = self.pubkey
        event = [
          0,
          pubk,
          int(time.time()),
          1,
          [],
          self.message
        ]
        event_json = json.dumps(event, separators=(',', ':'), ensure_ascii=False)
        event_hash = hashlib.sha256(event_json.encode('utf-8')).digest()
        return event_hash

    def to_json(self):
        if self.keytype == "nsec":
            privk = from_nsec(self.privkey).hex()
            pubk = from_npub(self.pubkey).hex()
        elif self.keytype == "bytes":
            privk = self.privkey.hex()
            pubk = self.pubkey.hex()
        else:
            pubk = self.privkey
            pubk = self.pubkey
        ret = {
          "id": self.get_id().hex(),
          "pubkey": pubk,
          "created_at": int(time.time()),
          "kind": 1,
          "tags": [],
          "content": self.message,
          "sig": self.sign_message_hash(self.get_id())
        }
        return ret

    async def sendNote(self):
        note = json.dumps(["EVENT", self.to_json()], separators=(',', ':'), ensure_ascii=False)
        async with websockets.connect(self.relay) as websocket:
            await websocket.send(note)
            await websocket.recv()

if __name__ == "__main__":
    RELAY = "wss://relay.damus.io"
    if len(sys.argv) == 2:
        print("ici")
        PRIVKEY = secrets.token_bytes(32)
        sk = secp256k1.PrivateKey(PRIVKEY)
        PUBKEY = sk.pubkey.serialize()[1:]
    if len(sys.argv) == 4:
        PRIVKEY = sys.argv[2]
        PUBKEY = sys.argv[3]
        DAMUS_R = "wss://relay.damus.io"
    if len(sys.argv) == 1 or len(sys.argv) > 4:
        raise ValueError("python3 message.py [msg] or python3 message.py [msg] [privkey] [pubkey]")

    m = Message(PRIVKEY, PUBKEY, sys.argv[1], RELAY)
    asyncio.run(m.sendNote())
