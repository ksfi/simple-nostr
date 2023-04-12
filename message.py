import hashlib
import asyncio
import time
import websockets
import json
import secp256k1
import bech32
import secrets
import os
import base64

# message = note
class Message:
    def __init__(self, relay, privkey, pubkey, message, otherPubkey=None):
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

    def from_npub(self, other=None):
        if other is not None:
            hrp, data, spec = bech32.bech32_decode(other)
            raw_secret = bech32.convertbits(data, 5, 8)[:-1]
        else:
            hrp, data, spec = bech32.bech32_decode(self.pubkey)
            raw_secret = bech32.convertbits(data, 5, 8)[:-1]
        return bytes(raw_secret)

    def from_nsec(self):
        hrp, data, spec = bech32.bech32_decode(self.privkey)
        raw_secret = bech32.convertbits(data, 5, 8)[:-1]
        return bytes(raw_secret)

    def sign_message_hash(self, hash):
        if self.keytype == "nsec":
            privk = self.from_nsec()
        elif self.keytype == "bytes":
            privk = self.privkey.hex()
        else:
            privk = self.privkey
        if type(self.privkey) != str:
            sk = secp256k1.PrivateKey(bytes.fromhex(privk))
        else:
            sk = secp256k1.PrivateKey(bytes.fromhex(str(privk.hex())))
        sig = sk.schnorr_sign(hash, None, raw=True)
        return sig.hex()

    def get_id(self, dm_message, iv):
        if self.keytype == "nsec":
            privk = self.from_nsec().hex()
            pubk = self.from_npub().hex()
        elif self.keytype == "bytes":
            privk = self.privkey.hex()
            pubk = self.pubkey.hex()
        else:
            privk = self.privkey
            pubk = self.pubkey
        if dm_message is not None:
            kind = 4
            tags = [["p", str(self.otherPubkey.hex())]]
            content = str(base64.b64encode(self.message).decode('utf-8')) + "?iv=" + str(base64.b64encode(iv).decode('utf-8'))
        else:
            kind = 1
            tags = []
            content = self.message
        print("content:", content)
        event = [
          0,
          pubk,
          int(time.time()),
          kind,
          tags,
          content
        ]
        event_json = json.dumps(event, separators=(',', ':'), ensure_ascii=False)
        event_hash = hashlib.sha256(event_json.encode('utf-8')).digest()
        return event_hash

    def to_json(self, dm_message, iv):
        if self.keytype == "nsec":
            privk = self.from_nsec().hex()
            pubk = self.from_npub().hex()
        elif self.keytype == "bytes":
            privk = self.privkey.hex()
            pubk = self.pubkey.hex()
        else:
            privk = self.privkey
            pubk = self.pubkey
        if dm_message is not None:
            kind = 4
            self.message = dm_message
            tags = [["p", str(self.otherPubkey.hex())]]
            content = str(base64.b64encode(self.message).decode('utf-8')) + "?iv=" + str(base64.b64encode(iv).decode('utf-8'))
        else:
            content = self.message
            kind = 1
            tags = []
        print(self.message)
        print(base64.b64encode(self.message).decode('utf-8'))
        ret = {
          "id": self.get_id(dm_message, iv).hex(),
          "pubkey": pubk,
          "created_at": int(time.time()),
          "kind": kind,
          "tags": tags,
          "content": content,
          "sig": self.sign_message_hash(self.get_id(dm_message, iv))
        }
        return ret

    async def sendNote(self, dm_message=None, iv=None):
        note = json.dumps(["EVENT", self.to_json(dm_message, iv)], separators=(',', ':'), ensure_ascii=False)
        async with websockets.connect(self.relay) as websocket:
            await websocket.send(note)
            r = await websocket.recv()
            print(r)

    async def receive(self):
        k = 0
        sub = os.urandom(6).hex()
        filters = {"kinds": [1], "limit": 5}
        note = json.dumps(["REQ", sub, filters], separators=(',', ':'), ensure_ascii=False)
        async with websockets.connect(self.relay) as ws:
            while (k <= 4):
                await ws.send(note)
                m = await ws.recv()
                m = json.loads(m)
                tags_p = [x[1] for x in m[2]["tags"] if x[0] == 'p']
                tags_e = [x[1] for x in m[2]["tags"] if x[0] == 'e']
                print(f"\n-> by {m[2]['id']} at {time.strftime('%H:%M:%S', time.gmtime(m[2]['created_at']))}\n-> {m[2]['content']}")
                if len(tags_p):
                    print(f"-> to {tags_p}")
                    print(f"-> to {tags_e}")
                print("------------\n------------")
                k += 1
def key(ipt):
    if len(ipt) == 1:
        PRIVKEY = secrets.token_bytes(32)
        sk = secp256k1.PrivateKey(PRIVKEY)
        PUBKEY = sk.pubkey.serialize()[1:]
    elif len(ipt) == 3:
        PRIVKEY = ipt[1]
        PUBKEY = ipt[2]
    elif len(ipt) == 0 or len(ipt) > 4:
        raise ValueError("python3 message.py [msg] or python3 message.py [msg] [privkey] [pubkey]")
    return PRIVKEY, PUBKEY

def run():
    RELAY = input("ENTER A RELAY: (default: wss://relay.damus.io)\n")
    if len(RELAY) == 0:
        RELAY = "wss://relay.damus.io"
    print(RELAY)

    while (1):
        ipt = input("[msg] OR [msg] // [privkey] // [pubkey] OR q to quit OR enter to watch:\n").split(" // ")
        if ipt[0].lower() == 'q':
            print("END")
            break
        PRIVKEY, PUBKEY = key(ipt)

        if ipt[0].lower() == '':
            m = Message(RELAY, PRIVKEY, PUBKEY, ipt[0])
            asyncio.run(m.receive())
        elif len(ipt[0]) > 0:
            m = Message(RELAY, PRIVKEY, PUBKEY, ipt[0])
            asyncio.run(m.sendNote())

if __name__ == "__main__":
    run()
