import subprocess, sys, struct, time, os
from noise.connection import NoiseConnection, Keypair
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser
raw = lambda k: k.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
kotlin_role = sys.argv[1]; cp = sys.argv[2]
py_initiator = kotlin_role == "responder"
sid = bytes.fromhex("00112233445566778899aabbccddeeff")
idk = Ed25519PrivateKey.generate(); idpub = raw(idk.public_key())
stk = X25519PrivateKey.generate(); stpub = raw(stk.public_key())
now = int(time.time()*1000); nb, na = now-30000, now+600000
msg = b"ZCP1-ENDORSE-v1" + idpub + stpub + struct.pack(">qq", nb, na)
endorse = bytes([1]) + idpub + stpub + struct.pack(">qq", nb, na) + idk.sign(msg)
assert len(endorse) == 145
n = NoiseConnection.from_name(b"Noise_XX_25519_ChaChaPoly_SHA256")
n.set_as_initiator() if py_initiator else n.set_as_responder()
n.set_keypair_from_private_bytes(Keypair.STATIC, stk.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption()))
n.set_prologue(b"ZCP1/Noise_XX/v1" + sid)
n.start_handshake()
p = subprocess.Popen(["java","-cp",cp,"dev.zcpmap.security.InteropMainKt",kotlin_role], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
def send(h): p.stdin.write(h+"\n"); p.stdin.flush()
def recv(): return p.stdout.readline().strip()
def check_endorse(b):
    b = bytes(b)
    assert len(b)==145
    i, s = b[1:33], b[33:65]; nb2, na2 = struct.unpack(">qq", b[65:81])
    Ed25519PublicKey.from_public_bytes(i).verify(b[81:], b"ZCP1-ENDORSE-v1"+i+s+b[65:81])
    hs = getattr(n.noise_protocol, "handshake_state", None)
    if hs is not None: assert s == bytes(hs.rs.public_bytes), "endorsed static != noise rs"
    return i
if py_initiator:
    send(n.write_message(b"").hex())
    peer_id = check_endorse(n.read_message(bytes.fromhex(recv())))
    send(n.write_message(endorse).hex())
else:
    assert n.read_message(bytes.fromhex(recv())) == b""
    send(n.write_message(endorse).hex())
    peer_id = check_endorse(n.read_message(bytes.fromhex(recv())))
assert n.handshake_finished
H = recv().split()[1]; RID = recv().split()[1]
assert H == n.get_handshake_hash().hex(), "handshake hash mismatch"
assert RID == idpub.hex()
_, seq, ct = recv().split()
dec = n.noise_protocol.cipher_state_decrypt; dec.n = int(seq)
pt = dec.decrypt_with_ad(b"hdr", bytes.fromhex(ct)); assert pt == b"hello from kotlin", pt
enc = n.noise_protocol.cipher_state_encrypt; enc.n = 3
send("CT 3 " + enc.encrypt_with_ad(b"hdr", b"hello from python").hex())
assert recv() == "PT hello from python"
print(f"INTEROP OK (kotlin={kotlin_role}): h={H[:16]}... endorsements verified both ways, transport both directions")
