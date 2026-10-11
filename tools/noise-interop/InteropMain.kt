package dev.zcpmap.security
import dev.zcpmap.protocol.*
// Line protocol over stdin/stdout: hex messages. args[0] = initiator|responder
fun main(args: Array<String>) {
    val role = if (args[0] == "initiator") HandshakeRole.INITIATOR else HandshakeRole.RESPONDER
    val sid = SessionId.of("00112233445566778899aabbccddeeff".hexToBytes())
    val signer = SoftwareEd25519Signer.generate()
    val rot = StaticKeyRotator(signer, System::currentTimeMillis)
    val st = rot.current()
    val hs = if (role == HandshakeRole.INITIATOR) HandshakeStateMachine.initiator(sid, st) else HandshakeStateMachine.responder(sid, st)
    val r = System.`in`.bufferedReader()
    fun out(s: String) { println(s); System.out.flush() }
    var result: HandshakeResult? = null
    if (role == HandshakeRole.INITIATOR) {
        val s1 = hs.start() as HandshakeStep.Send; out(s1.message.toHex())
        when (val s = hs.onMessage(r.readLine().hexToBytes())) {
            is HandshakeStep.Complete -> { out(s.finalMessage!!.toHex()); result = s.result }
            is HandshakeStep.Failed -> { System.err.println("FAIL " + s.error.message); return }
            else -> error("x")
        }
    } else {
        when (val s = hs.onMessage(r.readLine().hexToBytes())) { is HandshakeStep.Send -> out(s.message.toHex()); is HandshakeStep.Failed -> { System.err.println("FAIL " + s.error.message); return }; else -> error("y") }
        when (val s = hs.onMessage(r.readLine().hexToBytes())) { is HandshakeStep.Complete -> result = s.result; is HandshakeStep.Failed -> { System.err.println("FAIL " + s.error.message); return }; else -> error("z") }
    }
    val res = result!!
    out("H " + res.handshakeHash.toHex())
    out("REMOTE_ID " + res.remoteIdentityPublicKey.toHex())
    // transport: send one frame with seq 3, AAD = "hdr"
    val seq = res.sendCipher.reserveSequence()
    out("CT " + seq + " " + res.sendCipher.seal(seq, "hdr".toByteArray(), "hello from kotlin".toByteArray()).toHex())
    val line = r.readLine().split(" ")
    val pt = res.receiveCipher.open(line[1].toLong(), "hdr".toByteArray(), line[2].hexToBytes())
    out("PT " + String((pt as CryptoResult.Ok).value))
}
