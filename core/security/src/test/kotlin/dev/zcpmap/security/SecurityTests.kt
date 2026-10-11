package dev.zcpmap.security

import dev.zcpmap.protocol.HandshakeRole
import dev.zcpmap.protocol.SessionId
import dev.zcpmap.protocol.hexToBytes
import dev.zcpmap.protocol.toHex
import org.bouncycastle.math.ec.rfc8032.Ed25519
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class CryptoEngineTest {
    @Test
    fun x25519Rfc7748Vector() {
        val a = SecretBytes.copyOf("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a".hexToBytes())
        assertEquals("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", CryptoEngine.x25519PublicFromPrivate(a).toHex())
        val shared = CryptoEngine.x25519(a, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f".hexToBytes()).getOrThrow()
        shared.withCopy { assertEquals("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", it.toHex()) }
    }

    @Test
    fun x25519RejectsLowOrderPoint() {
        val kp = CryptoEngine.generateX25519()
        assertIs<CryptoResult.Err>(CryptoEngine.x25519(kp.privateKey, ByteArray(32)))
    }

    @Test
    fun ed25519Rfc8032Vector() {
        val sk = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60".hexToBytes()
        val signer = SoftwareEd25519Signer.fromSeed(SecretBytes.adopt(sk), IdentitySecurityLevel.SOFTWARE_EPHEMERAL)
        assertEquals("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", signer.publicKey.toHex())
        val sig = signer.sign(ByteArray(0))
        assertEquals(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            sig.toHex(),
        )
        assertTrue(CryptoEngine.ed25519Verify(signer.publicKey, ByteArray(0), sig))
        assertFalse(CryptoEngine.ed25519Verify(signer.publicKey, byteArrayOf(1), sig))
        assertEquals(Ed25519.SIGNATURE_SIZE, sig.size)
    }

    @Test
    fun chacha20Poly1305Rfc8439Vector() {
        val key = ByteArray(32) { (0x80 + it).toByte() }
        val nonce = "070000004041424344454647".hexToBytes()
        val aad = "50515253c0c1c2c3c4c5c6c7".hexToBytes()
        val pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".toByteArray()
        val sealed = CryptoEngine.aeadSeal(key, nonce, aad, pt)
        assertEquals("1ae10b594f09e26a7e902ecbd0600691", sealed.copyOfRange(sealed.size - 16, sealed.size).toHex())
        assertTrue(sealed.toHex().startsWith("d31a8d34648e60db7b86afbc53ef7ec2"))
        assertContentEquals(pt, (CryptoEngine.aeadOpen(key, nonce, aad, sealed) as CryptoResult.Ok).value)
        sealed[3] = (sealed[3].toInt() xor 1).toByte()
        assertIs<CryptoResult.Err>(CryptoEngine.aeadOpen(key, nonce, aad, sealed))
    }

    @Test
    fun hkdfRfc5869Case1() {
        val okm = CryptoEngine.hkdf(ByteArray(13) { it.toByte() }, ByteArray(22) { 0x0b }, ByteArray(10) { (0xf0 + it).toByte() }, 42)
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", okm.toHex())
    }

    @Test
    fun replayWindowSemantics() {
        val w = ReplayWindow(256)
        listOf(3L, 5L, 4L, 100L, 6L).forEach { assertEquals(ReplayWindow.Verdict.Fresh, w.check(it)); w.commit(it) }
        assertEquals(ReplayWindow.Verdict.Duplicate, w.check(5))
        assertEquals(ReplayWindow.Verdict.Duplicate, w.check(100))
        assertEquals(ReplayWindow.Verdict.Fresh, w.check(99))
        w.commit(400)
        assertEquals(ReplayWindow.Verdict.TooOld, w.check(100))
        assertEquals(ReplayWindow.Verdict.Fresh, w.check(145))
        assertEquals(ReplayWindow.Verdict.TooOld, w.check(144))
        kotlin.test.assertFailsWith<CryptoError.ReplayDetected> { w.commit(400) }
    }

    @Test
    fun secretBytesZeroizeOnClose() {
        val s = SecretBytes.copyOf(ByteArray(32) { 7 })
        s.close()
        assertTrue(s.isWiped)
        kotlin.test.assertFailsWith<CryptoError.KeyWiped> { s.withCopy { } }
    }
}

class HandshakeStateMachineTest {
    private val now = 1_800_000_000_000L
    private fun node() = SoftwareEd25519Signer.generate().let { it to StaticKeyRotator(it, { now }) }

    private fun run(tamper: ((Int, ByteArray) -> ByteArray)? = null): Pair<HandshakeStep, HandshakeStep?> {
        val (_, rotA) = node()
        val (_, rotB) = node()
        val sid = SessionId.random(CryptoEngine::randomBytes)
        val i = HandshakeStateMachine.initiator(sid, rotA.current(), clock = { now })
        val r = HandshakeStateMachine.responder(sid, rotB.current(), clock = { now })
        val m1 = (i.start() as HandshakeStep.Send).message.let { tamper?.invoke(1, it) ?: it }
        val s2 = r.onMessage(m1)
        if (s2 !is HandshakeStep.Send) return s2 to null
        val m2 = tamper?.invoke(2, s2.message) ?: s2.message
        val s3 = i.onMessage(m2)
        if (s3 !is HandshakeStep.Complete) return s3 to null
        val m3 = tamper?.invoke(3, s3.finalMessage!!) ?: s3.finalMessage!!
        return s3 to r.onMessage(m3)
    }

    @Test
    fun completesWithMatchingKeysAndIdentities() {
        val (a, b) = run()
        assertIs<HandshakeStep.Complete>(a)
        assertIs<HandshakeStep.Complete>(b)
        val ra = a.result
        val rb = b.result
        assertContentEquals(ra.handshakeHash, rb.handshakeHash)
        ra.exporter.withCopy { ea -> rb.exporter.withCopy { eb -> assertContentEquals(ea, eb) } }
        val seq = ra.sendCipher.reserveSequence()
        assertEquals(3L, seq)
        val ct = ra.sendCipher.seal(seq, byteArrayOf(1, 2), "ping".toByteArray())
        assertEquals("ping", String((rb.receiveCipher.open(seq, byteArrayOf(1, 2), ct) as CryptoResult.Ok).value))
        assertIs<CryptoResult.Err>(rb.receiveCipher.open(seq, byteArrayOf(1, 2), ct)) // replay
        assertIs<CryptoResult.Err>(rb.receiveCipher.open(seq + 1, byteArrayOf(9, 9), ct)) // wrong AAD/nonce
        val dA = ra.deriveSecret("uwb-sts-key", 16)
        val dB = rb.deriveSecret("uwb-sts-key", 16)
        dA.withCopy { x -> dB.withCopy { y -> assertContentEquals(x, y) } }
        assertNotNull(ra.remoteFingerprint)
    }

    @Test
    fun tamperingAnyMessageFails() {
        for (target in 1..3) {
            val (a, b) = run { idx, m -> if (idx == target) m.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 0x01).toByte() } else m }
            val failed = a is HandshakeStep.Failed || b is HandshakeStep.Failed
            assertTrue(failed, "tampering message $target must fail the handshake")
        }
    }

    @Test
    fun reflectionOfOwnIdentityIsRejected() {
        val (_, rot) = node()
        val sid = SessionId.random(CryptoEngine::randomBytes)
        val i = HandshakeStateMachine.initiator(sid, rot.current(), clock = { now })
        val r = HandshakeStateMachine.responder(sid, rot.forceRotate(), clock = { now })
        val s2 = r.onMessage((i.start() as HandshakeStep.Send).message) as HandshakeStep.Send
        assertIs<HandshakeStep.Failed>(i.onMessage(s2.message))
    }

    @Test
    fun expiredEndorsementIsRejected() {
        val (_, rotA) = node()
        val (_, rotB) = node()
        val sid = SessionId.random(CryptoEngine::randomBytes)
        val i = HandshakeStateMachine.initiator(sid, rotA.current(), clock = { now + 3_600_000 })
        val r = HandshakeStateMachine.responder(sid, rotB.current(), clock = { now })
        val s2 = r.onMessage((i.start() as HandshakeStep.Send).message) as HandshakeStep.Send
        assertIs<HandshakeStep.Failed>(i.onMessage(s2.message))
    }

    @Test
    fun roleMismatchedSessionIdFails() {
        val (_, rotA) = node()
        val (_, rotB) = node()
        val i = HandshakeStateMachine.initiator(SessionId.random(CryptoEngine::randomBytes), rotA.current(), clock = { now })
        val r = HandshakeStateMachine.responder(SessionId.random(CryptoEngine::randomBytes), rotB.current(), clock = { now })
        val s2 = r.onMessage((i.start() as HandshakeStep.Send).message) as HandshakeStep.Send
        assertIs<HandshakeStep.Failed>(i.onMessage(s2.message))
        assertEquals(HandshakeRole.INITIATOR, i.role)
    }
}

class CapabilityAttestationTest {
    private val nowS = 1_800_000_000L
    private val issuer = SoftwareEd25519Signer.generate()
    private val verifier = SoftwareEd25519Signer.generate()
    private val h = CryptoEngine.randomBytes(32)

    private fun hw() = HardwareSummary(
        "50-79", false, "nominal", "10-100GiB",
        CommittedFact.commit("50-79", "63").first, CommittedFact.commit("10-100GiB", "40000000000").first,
    )

    private fun manifest() = CapabilityManifest.create(
        issuer, CryptoEngine.fingerprint(verifier.publicKey), h,
        listOf(CapabilityGrant(CapabilityAction.DATA_RECEIVE, "zcp:sandbox/inbox", 1_000_000, 0, 0)),
        hw(), "local-agent", nowS,
    )

    @Test
    fun signAndVerify() {
        val wire = CapabilityManifest.sign(manifest(), issuer)
        val cache = NonceReplayCache { nowS }
        val r = CapabilityManifest.verify(wire, issuer.publicKey, CryptoEngine.fingerprint(verifier.publicKey), h, nowS, cache)
        assertIs<CryptoResult.Ok<CapabilityManifest>>(r)
        assertEquals(1_000_000, r.value.grantFor(CapabilityAction.DATA_RECEIVE)!!.maxBytes)
        // Replay of the same manifest is refused.
        assertIs<CryptoResult.Err>(CapabilityManifest.verify(wire, issuer.publicKey, CryptoEngine.fingerprint(verifier.publicKey), h, nowS, cache))
    }

    @Test
    fun rejectsWrongAudienceSessionIssuerExpiryAndTamper() {
        val wire = CapabilityManifest.sign(manifest(), issuer)
        val aud = CryptoEngine.fingerprint(verifier.publicKey)
        fun v(w: ByteArray = wire, iss: ByteArray = issuer.publicKey, a: String = aud, hh: ByteArray = h, t: Long = nowS) =
            CapabilityManifest.verify(w, iss, a, hh, t, NonceReplayCache { t })
        assertIs<CryptoResult.Err>(v(a = CryptoEngine.fingerprint(issuer.publicKey)))
        assertIs<CryptoResult.Err>(v(hh = CryptoEngine.randomBytes(32)))
        assertIs<CryptoResult.Err>(v(iss = verifier.publicKey))
        assertIs<CryptoResult.Err>(v(t = nowS + 10_000))
        val tampered = String(wire).replace("1000000", "9000000").toByteArray()
        assertIs<CryptoResult.Err>(v(w = tampered))
        val extraKey = String(wire).replaceFirst("{", "{\"zz\":1,").toByteArray()
        assertIs<CryptoResult.Err>(v(w = extraKey))
    }

    @Test
    fun commitmentsOpen() {
        val (fact, salt) = CommittedFact.commit("50-79", "63")
        assertTrue(CommittedFact.open(fact, "63", salt))
        assertFalse(CommittedFact.open(fact, "64", salt))
    }

    @Test
    fun macaroonTokens() {
        val root = SecretBytes.copyOf(CryptoEngine.randomBytes(32))
        val token = CapabilityToken.mint(
            root,
            listOf("sid = s-1", "aud = zcp1:aa", "cid = ctr-0011223344556677", "op = push", "exp <= ${nowS + 60}", "max_bytes <= 1000", "path_prefix prefix inbox/ctr-0011223344556677"),
        )
        val ok = CapabilityRequest("s-1", "zcp1:aa", "ctr-0011223344556677", "push", nowS, 1000, 0, "inbox/ctr-0011223344556677")
        val decoded = CapabilityToken.decode(token.encode())!!
        assertIs<TokenVerdict.Authorized>(decoded.verify(root, ok))
        assertIs<TokenVerdict.Denied>(decoded.verify(root, ok.copy(bytes = 1001)))
        assertIs<TokenVerdict.Denied>(decoded.verify(root, ok.copy(nowSeconds = nowS + 61)))
        assertIs<TokenVerdict.Denied>(decoded.verify(root, ok.copy(path = "inbox/ctr-0011223344556677/../../outbox")))
        assertIs<TokenVerdict.Denied>(decoded.verify(root, ok.copy(operation = "pull")))
        assertIs<TokenVerdict.Denied>(decoded.verify(SecretBytes.copyOf(CryptoEngine.randomBytes(32)), ok))
        val narrowed = decoded.attenuate("max_bytes <= 10")
        assertIs<TokenVerdict.Denied>(narrowed.verify(root, ok))
        assertIs<TokenVerdict.Authorized>(narrowed.verify(root, ok.copy(bytes = 10)))
        // Unknown caveats are refused at decode/attenuate time (fail closed).
        kotlin.test.assertFailsWith<IllegalArgumentException> { decoded.attenuate("shell = yes") }
        val missing = CapabilityToken.mint(root, listOf("sid = s-1"))
        assertIs<TokenVerdict.Denied>(missing.verify(root, ok))
    }

    @Test
    fun settlementReceipts() {
        val r = SettlementReceipt.issue(issuer, "ctr-0011223344556677", h, 123, ByteArray(32) { 1 }, ByteArray(32) { 2 }, "fulfilled", nowS)
        assertIs<CryptoResult.Ok<SettlementReceipt>>(SettlementReceipt.verify(r.toJson(), issuer.publicKey, h))
        assertIs<CryptoResult.Err>(SettlementReceipt.verify(r.toJson(), verifier.publicKey, h))
        val forged = kotlinx.serialization.json.JsonObject(r.toJson() + ("bytes" to kotlinx.serialization.json.JsonPrimitive(124)))
        assertIs<CryptoResult.Err>(SettlementReceipt.verify(forged, issuer.publicKey, h))
    }
}
