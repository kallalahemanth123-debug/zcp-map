package dev.zcpmap.security

import dev.zcpmap.protocol.HandshakeRole
import dev.zcpmap.protocol.SessionId

/*
 * Noise_XX_25519_ChaChaPoly_SHA256 (Noise Protocol Framework, revision 34), implemented from the
 * specification and interoperability-tested against an independent implementation.
 *
 *   XX:
 *     -> e
 *     <- e, ee, s, es
 *     -> s, se
 *
 * Prologue = "ZCP1/Noise_XX/v1" || sessionId(16). Both sides must agree on the session id chosen
 * by the initiator (sent in the clear frame header); any mismatch makes message 2 fail to decrypt.
 *
 * Handshake payloads:
 *   msg1: empty (it would be sent in the clear)
 *   msg2: responder IdentityEndorsement (encrypted under ee/es)
 *   msg3: initiator IdentityEndorsement (encrypted under ee/es/se) — the initiator's identity is
 *         therefore hidden from active probing attackers, the responder's only from passive ones.
 *
 * Outputs on completion: two TransportCipher objects (Split), the final handshake hash h (public,
 * used for channel binding in signatures) and a secret 32-byte exporter derived from the final
 * chaining key (used to key UWB STS, capability tokens and the Wi-Fi Aware PSK).
 */

class CipherState : AutoCloseable {
    private var k: SecretBytes? = null
    private var n: Long = 0

    fun initializeKey(key: ByteArray?) {
        k?.close()
        k = key?.let { SecretBytes.copyOf(it) }
        n = 0
    }

    fun hasKey(): Boolean = k != null

    fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): ByteArray {
        val key = k ?: return plaintext.copyOf()
        if (n == -1L) throw CryptoError.NonceExhausted()
        val out = CryptoEngine.aeadSeal(key.unsafeView(), CryptoEngine.noiseNonce(n), ad, plaintext)
        n++
        return out
    }

    fun decryptWithAd(ad: ByteArray, ciphertext: ByteArray): CryptoResult<ByteArray> {
        val key = k ?: return CryptoResult.Ok(ciphertext.copyOf())
        if (n == -1L) return CryptoResult.Err(CryptoError.NonceExhausted())
        val r = CryptoEngine.aeadOpen(key.unsafeView(), CryptoEngine.noiseNonce(n), ad, ciphertext)
        if (r is CryptoResult.Ok) n++  // Noise: nonce only advances on success
        return r
    }

    override fun close() {
        k?.close()
        k = null
    }
}

class SymmetricState(protocolName: ByteArray) : AutoCloseable {
    private var ck: ByteArray
    private var h: ByteArray
    val cipher = CipherState()

    init {
        h = if (protocolName.size <= CryptoEngine.HASH_SIZE) protocolName.copyOf(CryptoEngine.HASH_SIZE)
        else CryptoEngine.sha256(protocolName)
        ck = h.copyOf()
    }

    fun handshakeHash(): ByteArray = h.copyOf()

    fun mixHash(data: ByteArray) {
        h = CryptoEngine.sha256(h, data)
    }

    fun mixKey(ikm: ByteArray) {
        val (newCk, tempK) = CryptoEngine.noiseHkdf(ck, ikm, 2)
        ck.zeroize()
        ck = newCk
        cipher.initializeKey(tempK)
        tempK.zeroize()
    }

    fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val ct = cipher.encryptWithAd(h, plaintext)
        mixHash(ct)
        return ct
    }

    fun decryptAndHash(ciphertext: ByteArray): CryptoResult<ByteArray> {
        val r = cipher.decryptWithAd(h, ciphertext)
        if (r is CryptoResult.Ok) mixHash(ciphertext)
        return r
    }

    /** Returns (initiator->responder key, responder->initiator key, exporter). Caller owns all three. */
    fun split(): Triple<SecretBytes, SecretBytes, SecretBytes> {
        val (k1, k2) = CryptoEngine.noiseHkdf(ck, ByteArray(0), 2)
        // Exporter: an extra HKDF output keyed by the final chaining key under a distinct label.
        // It is computed from secret state and never fed back into the Noise transcript, so it is
        // independent of the transport keys and does not affect interoperability.
        val exporter = CryptoEngine.hkdf(ck, EXPORTER_LABEL, h, CryptoEngine.KEY_SIZE)
        return Triple(SecretBytes.adopt(k1), SecretBytes.adopt(k2), SecretBytes.adopt(exporter))
    }

    override fun close() {
        ck.zeroize()
        cipher.close()
    }

    companion object {
        private val EXPORTER_LABEL = "ZCP1 exporter v1".toByteArray()
    }
}

class HandshakeResult(
    val role: HandshakeRole,
    val sessionId: SessionId,
    val sendCipher: TransportCipher,
    val receiveCipher: TransportCipher,
    handshakeHash: ByteArray,
    /** Secret. Owned by the session; zeroized at teardown. */
    val exporter: SecretBytes,
    val remoteStaticPublicKey: ByteArray,
    val remoteEndorsement: IdentityEndorsement,
) : AutoCloseable {
    private val hBytes = handshakeHash.copyOf()
    val handshakeHash: ByteArray get() = hBytes.copyOf()
    val remoteIdentityPublicKey: ByteArray get() = remoteEndorsement.identityPublicKey
    val remoteFingerprint: String get() = CryptoEngine.fingerprint(remoteEndorsement.identityPublicKey)

    /** Domain-separated secret derived from the exporter. */
    fun deriveSecret(label: String, length: Int): SecretBytes = exporter.withCopy { ex ->
        SecretBytes.adopt(CryptoEngine.hkdf(hBytes, ex, ("ZCP1 " + label).toByteArray(), length))
    }

    override fun close() {
        sendCipher.close()
        receiveCipher.close()
        exporter.close()
    }
}

sealed interface HandshakeStep {
    /** Send [message] in a HANDSHAKE frame with this sequence number. */
    class Send(val message: ByteArray, val sequence: Long) : HandshakeStep

    /** Handshake complete. If [finalMessage] is non-null it must be sent first (initiator msg3). */
    class Complete(val result: HandshakeResult, val finalMessage: ByteArray?, val finalSequence: Long) : HandshakeStep

    class Failed(val error: CryptoError) : HandshakeStep
}

/** Policy hook: decides whether a remote identity may complete a handshake at all (blocklist, pinning). */
fun interface PeerIdentityPolicy {
    fun admit(remoteIdentityPublicKey: ByteArray): Boolean

    companion object {
        val ADMIT_ALL = PeerIdentityPolicy { true }
    }
}

class HandshakeStateMachine private constructor(
    val role: HandshakeRole,
    private val sessionId: SessionId,
    private val localStatic: SecretBytes,
    private val localStaticPublic: ByteArray,
    private val localEndorsement: IdentityEndorsement,
    private val identityPolicy: PeerIdentityPolicy,
    private val clock: () -> Long,
) : AutoCloseable {

    private sealed interface Stage {
        data object InitiatorStart : Stage
        data object InitiatorAwaitMsg2 : Stage
        data object ResponderAwaitMsg1 : Stage
        data object ResponderAwaitMsg3 : Stage
        data object Done : Stage
        data object Failed : Stage
    }

    private val ss = SymmetricState(PROTOCOL_NAME)
    private var stage: Stage
    private var e: X25519KeyPair? = null
    private var re: ByteArray? = null
    private var rs: ByteArray? = null

    init {
        ss.mixHash(PROLOGUE_PREFIX + sessionId.toByteArray())
        stage = if (role == HandshakeRole.INITIATOR) Stage.InitiatorStart else Stage.ResponderAwaitMsg1
    }

    val isComplete: Boolean get() = stage == Stage.Done
    val isFailed: Boolean get() = stage == Stage.Failed

    /** Initiator only: produces message 1. */
    fun start(): HandshakeStep {
        if (stage != Stage.InitiatorStart) return fail(CryptoError.InvalidKeyMaterial("start() in wrong stage"))
        val eph = CryptoEngine.generateX25519()
        e = eph
        val ePub = eph.publicKey
        ss.mixHash(ePub)
        val payload = ss.encryptAndHash(ByteArray(0)) // no key yet: empty plaintext
        stage = Stage.InitiatorAwaitMsg2
        return HandshakeStep.Send(ePub + payload, 0)
    }

    fun onMessage(message: ByteArray): HandshakeStep = try {
        when (stage) {
            Stage.ResponderAwaitMsg1 -> readMsg1WriteMsg2(message)
            Stage.InitiatorAwaitMsg2 -> readMsg2WriteMsg3(message)
            Stage.ResponderAwaitMsg3 -> readMsg3(message)
            else -> fail(CryptoError.InvalidKeyMaterial("unexpected handshake message in stage $stage"))
        }
    } catch (ce: CryptoError) {
        fail(ce)
    } catch (re: RuntimeException) {
        fail(CryptoError.InvalidKeyMaterial("handshake processing error: ${re.javaClass.simpleName}"))
    }

    private fun readMsg1WriteMsg2(msg: ByteArray): HandshakeStep {
        // msg1 = e(32) || payload (must be empty)
        if (msg.size != DH_LEN) return fail(CryptoError.InvalidKeyMaterial("message 1 must be exactly 32 bytes"))
        val remoteE = msg.copyOfRange(0, DH_LEN)
        re = remoteE
        ss.mixHash(remoteE)
        val p1 = ss.decryptAndHash(msg.copyOfRange(DH_LEN, msg.size))
        if (p1 is CryptoResult.Err) return fail(p1.error)

        // <- e, ee, s, es
        val eph = CryptoEngine.generateX25519()
        e = eph
        val out = java.io.ByteArrayOutputStream()
        val ePub = eph.publicKey
        out.write(ePub)
        ss.mixHash(ePub)
        dh(eph.privateKey, remoteE).use { ss.mixKey(it.unsafeView()) }                  // ee
        out.write(ss.encryptAndHash(localStaticPublic))                                  // s
        dh(localStatic, remoteE).use { ss.mixKey(it.unsafeView()) }                      // es (responder: DH(s, re))
        out.write(ss.encryptAndHash(localEndorsement.encode()))                          // payload
        stage = Stage.ResponderAwaitMsg3
        return HandshakeStep.Send(out.toByteArray(), 1)
    }

    private fun readMsg2WriteMsg3(msg: ByteArray): HandshakeStep {
        val minLen = DH_LEN + (DH_LEN + TAG) + (IdentityEndorsement.ENCODED_SIZE + TAG)
        if (msg.size != minLen) return fail(CryptoError.InvalidKeyMaterial("message 2 has invalid length ${msg.size}"))
        var off = 0
        val remoteE = msg.copyOfRange(off, off + DH_LEN); off += DH_LEN
        re = remoteE
        ss.mixHash(remoteE)
        val eph = e ?: return fail(CryptoError.KeyWiped())
        dh(eph.privateKey, remoteE).use { ss.mixKey(it.unsafeView()) }                  // ee
        val encS = msg.copyOfRange(off, off + DH_LEN + TAG); off += DH_LEN + TAG
        val remoteS = when (val r = ss.decryptAndHash(encS)) {                            // s
            is CryptoResult.Ok -> r.value
            is CryptoResult.Err -> return fail(r.error)
        }
        rs = remoteS
        dh(eph.privateKey, remoteS).use { ss.mixKey(it.unsafeView()) }                  // es (initiator: DH(e, rs))
        val payload = when (val r = ss.decryptAndHash(msg.copyOfRange(off, msg.size))) {
            is CryptoResult.Ok -> r.value
            is CryptoResult.Err -> return fail(r.error)
        }
        val endorsement = validateEndorsement(payload, remoteS) ?: return fail(endorsementError!!)

        // -> s, se
        val out = java.io.ByteArrayOutputStream()
        out.write(ss.encryptAndHash(localStaticPublic))                                  // s
        dh(localStatic, remoteE).use { ss.mixKey(it.unsafeView()) }                      // se (initiator: DH(s, re))
        out.write(ss.encryptAndHash(localEndorsement.encode()))                          // payload
        val result = finish(remoteS, endorsement)
        return HandshakeStep.Complete(result, out.toByteArray(), 2)
    }

    private fun readMsg3(msg: ByteArray): HandshakeStep {
        val expected = (DH_LEN + TAG) + (IdentityEndorsement.ENCODED_SIZE + TAG)
        if (msg.size != expected) return fail(CryptoError.InvalidKeyMaterial("message 3 has invalid length ${msg.size}"))
        val remoteS = when (val r = ss.decryptAndHash(msg.copyOfRange(0, DH_LEN + TAG))) {   // s
            is CryptoResult.Ok -> r.value
            is CryptoResult.Err -> return fail(r.error)
        }
        rs = remoteS
        val eph = e ?: return fail(CryptoError.KeyWiped())
        dh(eph.privateKey, remoteS).use { ss.mixKey(it.unsafeView()) }                  // se (responder: DH(e, rs))
        val payload = when (val r = ss.decryptAndHash(msg.copyOfRange(DH_LEN + TAG, msg.size))) {
            is CryptoResult.Ok -> r.value
            is CryptoResult.Err -> return fail(r.error)
        }
        val endorsement = validateEndorsement(payload, remoteS) ?: return fail(endorsementError!!)
        return HandshakeStep.Complete(finish(remoteS, endorsement), null, 2)
    }

    private var endorsementError: CryptoError? = null

    private fun validateEndorsement(payload: ByteArray, remoteStatic: ByteArray): IdentityEndorsement? {
        val endorsement = IdentityEndorsement.decode(payload)
        if (endorsement == null) {
            endorsementError = CryptoError.EndorsementInvalid("malformed identity endorsement")
            return null
        }
        when (val v = endorsement.verify(remoteStatic, clock())) {
            is CryptoResult.Err -> { endorsementError = v.error; return null }
            is CryptoResult.Ok -> Unit
        }
        if (CryptoEngine.constantTimeEquals(endorsement.identityPublicKey, localEndorsement.identityPublicKey)) {
            endorsementError = CryptoError.EndorsementInvalid("peer presented our own identity (reflection attack)")
            return null
        }
        if (!identityPolicy.admit(endorsement.identityPublicKey)) {
            endorsementError = CryptoError.EndorsementInvalid("peer identity rejected by local policy")
            return null
        }
        return endorsement
    }

    private fun finish(remoteStatic: ByteArray, endorsement: IdentityEndorsement): HandshakeResult {
        val h = ss.handshakeHash()
        val (k1, k2, exporter) = ss.split()
        // Transport sequence numbers start at 3: 0..2 were the handshake frames.
        val (send, recv) = if (role == HandshakeRole.INITIATOR) {
            TransportCipher(k1, FIRST_TRANSPORT_SEQUENCE) to TransportCipher(k2, FIRST_TRANSPORT_SEQUENCE)
        } else {
            TransportCipher(k2, FIRST_TRANSPORT_SEQUENCE) to TransportCipher(k1, FIRST_TRANSPORT_SEQUENCE)
        }
        stage = Stage.Done
        wipeEphemeral()
        return HandshakeResult(role, sessionId, send, recv, h, exporter, remoteStatic, endorsement)
    }

    private fun dh(priv: SecretBytes, pub: ByteArray): SecretBytes = CryptoEngine.x25519(priv, pub).getOrThrow()

    private fun fail(error: CryptoError): HandshakeStep {
        stage = Stage.Failed
        wipeEphemeral()
        return HandshakeStep.Failed(error)
    }

    private fun wipeEphemeral() {
        e?.close()
        e = null
        ss.close()
        localStatic.close()
    }

    override fun close() {
        if (stage != Stage.Done) stage = Stage.Failed
        wipeEphemeral()
    }

    companion object {
        val PROTOCOL_NAME: ByteArray = "Noise_XX_25519_ChaChaPoly_SHA256".toByteArray()
        val PROLOGUE_PREFIX: ByteArray = "ZCP1/Noise_XX/v1".toByteArray()
        const val DH_LEN = 32
        const val TAG = 16
        const val FIRST_TRANSPORT_SEQUENCE = 3L

        fun initiator(
            sessionId: SessionId,
            static: RotatingStatic,
            identityPolicy: PeerIdentityPolicy = PeerIdentityPolicy.ADMIT_ALL,
            clock: () -> Long = System::currentTimeMillis,
        ) = HandshakeStateMachine(
            HandshakeRole.INITIATOR, sessionId, static.duplicatePrivate(), static.keyPair.publicKey,
            static.endorsement, identityPolicy, clock,
        )

        fun responder(
            sessionId: SessionId,
            static: RotatingStatic,
            identityPolicy: PeerIdentityPolicy = PeerIdentityPolicy.ADMIT_ALL,
            clock: () -> Long = System::currentTimeMillis,
        ) = HandshakeStateMachine(
            HandshakeRole.RESPONDER, sessionId, static.duplicatePrivate(), static.keyPair.publicKey,
            static.endorsement, identityPolicy, clock,
        )

        /** Raw constructor for interoperability testing with arbitrary payloads/keys. */
        internal fun raw(
            role: HandshakeRole,
            sessionId: SessionId,
            localStatic: SecretBytes,
            localStaticPublic: ByteArray,
            endorsement: IdentityEndorsement,
            clock: () -> Long,
        ) = HandshakeStateMachine(role, sessionId, localStatic, localStaticPublic, endorsement, PeerIdentityPolicy.ADMIT_ALL, clock)
    }
}
