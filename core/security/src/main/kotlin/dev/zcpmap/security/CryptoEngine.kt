package dev.zcpmap.security

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.math.ec.rfc7748.X25519
import org.bouncycastle.math.ec.rfc8032.Ed25519
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/*
 * Cryptographic engine for ZCP-MAP.
 *
 * Primitive choices (all through the BouncyCastle *lightweight* API so behaviour is identical on
 * every Android version and on the JVM used for tests; no JCA provider lookups):
 *   - X25519 (RFC 7748) for all Diffie-Hellman.
 *   - Ed25519 (RFC 8032) for identity signatures and peer verification.
 *   - ChaCha20-Poly1305 (RFC 8439) AEAD.
 *   - HKDF-SHA256 (RFC 5869) built from HMAC-SHA256.
 *
 * Zeroization note: the JVM gives no hard guarantee that a ByteArray was never copied by the GC
 * or JIT. We therefore (1) keep secrets in exactly one ByteArray wrapped by [SecretBytes],
 * (2) wipe that array deterministically on close/teardown, and (3) never convert secrets to
 * String or boxed collections. That is the strongest guarantee available to managed code; the
 * long-term identity key never enters process memory at all when hardware Ed25519 is available.
 */

// ------------------------------------------------------------------------------------------
// Results and errors
// ------------------------------------------------------------------------------------------

sealed class CryptoError(message: String) : Exception(message) {
    class AuthenticationFailed(detail: String = "AEAD tag mismatch") : CryptoError(detail)
    class ReplayDetected(val sequence: Long) : CryptoError("replayed or too-old sequence $sequence")
    class NonceExhausted : CryptoError("transport nonce space exhausted; session must be torn down")
    class InvalidKeyMaterial(detail: String) : CryptoError(detail)
    class LowOrderPoint : CryptoError("X25519 produced an all-zero shared secret (low-order point)")
    class SignatureInvalid(detail: String = "Ed25519 signature verification failed") : CryptoError(detail)
    class EndorsementInvalid(detail: String) : CryptoError(detail)
    class KeyWiped : CryptoError("key material has already been zeroized")
    class HardwareKeystoreFailure(detail: String, cause: Throwable? = null) : CryptoError(detail) {
        init { cause?.let { initCause(it) } }
    }
}

sealed interface CryptoResult<out T> {
    data class Ok<T>(val value: T) : CryptoResult<T>
    data class Err(val error: CryptoError) : CryptoResult<Nothing>

    fun getOrThrow(): T = when (this) {
        is Ok -> value
        is Err -> throw error
    }
}

// ------------------------------------------------------------------------------------------
// Secret handling
// ------------------------------------------------------------------------------------------

/** Overwrites the array with zeros. The fence prevents the store from being reordered away. */
fun ByteArray.zeroize() {
    java.util.Arrays.fill(this, 0.toByte())
    java.lang.invoke.VarHandle.fullFence()
}

/**
 * Owns exactly one secret ByteArray. Reads hand out defensive copies only through [use] so that
 * callers are forced to scope their copy; [close] zeroizes the backing store.
 */
class SecretBytes private constructor(private val bytes: ByteArray) : AutoCloseable {
    @Volatile private var wiped = false

    val size: Int get() = bytes.size
    val isWiped: Boolean get() = wiped

    /** Runs [block] with a temporary copy that is wiped as soon as the block returns. */
    inline fun <R> withCopy(block: (ByteArray) -> R): R {
        val tmp = copyOut()
        try {
            return block(tmp)
        } finally {
            tmp.zeroize()
        }
    }

    @PublishedApi
    internal fun copyOut(): ByteArray {
        if (wiped) throw CryptoError.KeyWiped()
        return bytes.copyOf()
    }

    /** Direct, non-copying access for hot paths inside this module (AEAD key setup). */
    internal fun unsafeView(): ByteArray {
        if (wiped) throw CryptoError.KeyWiped()
        return bytes
    }

    fun duplicate(): SecretBytes = SecretBytes(copyOut())

    override fun close() {
        if (!wiped) {
            bytes.zeroize()
            wiped = true
        }
    }

    companion object {
        /** Takes ownership of [bytes]; the caller must not keep or reuse the array. */
        fun adopt(bytes: ByteArray): SecretBytes = SecretBytes(bytes)

        fun copyOf(bytes: ByteArray): SecretBytes = SecretBytes(bytes.copyOf())
    }
}

class X25519KeyPair(val privateKey: SecretBytes, publicKey: ByteArray) : AutoCloseable {
    private val pub = publicKey.copyOf()
    val publicKey: ByteArray get() = pub.copyOf()
    override fun close() = privateKey.close()
}

enum class IdentitySecurityLevel(val label: String, val hardwareBacked: Boolean) {
    STRONGBOX_NATIVE("StrongBox Ed25519", true),
    TEE_NATIVE("TEE Ed25519", true),
    SOFTWARE_SEALED_STRONGBOX("Software Ed25519 sealed by StrongBox AES", true),
    SOFTWARE_SEALED_TEE("Software Ed25519 sealed by TEE AES", true),
    /** Keystore without secure hardware (emulators, some old builds): encrypted at rest, not hardware-protected. */
    SOFTWARE_SEALED_SOFTWARE("Software Ed25519 sealed by software keystore", false),
    SOFTWARE_EPHEMERAL("Software Ed25519 (test / ephemeral)", false),
}

/** Long-term Ed25519 identity. Implementations may never expose the private key. */
interface IdentitySigner {
    /** Raw 32-byte Ed25519 public key. */
    val publicKey: ByteArray
    val securityLevel: IdentitySecurityLevel
    fun sign(message: ByteArray): ByteArray
}

/** Pure-software Ed25519 signer used for tests and as the sealed-key fallback's in-RAM form. */
class SoftwareEd25519Signer private constructor(
    private val seed: SecretBytes,
    override val securityLevel: IdentitySecurityLevel,
) : IdentitySigner, AutoCloseable {
    private val pub: ByteArray = seed.withCopy { s ->
        ByteArray(Ed25519.PUBLIC_KEY_SIZE).also { Ed25519.generatePublicKey(s, 0, it, 0) }
    }

    override val publicKey: ByteArray get() = pub.copyOf()

    override fun sign(message: ByteArray): ByteArray = seed.withCopy { s ->
        ByteArray(Ed25519.SIGNATURE_SIZE).also { Ed25519.sign(s, 0, message, 0, message.size, it, 0) }
    }

    override fun close() = seed.close()

    companion object {
        fun generate(random: SecureRandom = CryptoEngine.secureRandom): SoftwareEd25519Signer {
            val sk = ByteArray(Ed25519.SECRET_KEY_SIZE)
            Ed25519.generatePrivateKey(random, sk)
            return SoftwareEd25519Signer(SecretBytes.adopt(sk), IdentitySecurityLevel.SOFTWARE_EPHEMERAL)
        }

        /** Takes ownership of a 32-byte seed (e.g. just unsealed from Keystore). */
        fun fromSeed(seed: SecretBytes, level: IdentitySecurityLevel): SoftwareEd25519Signer {
            require(seed.size == Ed25519.SECRET_KEY_SIZE) { "Ed25519 seed must be 32 bytes" }
            return SoftwareEd25519Signer(seed, level)
        }
    }
}

// ------------------------------------------------------------------------------------------
// Engine
// ------------------------------------------------------------------------------------------

object CryptoEngine {
    const val KEY_SIZE = 32
    const val NONCE_SIZE = 12
    const val TAG_SIZE = 16
    const val HASH_SIZE = 32

    val secureRandom: SecureRandom by lazy {
        // Android: the default SecureRandom is backed by /dev/urandom via Conscrypt/OpenSSL;
        // on the JVM it is the platform DRBG. Never use SHA1PRNG with an explicit seed.
        SecureRandom()
    }

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also { secureRandom.nextBytes(it) }

    fun sha256(vararg parts: ByteArray): ByteArray {
        val d = SHA256Digest()
        parts.forEach { d.update(it, 0, it.size) }
        return ByteArray(HASH_SIZE).also { d.doFinal(it, 0) }
    }

    fun hmacSha256(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = HMac(SHA256Digest())
        mac.init(KeyParameter(key))
        parts.forEach { mac.update(it, 0, it.size) }
        return ByteArray(HASH_SIZE).also { mac.doFinal(it, 0) }
    }

    /** RFC 5869 HKDF-Extract. */
    fun hkdfExtract(salt: ByteArray?, ikm: ByteArray): ByteArray =
        hmacSha256(salt ?: ByteArray(HASH_SIZE), ikm)

    /** RFC 5869 HKDF-Expand. */
    fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * HASH_SIZE) { "HKDF output length out of range" }
        val out = ByteArray(length)
        var t = ByteArray(0)
        var produced = 0
        var counter = 1
        while (produced < length) {
            val next = hmacSha256(prk, t, info, byteArrayOf(counter.toByte()))
            t.zeroize()
            t = next
            val take = minOf(HASH_SIZE, length - produced)
            System.arraycopy(t, 0, out, produced, take)
            produced += take
            counter++
        }
        t.zeroize()
        return out
    }

    fun hkdf(salt: ByteArray?, ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hkdfExtract(salt, ikm)
        try {
            return hkdfExpand(prk, info, length)
        } finally {
            prk.zeroize()
        }
    }

    /** Noise HKDF(chaining_key, ikm, n): RFC 5869 with salt=ck, info="", split into 32-byte outputs. */
    fun noiseHkdf(chainingKey: ByteArray, ikm: ByteArray, outputs: Int): List<ByteArray> {
        require(outputs in 2..3)
        val okm = hkdf(chainingKey, ikm, ByteArray(0), HASH_SIZE * outputs)
        try {
            return List(outputs) { i -> okm.copyOfRange(i * HASH_SIZE, (i + 1) * HASH_SIZE) }
        } finally {
            okm.zeroize()
        }
    }

    // ---------------------------------- X25519 ----------------------------------------

    fun generateX25519(random: SecureRandom = secureRandom): X25519KeyPair {
        val sk = ByteArray(X25519.SCALAR_SIZE)
        X25519.generatePrivateKey(random, sk)
        val pk = ByteArray(X25519.POINT_SIZE)
        X25519.generatePublicKey(sk, 0, pk, 0)
        return X25519KeyPair(SecretBytes.adopt(sk), pk)
    }

    fun x25519PublicFromPrivate(privateKey: SecretBytes): ByteArray = privateKey.withCopy { sk ->
        ByteArray(X25519.POINT_SIZE).also { X25519.generatePublicKey(sk, 0, it, 0) }
    }

    /** DH with contributory-behaviour check: an all-zero result (low-order peer point) is rejected. */
    fun x25519(privateKey: SecretBytes, peerPublic: ByteArray): CryptoResult<SecretBytes> {
        if (peerPublic.size != X25519.POINT_SIZE) {
            return CryptoResult.Err(CryptoError.InvalidKeyMaterial("X25519 public key must be 32 bytes"))
        }
        val out = ByteArray(X25519.POINT_SIZE)
        val ok = privateKey.withCopy { sk -> X25519.calculateAgreement(sk, 0, peerPublic, 0, out, 0) }
        if (!ok) {
            out.zeroize()
            return CryptoResult.Err(CryptoError.LowOrderPoint())
        }
        return CryptoResult.Ok(SecretBytes.adopt(out))
    }

    // ---------------------------------- Ed25519 ---------------------------------------

    fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != Ed25519.PUBLIC_KEY_SIZE || signature.size != Ed25519.SIGNATURE_SIZE) return false
        return try {
            Ed25519.verify(signature, 0, publicKey, 0, message, 0, message.size)
        } catch (_: RuntimeException) {
            false
        }
    }

    // ---------------------------------- AEAD ------------------------------------------

    /** Noise ChaChaPoly nonce: 4 zero bytes followed by the 64-bit counter, little-endian. */
    fun noiseNonce(counter: Long): ByteArray =
        ByteBuffer.allocate(NONCE_SIZE).order(ByteOrder.LITTLE_ENDIAN).putInt(0).putLong(counter).array()

    fun aeadSeal(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        require(key.size == KEY_SIZE && nonce.size == NONCE_SIZE)
        val c = ChaCha20Poly1305()
        c.init(true, AEADParameters(KeyParameter(key), TAG_SIZE * 8, nonce, aad))
        val out = ByteArray(c.getOutputSize(plaintext.size))
        var n = c.processBytes(plaintext, 0, plaintext.size, out, 0)
        n += c.doFinal(out, n)
        check(n == out.size)
        return out
    }

    fun aeadOpen(key: ByteArray, nonce: ByteArray, aad: ByteArray, sealed: ByteArray): CryptoResult<ByteArray> {
        if (key.size != KEY_SIZE || nonce.size != NONCE_SIZE) {
            return CryptoResult.Err(CryptoError.InvalidKeyMaterial("bad AEAD key/nonce size"))
        }
        if (sealed.size < TAG_SIZE) return CryptoResult.Err(CryptoError.AuthenticationFailed("ciphertext shorter than tag"))
        val c = ChaCha20Poly1305()
        c.init(false, AEADParameters(KeyParameter(key), TAG_SIZE * 8, nonce, aad))
        val out = ByteArray(c.getOutputSize(sealed.size))
        return try {
            var n = c.processBytes(sealed, 0, sealed.size, out, 0)
            n += c.doFinal(out, n)
            CryptoResult.Ok(if (n == out.size) out else out.copyOf(n).also { out.zeroize() })
        } catch (_: org.bouncycastle.crypto.InvalidCipherTextException) {
            out.zeroize()
            CryptoResult.Err(CryptoError.AuthenticationFailed())
        }
    }

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    // ---------------------------------- Encoding --------------------------------------

    fun b64url(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    fun b64urlDecode(text: String): ByteArray? = try {
        if (text.length > 4096 || text.any { !(it.isLetterOrDigit() || it == '-' || it == '_') }) null
        else Base64.getUrlDecoder().decode(text)
    } catch (_: IllegalArgumentException) {
        null
    }

    /** Human-comparable identity fingerprint: "zcp1:" + first 20 bytes of SHA-256(pub) as hex groups. */
    fun fingerprint(identityPublicKey: ByteArray): String {
        val h = sha256("ZCP1-FP".toByteArray(), identityPublicKey)
        val hex = h.copyOf(20).joinToString("") { "%02x".format(it) }
        return "zcp1:" + hex.chunked(8).joinToString("-")
    }
}

// ------------------------------------------------------------------------------------------
// Anti-replay sliding window (RFC 4303 §3.4.3 style bitmask, 256 entries)
// ------------------------------------------------------------------------------------------

/**
 * Tracks the highest authenticated sequence number and a 256-bit bitmap of recently seen
 * sequence numbers below it. [check] is side-effect free and is called BEFORE decryption to
 * cheaply drop obvious replays; [commit] is called only AFTER the AEAD tag verified, so an
 * attacker cannot poison the window with forged frames.
 */
class ReplayWindow(val size: Int = 256) {
    init { require(size % 64 == 0 && size in 64..4096) }

    private val words = LongArray(size / 64)
    private var highest = -1L  // unsigned compare not needed: we cap sequences at 2^62

    sealed interface Verdict {
        data object Fresh : Verdict
        data object Duplicate : Verdict
        data object TooOld : Verdict
    }

    @Synchronized
    fun check(seq: Long): Verdict {
        if (seq < 0) return Verdict.TooOld
        if (seq > highest) return Verdict.Fresh
        val diff = highest - seq
        if (diff >= size) return Verdict.TooOld
        return if (bit(diff.toInt())) Verdict.Duplicate else Verdict.Fresh
    }

    @Synchronized
    fun commit(seq: Long) {
        when (check(seq)) {
            Verdict.Fresh -> Unit
            else -> throw CryptoError.ReplayDetected(seq)
        }
        if (seq > highest) {
            val shift = if (highest < 0) size.toLong() else seq - highest
            shiftLeft(shift)
            highest = seq
            setBit(0)
        } else {
            setBit((highest - seq).toInt())
        }
    }

    @Synchronized
    fun highestAccepted(): Long = highest

    // Bit i means "sequence (highest - i) has been seen".
    private fun bit(i: Int): Boolean = (words[i ushr 6] ushr (i and 63)) and 1L == 1L
    private fun setBit(i: Int) { words[i ushr 6] = words[i ushr 6] or (1L shl (i and 63)) }

    private fun shiftLeft(by: Long) {
        if (by >= size) { words.fill(0); return }
        val n = by.toInt()
        val wordShift = n ushr 6
        val bitShift = n and 63
        for (w in words.indices.reversed()) {
            val src = w - wordShift
            var v = if (src >= 0) words[src] shl bitShift else 0L
            if (bitShift != 0 && src - 1 >= 0) v = v or (words[src - 1] ushr (64 - bitShift))
            words[w] = v
        }
    }
}

// ------------------------------------------------------------------------------------------
// Transport cipher (one per direction), produced by the Noise Split()
// ------------------------------------------------------------------------------------------

/**
 * ChaCha20-Poly1305 with explicit 64-bit sequence numbers carried in the ZCP1 header.
 * The nonce is the Noise encoding of the sequence number; the 34-byte header is the AAD.
 * Sending sequence numbers are strictly monotonic and start at [firstSequence] so they never
 * collide with the handshake frame numbers (0..2) that used different keys anyway.
 */
class TransportCipher internal constructor(
    private val key: SecretBytes,
    firstSequence: Long,
    private val replay: ReplayWindow = ReplayWindow(),
) : AutoCloseable {
    private var nextSend = firstSequence

    /** Reserves the next outbound sequence number. */
    @Synchronized
    fun reserveSequence(): Long {
        if (nextSend >= MAX_SEQUENCE) throw CryptoError.NonceExhausted()
        return nextSend++
    }

    fun seal(sequence: Long, headerAad: ByteArray, plaintext: ByteArray): ByteArray =
        CryptoEngine.aeadSeal(key.unsafeView(), CryptoEngine.noiseNonce(sequence), headerAad, plaintext)

    fun open(sequence: Long, headerAad: ByteArray, sealed: ByteArray): CryptoResult<ByteArray> {
        if (sequence >= MAX_SEQUENCE) return CryptoResult.Err(CryptoError.NonceExhausted())
        when (replay.check(sequence)) {
            ReplayWindow.Verdict.Fresh -> Unit
            else -> return CryptoResult.Err(CryptoError.ReplayDetected(sequence))
        }
        val r = CryptoEngine.aeadOpen(key.unsafeView(), CryptoEngine.noiseNonce(sequence), headerAad, sealed)
        if (r is CryptoResult.Ok) {
            try {
                replay.commit(sequence)
            } catch (e: CryptoError.ReplayDetected) {
                // Two concurrent decrypts of the same frame: the second loses.
                r.value.zeroize()
                return CryptoResult.Err(e)
            }
        }
        return r
    }

    val isWiped: Boolean get() = key.isWiped

    override fun close() = key.close()

    companion object {
        /** Hard cap well below 2^64-1 (reserved by Noise). Reaching it forces teardown. */
        const val MAX_SEQUENCE: Long = 1L shl 48
    }
}

// ------------------------------------------------------------------------------------------
// Identity endorsement of a rotating Noise static key
// ------------------------------------------------------------------------------------------

/**
 * Binds a short-lived X25519 Noise static key to the long-term Ed25519 identity:
 *   version(1)=1 | identityPub(32) | staticPub(32) | notBefore(8) | notAfter(8) | sig(64)  = 145 bytes
 *   sig = Ed25519(identity, "ZCP1-ENDORSE-v1" || identityPub || staticPub || notBefore || notAfter)
 */
class IdentityEndorsement(
    identityPublicKey: ByteArray,
    staticPublicKey: ByteArray,
    val notBeforeMillis: Long,
    val notAfterMillis: Long,
    signature: ByteArray,
) {
    private val idPub = identityPublicKey.copyOf()
    private val stPub = staticPublicKey.copyOf()
    private val sig = signature.copyOf()

    val identityPublicKey: ByteArray get() = idPub.copyOf()
    val staticPublicKey: ByteArray get() = stPub.copyOf()

    fun encode(): ByteArray = ByteBuffer.allocate(ENCODED_SIZE)
        .put(VERSION).put(idPub).put(stPub).putLong(notBeforeMillis).putLong(notAfterMillis).put(sig).array()

    fun verify(expectedStatic: ByteArray, nowMillis: Long, skewMillis: Long = 60_000): CryptoResult<Unit> {
        if (!CryptoEngine.constantTimeEquals(stPub, expectedStatic)) {
            return CryptoResult.Err(CryptoError.EndorsementInvalid("endorsed static key does not match Noise static key"))
        }
        if (notAfterMillis <= notBeforeMillis || notAfterMillis - notBeforeMillis > MAX_VALIDITY_MILLIS) {
            return CryptoResult.Err(CryptoError.EndorsementInvalid("endorsement validity window invalid"))
        }
        if (nowMillis + skewMillis < notBeforeMillis || nowMillis - skewMillis > notAfterMillis) {
            return CryptoResult.Err(CryptoError.EndorsementInvalid("endorsement expired or not yet valid"))
        }
        if (!CryptoEngine.ed25519Verify(idPub, signingInput(idPub, stPub, notBeforeMillis, notAfterMillis), sig)) {
            return CryptoResult.Err(CryptoError.SignatureInvalid("endorsement signature invalid"))
        }
        return CryptoResult.Ok(Unit)
    }

    companion object {
        const val VERSION: Byte = 1
        const val ENCODED_SIZE = 1 + 32 + 32 + 8 + 8 + 64
        const val MAX_VALIDITY_MILLIS = 30L * 60_000
        private val DOMAIN = "ZCP1-ENDORSE-v1".toByteArray()

        fun signingInput(idPub: ByteArray, stPub: ByteArray, nb: Long, na: Long): ByteArray =
            ByteBuffer.allocate(DOMAIN.size + 32 + 32 + 16).put(DOMAIN).put(idPub).put(stPub).putLong(nb).putLong(na).array()

        fun issue(signer: IdentitySigner, staticPublicKey: ByteArray, notBefore: Long, notAfter: Long): IdentityEndorsement {
            val idPub = signer.publicKey
            val sig = signer.sign(signingInput(idPub, staticPublicKey, notBefore, notAfter))
            require(CryptoEngine.ed25519Verify(idPub, signingInput(idPub, staticPublicKey, notBefore, notAfter), sig)) {
                "identity signer produced a signature that does not verify (encoding mismatch?)"
            }
            return IdentityEndorsement(idPub, staticPublicKey, notBefore, notAfter, sig)
        }

        fun decode(bytes: ByteArray): IdentityEndorsement? {
            if (bytes.size != ENCODED_SIZE || bytes[0] != VERSION) return null
            val bb = ByteBuffer.wrap(bytes, 1, ENCODED_SIZE - 1)
            val id = ByteArray(32).also { bb.get(it) }
            val st = ByteArray(32).also { bb.get(it) }
            val nb = bb.long
            val na = bb.long
            val sig = ByteArray(64).also { bb.get(it) }
            return IdentityEndorsement(id, st, nb, na, sig)
        }
    }
}

// ------------------------------------------------------------------------------------------
// Rotating Noise static key / discovery beacon (anti-tracking)
// ------------------------------------------------------------------------------------------

/**
 * Snapshot of the current rotation epoch. Handshakes take a [duplicate] of the private key so
 * that rotation (which wipes the old epoch) never breaks an in-flight session.
 */
class RotatingStatic internal constructor(
    val keyPair: X25519KeyPair,
    val endorsement: IdentityEndorsement,
    /** 8 random bytes advertised as the BLE/Nearby endpoint name; unlinkable across epochs. */
    val beaconToken: String,
    val epochStartMillis: Long,
    val epochEndMillis: Long,
) : AutoCloseable {
    fun duplicatePrivate(): SecretBytes = keyPair.privateKey.duplicate()
    override fun close() = keyPair.close()
}

class StaticKeyRotator(
    private val identity: IdentitySigner,
    private val clock: () -> Long,
    private val rotationMillis: Long = 15L * 60_000,
    private val graceMillis: Long = 5L * 60_000,
) : AutoCloseable {
    private var current: RotatingStatic? = null

    /** Returns the active epoch, rotating (and wiping the previous key) if it has expired. */
    @Synchronized
    fun current(): RotatingStatic {
        val now = clock()
        val c = current
        if (c != null && now < c.epochEndMillis) return c
        c?.close()
        val kp = CryptoEngine.generateX25519()
        val endorsement = IdentityEndorsement.issue(identity, kp.publicKey, now - 30_000, now + rotationMillis + graceMillis)
        val token = CryptoEngine.randomBytes(8).joinToString("") { "%02x".format(it) }
        return RotatingStatic(kp, endorsement, "zcp-$token", now, now + rotationMillis).also { current = it }
    }

    @Synchronized
    fun forceRotate(): RotatingStatic {
        current?.close()
        current = null
        return current()
    }

    @Synchronized
    override fun close() {
        current?.close()
        current = null
    }
}
