package dev.zcpmap.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.UUID

/*
 * ZCP1 binary wire format (all integers big-endian):
 *
 *   offset  size  field
 *   0       4     magic            0x5A 0x43 0x50 0x31 ("ZCP1")
 *   4       1     protocol version 0x01
 *   5       1     frame type
 *   6       16    session id       (UUIDv4, RFC 4122 byte order)
 *   22      8     sequence number  (unsigned 64-bit)
 *   30      4     payload length N (unsigned 32-bit, ciphertext bytes, EXCLUDING the tag)
 *   34      N     ciphertext payload
 *   34+N    16    auth tag         (Poly1305)
 *
 * For every frame that travels after the Noise handshake, the 34-byte header is the
 * AEAD associated data, so any bit flip in magic/version/type/session/sequence/length
 * fails authentication. The sequence number is also the AEAD nonce counter.
 *
 * HANDSHAKE frames carry a raw Noise XX message M. The codec stores M as
 * payload = M[0 until |M|-16] and tag = M[|M|-16 until |M|]. For Noise messages 2 and 3
 * the trailing 16 bytes are literally the Poly1305 tag over the encrypted handshake
 * payload. Message 1 (an ephemeral public key) is unauthenticated by Noise design; it
 * is authenticated retroactively because the transcript hash covers it.
 */

object WireConstants {
    val MAGIC: ByteArray = byteArrayOf(0x5A, 0x43, 0x50, 0x31)
    const val PROTOCOL_VERSION: Byte = 0x01
    const val HEADER_SIZE: Int = 34
    const val TAG_SIZE: Int = 16
    const val SESSION_ID_SIZE: Int = 16

    /** Nearby Connections BYTES payloads are capped at 32 768 bytes per payload. */
    const val NEARBY_MAX_FRAME: Int = 32_768
    const val NEARBY_MAX_PAYLOAD: Int = NEARBY_MAX_FRAME - HEADER_SIZE - TAG_SIZE

    /** Hard upper bound for any transport (Wi-Fi Aware stream). Prevents memory-exhaustion DoS. */
    const val ABSOLUTE_MAX_PAYLOAD: Int = 1 shl 20
}

enum class FrameType(val code: Byte) {
    HANDSHAKE(0x01),
    UWB_BIND(0x02),
    CAPABILITY_MANIFEST(0x03),
    AGENT_PROPOSAL(0x04),
    PAYLOAD_CHUNK(0x05),
    HEARTBEAT_ACK(0x06),
    SECURITY_ABORT(0xFF.toByte());

    companion object {
        fun fromCode(code: Byte): FrameType? = entries.firstOrNull { it.code == code }
    }
}

/** 16-byte session identifier. Immutable: the backing array is defensively copied. */
class SessionId private constructor(private val bytes: ByteArray) {
    init {
        require(bytes.size == WireConstants.SESSION_ID_SIZE) { "session id must be 16 bytes" }
    }

    fun toByteArray(): ByteArray = bytes.copyOf()

    fun toUuid(): UUID {
        val bb = ByteBuffer.wrap(bytes)
        return UUID(bb.long, bb.long)
    }

    override fun equals(other: Any?): Boolean =
        other is SessionId && MessageDigest.isEqual(bytes, other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()
    override fun toString(): String = toUuid().toString()

    companion object {
        fun of(bytes: ByteArray): SessionId = SessionId(bytes.copyOf())

        fun fromUuid(uuid: UUID): SessionId {
            val bb = ByteBuffer.allocate(16)
            bb.putLong(uuid.mostSignificantBits)
            bb.putLong(uuid.leastSignificantBits)
            return SessionId(bb.array())
        }

        /** Generates an RFC 4122 version-4 UUID from the supplied CSPRNG output. */
        fun random(randomBytes: (Int) -> ByteArray): SessionId {
            val b = randomBytes(16)
            require(b.size == 16)
            b[6] = ((b[6].toInt() and 0x0F) or 0x40).toByte()  // version 4
            b[8] = ((b[8].toInt() and 0x3F) or 0x80).toByte()  // IETF variant
            return SessionId(b)
        }

        fun parse(text: String): SessionId = fromUuid(UUID.fromString(text))
    }
}

data class FrameHeader(
    val version: Byte,
    val type: FrameType,
    val sessionId: SessionId,
    /** Unsigned 64-bit value carried in a Long; compare with [java.lang.Long.compareUnsigned]. */
    val sequence: Long,
    val payloadLength: Int,
) {
    init {
        require(payloadLength >= 0) { "payload length must be non-negative" }
    }
}

class WireFrame(
    val header: FrameHeader,
    payload: ByteArray,
    tag: ByteArray,
) {
    private val payloadBytes: ByteArray = payload.copyOf()
    private val tagBytes: ByteArray = tag.copyOf()

    init {
        require(payloadBytes.size == header.payloadLength) {
            "payload length mismatch: header=${header.payloadLength} actual=${payloadBytes.size}"
        }
        require(tagBytes.size == WireConstants.TAG_SIZE) { "tag must be 16 bytes" }
    }

    val payload: ByteArray get() = payloadBytes.copyOf()
    val tag: ByteArray get() = tagBytes.copyOf()

    /** Ciphertext||tag as consumed by an AEAD decrypt call. */
    fun sealedBody(): ByteArray = payloadBytes + tagBytes

    val encodedSize: Int get() = WireConstants.HEADER_SIZE + payloadBytes.size + WireConstants.TAG_SIZE
}

sealed interface DecodeResult {
    data class Frame(val frame: WireFrame, val consumed: Int) : DecodeResult
    data object NeedMoreData : DecodeResult
    data class Malformed(val reason: MalformedReason, val detail: String) : DecodeResult
}

enum class MalformedReason {
    BAD_MAGIC,
    UNSUPPORTED_VERSION,
    UNKNOWN_FRAME_TYPE,
    PAYLOAD_TOO_LARGE,
    TRAILING_GARBAGE,
    TRUNCATED,
    SEQUENCE_VIOLATION,
}

class WireProtocolCodec(
    private val maxPayload: Int = WireConstants.NEARBY_MAX_PAYLOAD,
) {
    init {
        require(maxPayload in 0..WireConstants.ABSOLUTE_MAX_PAYLOAD)
    }

    /** Encodes only the 34-byte header. This exact byte string is the AEAD associated data. */
    fun encodeHeader(header: FrameHeader): ByteArray {
        require(header.payloadLength <= maxPayload) { "payload ${header.payloadLength} exceeds $maxPayload" }
        val bb = ByteBuffer.allocate(WireConstants.HEADER_SIZE).order(ByteOrder.BIG_ENDIAN)
        bb.put(WireConstants.MAGIC)
        bb.put(header.version)
        bb.put(header.type.code)
        bb.put(header.sessionId.toByteArray())
        bb.putLong(header.sequence)
        bb.putInt(header.payloadLength)
        return bb.array()
    }

    fun encode(frame: WireFrame): ByteArray {
        val out = ByteBuffer.allocate(frame.encodedSize).order(ByteOrder.BIG_ENDIAN)
        out.put(encodeHeader(frame.header))
        out.put(frame.payload)
        out.put(frame.tag)
        return out.array()
    }

    /**
     * Decodes exactly one frame from a datagram-style payload (e.g. one Nearby BYTES payload).
     * Any byte beyond the frame is rejected as TRAILING_GARBAGE, so a single datagram can
     * never smuggle a second, unvalidated frame.
     */
    fun decodeDatagram(bytes: ByteArray): DecodeResult =
        when (val r = decodeFrom(bytes, 0, bytes.size)) {
            is DecodeResult.Frame ->
                if (r.consumed != bytes.size) {
                    DecodeResult.Malformed(MalformedReason.TRAILING_GARBAGE, "${bytes.size - r.consumed} trailing bytes")
                } else r
            DecodeResult.NeedMoreData ->
                DecodeResult.Malformed(MalformedReason.TRUNCATED, "datagram of ${bytes.size} bytes is not a full frame")
            is DecodeResult.Malformed -> r
        }

    /** Stream-oriented decode starting at [offset] within the first [length] bytes of [buf]. */
    fun decodeFrom(buf: ByteArray, offset: Int, length: Int): DecodeResult {
        val available = length - offset
        if (available < WireConstants.HEADER_SIZE) {
            // Validate the magic bytes we already have so garbage is rejected early.
            for (i in 0 until minOf(available, 4)) {
                if (buf[offset + i] != WireConstants.MAGIC[i]) {
                    return DecodeResult.Malformed(MalformedReason.BAD_MAGIC, "bad magic at byte $i")
                }
            }
            return DecodeResult.NeedMoreData
        }
        val bb = ByteBuffer.wrap(buf, offset, available).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(4).also { bb.get(it) }
        if (!magic.contentEquals(WireConstants.MAGIC)) {
            return DecodeResult.Malformed(MalformedReason.BAD_MAGIC, "magic=${magic.toHex()}")
        }
        val version = bb.get()
        if (version != WireConstants.PROTOCOL_VERSION) {
            return DecodeResult.Malformed(MalformedReason.UNSUPPORTED_VERSION, "version=$version")
        }
        val typeCode = bb.get()
        val type = FrameType.fromCode(typeCode)
            ?: return DecodeResult.Malformed(MalformedReason.UNKNOWN_FRAME_TYPE, "type=0x%02x".format(typeCode))
        val sid = ByteArray(16).also { bb.get(it) }
        val seq = bb.long
        val lenUnsigned = bb.int.toLong() and 0xFFFF_FFFFL
        if (lenUnsigned > maxPayload) {
            return DecodeResult.Malformed(MalformedReason.PAYLOAD_TOO_LARGE, "length=$lenUnsigned max=$maxPayload")
        }
        val len = lenUnsigned.toInt()
        val total = WireConstants.HEADER_SIZE + len + WireConstants.TAG_SIZE
        if (available < total) return DecodeResult.NeedMoreData
        val payload = ByteArray(len).also { bb.get(it) }
        val tag = ByteArray(WireConstants.TAG_SIZE).also { bb.get(it) }
        val header = FrameHeader(version, type, SessionId.of(sid), seq, len)
        return DecodeResult.Frame(WireFrame(header, payload, tag), total)
    }

    companion object {
        /** Splits a raw Noise handshake message into (payload, tag) per the ZCP1 convention. */
        fun splitHandshakeMessage(noiseMessage: ByteArray): Pair<ByteArray, ByteArray> {
            require(noiseMessage.size >= WireConstants.TAG_SIZE) { "noise message shorter than 16 bytes" }
            val cut = noiseMessage.size - WireConstants.TAG_SIZE
            return noiseMessage.copyOfRange(0, cut) to noiseMessage.copyOfRange(cut, noiseMessage.size)
        }
    }
}

/**
 * Incremental decoder for byte streams (Wi-Fi Aware TCP sockets). Buffers partial frames,
 * rejects anything malformed and never grows beyond one maximum-size frame.
 */
class StreamFrameDecoder(private val codec: WireProtocolCodec, maxPayload: Int) {
    private val capacity = WireConstants.HEADER_SIZE + maxPayload + WireConstants.TAG_SIZE
    private val buffer = ByteArray(capacity)
    private var filled = 0

    sealed interface Output {
        data class Frames(val frames: List<WireFrame>) : Output
        data class Fatal(val reason: MalformedReason, val detail: String) : Output
    }

    fun feed(data: ByteArray, off: Int = 0, len: Int = data.size): Output {
        val frames = ArrayList<WireFrame>(2)
        var srcPos = off
        val srcEnd = off + len
        while (srcPos < srcEnd) {
            val take = minOf(capacity - filled, srcEnd - srcPos)
            System.arraycopy(data, srcPos, buffer, filled, take)
            filled += take
            srcPos += take
            var consumedTotal = 0
            while (true) {
                when (val r = codec.decodeFrom(buffer, consumedTotal, filled)) {
                    is DecodeResult.Frame -> {
                        frames += r.frame
                        consumedTotal += r.consumed
                    }
                    DecodeResult.NeedMoreData -> break
                    is DecodeResult.Malformed -> {
                        reset()
                        return Output.Fatal(r.reason, r.detail)
                    }
                }
            }
            if (consumedTotal > 0) {
                System.arraycopy(buffer, consumedTotal, buffer, 0, filled - consumedTotal)
                java.util.Arrays.fill(buffer, filled - consumedTotal, filled, 0)
                filled -= consumedTotal
            } else if (filled == capacity) {
                reset()
                return Output.Fatal(MalformedReason.PAYLOAD_TOO_LARGE, "frame exceeds stream buffer")
            }
        }
        return Output.Frames(frames)
    }

    fun reset() {
        java.util.Arrays.fill(buffer, 0)
        filled = 0
    }
}

/**
 * Structural sequence validation that does not need keys:
 *  - Noise handshake frames must arrive as exactly seq 0 (msg1, I->R), 1 (msg2, R->I), 2 (msg3, I->R).
 *  - All frames must belong to the bound session id once one is bound.
 * Transport-phase anti-replay (sliding bitmask window) lives in the security module because it must
 * only be updated AFTER successful AEAD authentication.
 */
class FrameSequenceValidator(private val expectedSession: SessionId) {
    sealed interface Verdict {
        data object Accept : Verdict
        data class Reject(val reason: String) : Verdict
    }

    private var nextHandshakeSeq = 0L

    fun check(header: FrameHeader): Verdict {
        if (header.sessionId != expectedSession) {
            return Verdict.Reject("session id mismatch")
        }
        if (header.type == FrameType.HANDSHAKE) {
            if (header.sequence != nextHandshakeSeq) {
                return Verdict.Reject("handshake seq ${header.sequence} expected $nextHandshakeSeq")
            }
            if (nextHandshakeSeq > 2) return Verdict.Reject("extra handshake frame")
        }
        return Verdict.Accept
    }

    /** Called after the handshake frame was accepted by the Noise state machine. */
    fun advanceHandshake() {
        nextHandshakeSeq++
    }

    fun handshakeFramesSeen(): Long = nextHandshakeSeq
}

// --------------------------------------------------------------------------------------
// Merkle tree (RFC 6962-style domain separation, odd node promotion — no duplication, so
// the CVE-2012-2459 "duplicate last leaf" ambiguity cannot occur).
//   leaf  = SHA-256(0x00 || chunk)
//   inner = SHA-256(0x01 || left || right)
// --------------------------------------------------------------------------------------

object MerkleHash {
    const val SIZE = 32
    private const val LEAF_PREFIX: Byte = 0x00
    private const val NODE_PREFIX: Byte = 0x01

    fun leaf(data: ByteArray, off: Int = 0, len: Int = data.size): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(LEAF_PREFIX)
        md.update(data, off, len)
        return md.digest()
    }

    fun node(left: ByteArray, right: ByteArray): ByteArray {
        require(left.size == SIZE && right.size == SIZE)
        val md = MessageDigest.getInstance("SHA-256")
        md.update(NODE_PREFIX)
        md.update(left)
        md.update(right)
        return md.digest()
    }
}

class MerkleTree private constructor(private val levels: List<List<ByteArray>>) {
    val leafCount: Int get() = levels[0].size
    val root: ByteArray get() = levels.last()[0].copyOf()

    /** Inclusion proof: sibling hashes from leaf level upward, skipping promoted levels. */
    fun proof(index: Int): List<ByteArray> {
        require(index in 0 until leafCount) { "leaf index $index out of range" }
        val out = ArrayList<ByteArray>()
        var idx = index
        for (level in 0 until levels.size - 1) {
            val nodes = levels[level]
            if (idx % 2 == 1) {
                out += nodes[idx - 1].copyOf()
            } else if (idx + 1 < nodes.size) {
                out += nodes[idx + 1].copyOf()
            }
            idx /= 2
        }
        return out
    }

    companion object {
        fun fromLeafHashes(leaves: List<ByteArray>): MerkleTree {
            require(leaves.isNotEmpty()) { "Merkle tree needs at least one leaf" }
            require(leaves.all { it.size == MerkleHash.SIZE })
            val levels = ArrayList<List<ByteArray>>()
            var current: List<ByteArray> = leaves.map { it.copyOf() }
            levels += current
            while (current.size > 1) {
                val next = ArrayList<ByteArray>((current.size + 1) / 2)
                var i = 0
                while (i < current.size) {
                    next += if (i + 1 < current.size) MerkleHash.node(current[i], current[i + 1]) else current[i]
                    i += 2
                }
                levels += next
                current = next
            }
            return MerkleTree(levels)
        }

        fun fromChunks(chunks: List<ByteArray>): MerkleTree = fromLeafHashes(chunks.map { MerkleHash.leaf(it) })

        /** Number of hashes a valid proof for [index] must contain; used to reject padded proofs. */
        fun expectedProofLength(index: Int, leafCount: Int): Int {
            var idx = index
            var size = leafCount
            var n = 0
            while (size > 1) {
                if (idx % 2 == 1 || idx + 1 < size) n++
                idx /= 2
                size = (size + 1) / 2
            }
            return n
        }
    }
}

sealed interface MerkleVerdict {
    data object Valid : MerkleVerdict
    data class Invalid(val reason: String) : MerkleVerdict
}

object MerkleVerifier {
    fun verifyChunk(
        root: ByteArray,
        leafCount: Int,
        index: Int,
        chunk: ByteArray,
        proof: List<ByteArray>,
    ): MerkleVerdict {
        if (root.size != MerkleHash.SIZE) return MerkleVerdict.Invalid("bad root length")
        if (leafCount <= 0) return MerkleVerdict.Invalid("leafCount must be positive")
        if (index !in 0 until leafCount) return MerkleVerdict.Invalid("index out of range")
        if (proof.any { it.size != MerkleHash.SIZE }) return MerkleVerdict.Invalid("bad proof element length")
        val expected = MerkleTree.expectedProofLength(index, leafCount)
        if (proof.size != expected) return MerkleVerdict.Invalid("proof length ${proof.size} expected $expected")

        var hash = MerkleHash.leaf(chunk)
        var idx = index
        var size = leafCount
        var p = 0
        while (size > 1) {
            if (idx % 2 == 1) {
                hash = MerkleHash.node(proof[p++], hash)
            } else if (idx + 1 < size) {
                hash = MerkleHash.node(hash, proof[p++])
            }
            idx /= 2
            size = (size + 1) / 2
        }
        return if (MessageDigest.isEqual(hash, root)) MerkleVerdict.Valid else MerkleVerdict.Invalid("root mismatch")
    }
}

// --------------------------------------------------------------------------------------
// Inner (post-decryption) binary bodies for PAYLOAD_CHUNK and HEARTBEAT_ACK frames.
// --------------------------------------------------------------------------------------

class ChunkBody(
    val transferId: ByteArray,   // 16 bytes
    val chunkIndex: Int,
    val chunkCount: Int,
    val proof: List<ByteArray>,
    val data: ByteArray,
) {
    init {
        require(transferId.size == 16)
        require(chunkCount > 0 && chunkIndex in 0 until chunkCount)
        require(proof.size <= MAX_PROOF_HASHES)
    }

    fun encode(): ByteArray {
        val size = 16 + 4 + 4 + 1 + proof.size * MerkleHash.SIZE + 4 + data.size
        val bb = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN)
        bb.put(transferId)
        bb.putInt(chunkIndex)
        bb.putInt(chunkCount)
        bb.put(proof.size.toByte())
        proof.forEach { bb.put(it) }
        bb.putInt(data.size)
        bb.put(data)
        return bb.array()
    }

    companion object {
        const val MAX_PROOF_HASHES = 40
        const val MAX_CHUNK_DATA = 24 * 1024

        fun decode(bytes: ByteArray): ChunkBody? {
            if (bytes.size < 16 + 4 + 4 + 1 + 4) return null
            val bb = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
            val tid = ByteArray(16).also { bb.get(it) }
            val index = bb.int
            val count = bb.int
            val proofCount = bb.get().toInt() and 0xFF
            if (count <= 0 || index < 0 || index >= count || proofCount > MAX_PROOF_HASHES) return null
            if (bb.remaining() < proofCount * MerkleHash.SIZE + 4) return null
            val proof = List(proofCount) { ByteArray(MerkleHash.SIZE).also { h -> bb.get(h) } }
            val dataLen = bb.int
            if (dataLen < 0 || dataLen > MAX_CHUNK_DATA || bb.remaining() != dataLen) return null
            val data = ByteArray(dataLen).also { bb.get(it) }
            return ChunkBody(tid, index, count, proof, data)
        }
    }
}

sealed interface AckBody {
    fun encode(): ByteArray

    data class Heartbeat(val monotonicMillis: Long) : AckBody {
        override fun encode(): ByteArray =
            ByteBuffer.allocate(9).put(KIND_HEARTBEAT).putLong(monotonicMillis).array()
    }

    /** Cumulative acknowledgement: every chunk index < [nextExpected] has been verified and persisted. */
    data class ChunkAck(val transferId: ByteArray, val nextExpected: Int) : AckBody {
        init { require(transferId.size == 16 && nextExpected >= 0) }
        override fun encode(): ByteArray =
            ByteBuffer.allocate(21).put(KIND_CHUNK_ACK).put(transferId).putInt(nextExpected).array()
        override fun equals(other: Any?) =
            other is ChunkAck && transferId.contentEquals(other.transferId) && nextExpected == other.nextExpected
        override fun hashCode() = transferId.contentHashCode() * 31 + nextExpected
    }

    /** Receiver refuses a chunk (bad proof / quota). Sender must abort the transfer. */
    data class ChunkNack(val transferId: ByteArray, val index: Int, val reasonCode: Byte) : AckBody {
        init { require(transferId.size == 16) }
        override fun encode(): ByteArray =
            ByteBuffer.allocate(22).put(KIND_CHUNK_NACK).put(transferId).putInt(index).put(reasonCode).array()
        override fun equals(other: Any?) =
            other is ChunkNack && transferId.contentEquals(other.transferId) && index == other.index && reasonCode == other.reasonCode
        override fun hashCode() = (transferId.contentHashCode() * 31 + index) * 31 + reasonCode
    }

    companion object {
        const val KIND_HEARTBEAT: Byte = 0
        const val KIND_CHUNK_ACK: Byte = 1
        const val KIND_CHUNK_NACK: Byte = 2

        fun decode(bytes: ByteArray): AckBody? {
            if (bytes.isEmpty()) return null
            val bb = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
            return when (bb.get()) {
                KIND_HEARTBEAT -> if (bytes.size == 9) Heartbeat(bb.long) else null
                KIND_CHUNK_ACK -> if (bytes.size == 21) {
                    val t = ByteArray(16).also { bb.get(it) }
                    val n = bb.int
                    if (n < 0) null else ChunkAck(t, n)
                } else null
                KIND_CHUNK_NACK -> if (bytes.size == 22) {
                    val t = ByteArray(16).also { bb.get(it) }
                    ChunkNack(t, bb.int, bb.get())
                } else null
                else -> null
            }
        }
    }
}

/** Abort reason codes carried in SECURITY_ABORT frames. */
enum class AbortCode(val code: Byte) {
    UNSPECIFIED(0),
    AUTHENTICATION_FAILED(1),
    REPLAY_DETECTED(2),
    DISTANCE_BOUND_EXCEEDED(3),
    ATTESTATION_INVALID(4),
    POLICY_VIOLATION(5),
    PROTOCOL_VIOLATION(6),
    TIMEOUT(7),
    RANGING_LOST(8),
    USER_TERMINATED(9),
    LOCAL_RESOURCE_EXHAUSTED(10);

    companion object {
        fun fromCode(code: Byte): AbortCode = entries.firstOrNull { it.code == code } ?: UNSPECIFIED
    }
}

fun ByteArray.toHex(): String {
    val sb = StringBuilder(size * 2)
    for (b in this) {
        val v = b.toInt() and 0xFF
        sb.append(HEX[v ushr 4]).append(HEX[v and 0x0F])
    }
    return sb.toString()
}

fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "odd hex length" }
    return ByteArray(length / 2) { i ->
        val hi = Character.digit(this[2 * i], 16)
        val lo = Character.digit(this[2 * i + 1], 16)
        require(hi >= 0 && lo >= 0) { "invalid hex" }
        ((hi shl 4) or lo).toByte()
    }
}

private val HEX = "0123456789abcdef".toCharArray()
