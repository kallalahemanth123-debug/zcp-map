package dev.zcpmap.protocol

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class WireProtocolCodecTest {
    private val codec = WireProtocolCodec()
    private val sid = SessionId.random { n -> ByteArray(n) { (it * 7 + 3).toByte() } }

    private fun frame(type: FrameType, seq: Long, payload: ByteArray) =
        WireFrame(FrameHeader(WireConstants.PROTOCOL_VERSION, type, sid, seq, payload.size), payload, ByteArray(16) { 0x5A })

    @Test
    fun headerLayoutIsExact() {
        val f = frame(FrameType.PAYLOAD_CHUNK, 0x0102030405060708L, byteArrayOf(9, 9, 9))
        val bytes = codec.encode(f)
        assertEquals(34 + 3 + 16, bytes.size)
        assertContentEquals(byteArrayOf(0x5A, 0x43, 0x50, 0x31), bytes.copyOfRange(0, 4))
        assertEquals(0x01, bytes[4].toInt())
        assertEquals(0x05, bytes[5].toInt())
        assertContentEquals(sid.toByteArray(), bytes.copyOfRange(6, 22))
        assertContentEquals(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8), bytes.copyOfRange(22, 30))
        assertContentEquals(byteArrayOf(0, 0, 0, 3), bytes.copyOfRange(30, 34))
        assertEquals(4, sid.toUuid().version())
    }

    @Test
    fun roundTripAndSecurityAbortCode() {
        val f = frame(FrameType.SECURITY_ABORT, Long.MAX_VALUE, ByteArray(0))
        val r = codec.decodeDatagram(codec.encode(f))
        assertIs<DecodeResult.Frame>(r)
        assertEquals(FrameType.SECURITY_ABORT, r.frame.header.type)
        assertEquals(Long.MAX_VALUE, r.frame.header.sequence)
    }

    @Test
    fun rejectsMalformed() {
        val good = codec.encode(frame(FrameType.HEARTBEAT_ACK, 7, byteArrayOf(1)))
        assertEquals(MalformedReason.BAD_MAGIC, (codec.decodeDatagram(good.copyOf().also { it[0] = 0 }) as DecodeResult.Malformed).reason)
        assertEquals(MalformedReason.UNSUPPORTED_VERSION, (codec.decodeDatagram(good.copyOf().also { it[4] = 2 }) as DecodeResult.Malformed).reason)
        assertEquals(MalformedReason.UNKNOWN_FRAME_TYPE, (codec.decodeDatagram(good.copyOf().also { it[5] = 0x07 }) as DecodeResult.Malformed).reason)
        assertEquals(MalformedReason.TRAILING_GARBAGE, (codec.decodeDatagram(good + byteArrayOf(0)) as DecodeResult.Malformed).reason)
        assertEquals(MalformedReason.TRUNCATED, (codec.decodeDatagram(good.copyOf(good.size - 1)) as DecodeResult.Malformed).reason)
        val huge = good.copyOf().also { it[30] = 0x7F }
        assertEquals(MalformedReason.PAYLOAD_TOO_LARGE, (codec.decodeDatagram(huge) as DecodeResult.Malformed).reason)
    }

    @Test
    fun streamDecoderHandlesArbitrarySplits() {
        val frames = (0 until 20).map { frame(FrameType.PAYLOAD_CHUNK, it.toLong(), ByteArray(it * 37) { b -> b.toByte() }) }
        val stream = frames.map { codec.encode(it) }.reduce { a, b -> a + b }
        val dec = StreamFrameDecoder(codec, WireConstants.NEARBY_MAX_PAYLOAD)
        val out = ArrayList<WireFrame>()
        var pos = 0
        var step = 1
        while (pos < stream.size) {
            val n = minOf(step, stream.size - pos)
            val r = dec.feed(stream, pos, n)
            assertIs<StreamFrameDecoder.Output.Frames>(r)
            out += r.frames
            pos += n
            step = (step * 3 + 1) % 97 + 1
        }
        assertEquals(20, out.size)
        out.forEachIndexed { i, f -> assertEquals(i.toLong(), f.header.sequence); assertEquals(i * 37, f.header.payloadLength) }
    }

    @Test
    fun handshakeSequenceValidation() {
        val v = FrameSequenceValidator(sid)
        val h0 = FrameHeader(1, FrameType.HANDSHAKE, sid, 0, 32)
        assertIs<FrameSequenceValidator.Verdict.Accept>(v.check(h0))
        v.advanceHandshake()
        assertIs<FrameSequenceValidator.Verdict.Reject>(v.check(h0))
        val other = SessionId.random { n -> ByteArray(n) { 1 } }
        assertIs<FrameSequenceValidator.Verdict.Reject>(v.check(FrameHeader(1, FrameType.HEARTBEAT_ACK, other, 5, 0)))
    }

    @Test
    fun merkleProofsVerifyForEveryShape() {
        for (n in 1..40) {
            val chunks = List(n) { i -> ByteArray(10 + i) { (i * 31 + it).toByte() } }
            val tree = MerkleTree.fromChunks(chunks)
            for (i in 0 until n) {
                val proof = tree.proof(i)
                assertEquals(MerkleTree.expectedProofLength(i, n), proof.size)
                assertEquals(MerkleVerdict.Valid, MerkleVerifier.verifyChunk(tree.root, n, i, chunks[i], proof))
                val tampered = chunks[i].copyOf().also { it[0] = (it[0] + 1).toByte() }
                assertIs<MerkleVerdict.Invalid>(MerkleVerifier.verifyChunk(tree.root, n, i, tampered, proof))
                if (n > 1) {
                    assertIs<MerkleVerdict.Invalid>(MerkleVerifier.verifyChunk(tree.root, n, (i + 1) % n, chunks[i], proof))
                }
            }
        }
    }

    @Test
    fun merkleRejectsDuplicatedLastLeafAmbiguity() {
        val a = List(3) { ByteArray(4) { b -> (it + b).toByte() } }
        val b = a + listOf(a[2])
        assertTrue(!MerkleTree.fromChunks(a).root.contentEquals(MerkleTree.fromChunks(b).root))
    }

    @Test
    fun chunkAndAckBodiesRoundTrip() {
        val tid = ByteArray(16) { it.toByte() }
        val body = ChunkBody(tid, 3, 9, listOf(ByteArray(32) { 1 }, ByteArray(32) { 2 }), ByteArray(100) { 7 })
        val back = ChunkBody.decode(body.encode())!!
        assertEquals(3, back.chunkIndex); assertEquals(9, back.chunkCount); assertEquals(2, back.proof.size)
        assertEquals(null, ChunkBody.decode(body.encode() + byteArrayOf(0)))
        assertEquals(AckBody.ChunkAck(tid, 4), AckBody.decode(AckBody.ChunkAck(tid, 4).encode()))
        assertEquals(AckBody.Heartbeat(99), AckBody.decode(AckBody.Heartbeat(99).encode()))
    }
}

class SessionLifecycleTest {
    @Test
    fun happyPathReachesSettlementAndLoops() {
        var s: LifecycleState = LifecycleState.Idle
        fun go(e: LifecycleEvent) { val t = SessionLifecycle.transition(s, e, 0); assertIs<Transition.Moved>(t); s = t.next }
        go(LifecycleEvent.PeerDiscovered("ep"))
        go(LifecycleEvent.LinkEstablished(HandshakeRole.INITIATOR))
        go(LifecycleEvent.NoiseCompleted)
        go(LifecycleEvent.DistanceBoundVerified(1.2))
        go(LifecycleEvent.ManifestVerified("fp"))
        assertEquals(1.2, (s as LifecycleState.AttestationVerified).boundDistanceMeters)
        go(LifecycleEvent.ContractOpened("c1"))
        go(LifecycleEvent.ContractAccepted("c1"))
        go(LifecycleEvent.SettlementSigned("c1", "aa"))
        go(LifecycleEvent.ContractOpened("c2"))
        assertEquals(LifecyclePhase.AGENT_NEGOTIATING, s.phase)
    }

    @Test
    fun illegalEventsFailClosed() {
        val t = SessionLifecycle.transition(LifecycleState.Idle, LifecycleEvent.ContractOpened("x"), 0)
        assertIs<Transition.Violation>(t)
        assertEquals(TeardownReason.PROTOCOL_VIOLATION, t.next.reason)
        val hs = LifecycleState.NoiseHandshake(HandshakeRole.RESPONDER, HandshakeSubPhase.NOISE_EXCHANGE, 0)
        assertIs<Transition.Violation>(SessionLifecycle.transition(hs, LifecycleEvent.ManifestVerified("fp"), 0))
        val neg = LifecycleState.AgentNegotiating("fp", setOf("a"), 0)
        assertIs<Transition.Violation>(SessionLifecycle.transition(neg, LifecycleEvent.ContractAccepted("b"), 0))
        val td = SessionLifecycle.transition(neg, LifecycleEvent.SecurityViolation(TeardownReason.REPLAY_DETECTED, "r"), 0)
        assertEquals(LifecyclePhase.TEARDOWN, td.next.phase)
        assertIs<Transition.Stayed>(SessionLifecycle.transition(td.next, LifecycleEvent.NoiseCompleted, 0))
    }

    @Test
    fun deadlinesExpire() {
        val s = LifecycleState.NoiseHandshake(HandshakeRole.INITIATOR, HandshakeSubPhase.NOISE_EXCHANGE, 1_000)
        assertTrue(!SessionLifecycle.isExpired(s, 5_000))
        assertTrue(SessionLifecycle.isExpired(s, 20_000))
    }
}

class StrictJsonTest {
    @Test
    fun rejectsDuplicateKeysAndGarbage() {
        val bad = listOf("{\"a\":1,\"a\":2}", "{\"a\":1} x", "{\"a\":NaN}", "{\"a\":\"\\ud800\"}", "[1,]", "{\"a\":01}")
        bad.forEach { b -> kotlin.test.assertFailsWith<StrictJsonException> { StrictJsonParser.parse(b) } }
    }

    @Test
    fun canonicalFormSortsKeysAndRejectsFloats() {
        val o = StrictJsonParser.parseObject("{\"b\":1,\"a\":[true,null,\"x\\n\"],\"A\":-3}")
        assertEquals("{\"A\":-3,\"a\":[true,null,\"x\\n\"],\"b\":1}", CanonicalJson.encode(o))
        kotlin.test.assertFailsWith<StrictJsonException> { CanonicalJson.encode(StrictJsonParser.parse("{\"f\":1.5}")) }
    }

    @Test
    fun schemaIsClosedAndTyped() {
        val schema = JsonSchema.Obj(
            mapOf("n" to JsonSchema.Integer(minimum = 1, maximum = 3), "s" to JsonSchema.Str(pattern = Regex("^[a-z]+$"), maxLength = 5)),
            setOf("n"),
        )
        assertEquals(SchemaResult.Valid, SchemaValidator.validate(schema, StrictJsonParser.parse("{\"n\":2,\"s\":\"ab\"}")))
        assertIs<SchemaResult.Invalid>(SchemaValidator.validate(schema, StrictJsonParser.parse("{\"n\":2,\"x\":1}")))
        assertIs<SchemaResult.Invalid>(SchemaValidator.validate(schema, StrictJsonParser.parse("{\"n\":\"2\"}")))
        assertIs<SchemaResult.Invalid>(SchemaValidator.validate(schema, StrictJsonParser.parse("{\"n\":4}")))
        assertIs<SchemaResult.Invalid>(SchemaValidator.validate(schema, StrictJsonParser.parse("{\"n\":1,\"s\":\"AB\"}")))
        assertIs<SchemaResult.Invalid>(SchemaValidator.validate(schema, StrictJsonParser.parse("{\"n\":1.0}")))
    }
}
