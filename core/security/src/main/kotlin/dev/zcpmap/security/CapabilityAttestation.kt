package dev.zcpmap.security

import dev.zcpmap.protocol.CanonicalJson
import dev.zcpmap.protocol.JsonSchema
import dev.zcpmap.protocol.SchemaResult
import dev.zcpmap.protocol.SchemaValidator
import dev.zcpmap.protocol.StrictJsonException
import dev.zcpmap.protocol.StrictJsonParser
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import java.nio.ByteBuffer
import java.util.UUID

/*
 * Capability attestation and capability-based authorization.
 *
 * 1. CapabilityManifest — a JSON-LD document signed with the long-term Ed25519 identity over its
 *    RFC 8785 canonical form. It is audience-restricted (aud = verifier's fingerprint), single-use
 *    (nonce), short-lived (exp - iat <= 10 min) and channel-bound (sessionBinding = H(handshake hash)),
 *    so a manifest captured in one session is useless in any other.
 *
 *    Hardware facts are NOT disclosed raw. Each fact is published as a coarse bucket plus a salted
 *    SHA-256 commitment to the exact value. This is selective disclosure with commitments — it is
 *    honest to call it "commit-and-bucket", not a zero-knowledge proof system: a verifier learns the
 *    bucket, and learns the exact value only if the prover later opens the commitment.
 *
 * 2. CapabilityToken — a macaroon (HMAC chain over caveats) keyed from the Noise exporter. Each
 *    accepted contract mints one least-privilege token restricting the peer to exact operations,
 *    byte and CPU budgets, path prefixes and an expiry. Holders can attenuate (add caveats) but not
 *    widen. Verification is fail-closed: an unknown caveat key invalidates the token.
 *
 * 3. SettlementReceipt — each party signs the outcome of a contract (bytes, Merkle root, result hash)
 *    bound to the session; both receipts together are the settlement.
 */

// ------------------------------------------------------------------------------------------
// Manifest model
// ------------------------------------------------------------------------------------------

enum class CapabilityAction(val wire: String) {
    COMPUTE_OFFLOAD("compute.offload"),
    DATA_SEND("data.send"),
    DATA_RECEIVE("data.receive"),
    INFERENCE_SHARD("inference.shard");

    companion object {
        fun fromWire(s: String): CapabilityAction? = entries.firstOrNull { it.wire == s }
    }
}

data class CapabilityGrant(
    val action: CapabilityAction,
    /** Logical resource namespace, always inside the local sandbox, e.g. "zcp:sandbox/inbox". */
    val resource: String,
    val maxBytes: Long,
    val maxCpuMillis: Long,
    val maxMemoryMb: Long,
) {
    fun toJson() = buildJsonObject {
        put("action", action.wire)
        put("resource", resource)
        put("maxBytes", maxBytes)
        put("maxCpuMs", maxCpuMillis)
        put("maxMemoryMb", maxMemoryMb)
    }
}

/** A bucketed hardware fact plus a commitment to the exact value. */
data class CommittedFact(val bucket: String, val commitmentB64: String) {
    companion object {
        /** Returns the public fact and the opening (salt) which stays local unless disclosed. */
        fun commit(bucket: String, exactValue: String): Pair<CommittedFact, ByteArray> {
            val salt = CryptoEngine.randomBytes(16)
            val c = CryptoEngine.sha256("ZCP1-COMMIT".toByteArray(), salt, exactValue.toByteArray())
            return CommittedFact(bucket, CryptoEngine.b64url(c)) to salt
        }

        fun open(fact: CommittedFact, exactValue: String, salt: ByteArray): Boolean {
            val c = CryptoEngine.sha256("ZCP1-COMMIT".toByteArray(), salt, exactValue.toByteArray())
            val published = CryptoEngine.b64urlDecode(fact.commitmentB64) ?: return false
            return CryptoEngine.constantTimeEquals(c, published)
        }
    }
}

data class HardwareSummary(
    val batteryBucket: String,      // "0-19" | "20-49" | "50-79" | "80-100"
    val charging: Boolean,
    val thermalBucket: String,      // "nominal" | "elevated" | "severe" | "critical"
    val storageBucket: String,      // "<1GiB" | "1-10GiB" | "10-100GiB" | ">100GiB"
    val batteryCommitment: CommittedFact,
    val storageCommitment: CommittedFact,
)

class CapabilityManifest(
    val id: String,
    val issuerPublicKey: ByteArray,
    val audienceFingerprint: String,
    val nonce: String,
    val issuedAtSeconds: Long,
    val expiresAtSeconds: Long,
    val sessionBinding: String,
    val capabilities: List<CapabilityGrant>,
    val hardware: HardwareSummary,
    val agentModel: String,
) {
    val issuerFingerprint: String get() = CryptoEngine.fingerprint(issuerPublicKey)

    fun grantFor(action: CapabilityAction): CapabilityGrant? = capabilities.firstOrNull { it.action == action }

    internal fun unsignedJson(proofCreated: Long): JsonObject = buildJsonObject {
        put("@context", buildJsonArray {
            add(JsonPrimitive("https://www.w3.org/ns/credentials/v2"))
            add(JsonPrimitive(CONTEXT_URL))
        })
        put("type", TYPE)
        put("id", id)
        put("issuer", issuerDid(issuerPublicKey))
        put("aud", audienceFingerprint)
        put("nonce", nonce)
        put("iat", issuedAtSeconds)
        put("exp", expiresAtSeconds)
        put("sessionBinding", sessionBinding)
        put("agent", buildJsonObject { put("model", agentModel); put("protocol", "ZCP1") })
        put("capabilities", JsonArray(capabilities.map { it.toJson() }))
        put("hardware", buildJsonObject {
            put("battery", hardware.batteryBucket)
            put("charging", hardware.charging)
            put("thermal", hardware.thermalBucket)
            put("storage", hardware.storageBucket)
            put("batteryCommitment", hardware.batteryCommitment.commitmentB64)
            put("storageCommitment", hardware.storageCommitment.commitmentB64)
        })
        put("proof", buildJsonObject {
            put("type", PROOF_TYPE)
            put("verificationMethod", issuerDid(issuerPublicKey))
            put("created", proofCreated)
        })
    }

    companion object {
        const val CONTEXT_URL = "https://zcp-map.dev/ns/capabilities/v1"
        const val TYPE = "ZcpCapabilityManifest"
        const val PROOF_TYPE = "ZcpEd25519JcsSignature2026"
        const val MAX_LIFETIME_SECONDS = 600L
        private val DOMAIN = "ZCP1-MANIFEST-v1\n".toByteArray()

        fun issuerDid(pub: ByteArray) = "zcp-ed25519:" + CryptoEngine.b64url(pub)

        fun sessionBinding(handshakeHash: ByteArray): String =
            CryptoEngine.b64url(CryptoEngine.sha256("ZCP1-BIND".toByteArray(), handshakeHash))

        fun create(
            signer: IdentitySigner,
            audienceFingerprint: String,
            handshakeHash: ByteArray,
            capabilities: List<CapabilityGrant>,
            hardware: HardwareSummary,
            agentModel: String,
            nowSeconds: Long,
            lifetimeSeconds: Long = 300,
        ): CapabilityManifest {
            require(lifetimeSeconds in 30..MAX_LIFETIME_SECONDS)
            require(capabilities.size in 1..8)
            return CapabilityManifest(
                id = "urn:uuid:" + UUID.randomUUID(),
                issuerPublicKey = signer.publicKey,
                audienceFingerprint = audienceFingerprint,
                nonce = CryptoEngine.b64url(CryptoEngine.randomBytes(16)),
                issuedAtSeconds = nowSeconds,
                expiresAtSeconds = nowSeconds + lifetimeSeconds,
                sessionBinding = sessionBinding(handshakeHash),
                capabilities = capabilities,
                hardware = hardware,
                agentModel = agentModel,
            )
        }

        /** Signs and returns the canonical wire JSON (UTF-8 bytes). */
        fun sign(manifest: CapabilityManifest, signer: IdentitySigner): ByteArray {
            require(CryptoEngine.constantTimeEquals(manifest.issuerPublicKey, signer.publicKey)) { "issuer/signer mismatch" }
            val unsigned = manifest.unsignedJson(manifest.issuedAtSeconds)
            val sig = signer.sign(DOMAIN + CanonicalJson.encodeToBytes(unsigned))
            val proof = unsigned.getValue("proof").jsonObject
            val signedProof = JsonObject(proof + ("proofValue" to JsonPrimitive(CryptoEngine.b64url(sig))))
            val signed = JsonObject(unsigned + ("proof" to signedProof))
            return CanonicalJson.encodeToBytes(signed)
        }

        private val B64_32 = Regex("^[A-Za-z0-9_-]{43}$")
        private val B64_64 = Regex("^[A-Za-z0-9_-]{86}$")
        private val B64_16 = Regex("^[A-Za-z0-9_-]{22}$")
        private val FP = Regex("^zcp1:[0-9a-f]{8}(-[0-9a-f]{8}){4}$")
        private val DID = Regex("^zcp-ed25519:[A-Za-z0-9_-]{43}$")

        val SCHEMA: JsonSchema.Obj = JsonSchema.Obj(
            properties = mapOf(
                "@context" to JsonSchema.Arr(JsonSchema.Str(maxLength = 128), minItems = 2, maxItems = 2),
                "type" to JsonSchema.Str(enum = listOf(TYPE)),
                "id" to JsonSchema.Str(pattern = Regex("^urn:uuid:[0-9a-f-]{36}$"), maxLength = 45),
                "issuer" to JsonSchema.Str(pattern = DID, maxLength = 64),
                "aud" to JsonSchema.Str(pattern = FP, maxLength = 64),
                "nonce" to JsonSchema.Str(pattern = B64_16, maxLength = 22),
                "iat" to JsonSchema.Integer(minimum = 0),
                "exp" to JsonSchema.Integer(minimum = 0),
                "sessionBinding" to JsonSchema.Str(pattern = B64_32, maxLength = 43),
                "agent" to JsonSchema.Obj(
                    mapOf(
                        "model" to JsonSchema.Str(pattern = Regex("^[a-z0-9.-]{1,64}$"), maxLength = 64),
                        "protocol" to JsonSchema.Str(enum = listOf("ZCP1")),
                    ),
                    setOf("model", "protocol"),
                ),
                "capabilities" to JsonSchema.Arr(
                    JsonSchema.Obj(
                        mapOf(
                            "action" to JsonSchema.Str(enum = CapabilityAction.entries.map { it.wire }),
                            "resource" to JsonSchema.Str(pattern = Regex("^zcp:sandbox/[a-z0-9_/-]{1,64}$"), maxLength = 76),
                            "maxBytes" to JsonSchema.Integer(minimum = 0, maximum = 1L shl 40),
                            "maxCpuMs" to JsonSchema.Integer(minimum = 0, maximum = 86_400_000),
                            "maxMemoryMb" to JsonSchema.Integer(minimum = 0, maximum = 65_536),
                        ),
                        setOf("action", "resource", "maxBytes", "maxCpuMs", "maxMemoryMb"),
                    ),
                    minItems = 1, maxItems = 8,
                ),
                "hardware" to JsonSchema.Obj(
                    mapOf(
                        "battery" to JsonSchema.Str(enum = listOf("0-19", "20-49", "50-79", "80-100")),
                        "charging" to JsonSchema.Bool(),
                        "thermal" to JsonSchema.Str(enum = listOf("nominal", "elevated", "severe", "critical")),
                        "storage" to JsonSchema.Str(enum = listOf("<1GiB", "1-10GiB", "10-100GiB", ">100GiB")),
                        "batteryCommitment" to JsonSchema.Str(pattern = B64_32, maxLength = 43),
                        "storageCommitment" to JsonSchema.Str(pattern = B64_32, maxLength = 43),
                    ),
                    setOf("battery", "charging", "thermal", "storage", "batteryCommitment", "storageCommitment"),
                ),
                "proof" to JsonSchema.Obj(
                    mapOf(
                        "type" to JsonSchema.Str(enum = listOf(PROOF_TYPE)),
                        "verificationMethod" to JsonSchema.Str(pattern = DID, maxLength = 64),
                        "created" to JsonSchema.Integer(minimum = 0),
                        "proofValue" to JsonSchema.Str(pattern = B64_64, maxLength = 86),
                    ),
                    setOf("type", "verificationMethod", "created", "proofValue"),
                ),
            ),
            required = setOf(
                "@context", "type", "id", "issuer", "aud", "nonce", "iat", "exp",
                "sessionBinding", "agent", "capabilities", "hardware", "proof",
            ),
        )

        /**
         * Full verification. [expectedIssuer] is the identity authenticated by the Noise handshake;
         * a manifest signed by anyone else is rejected even if its signature is valid.
         */
        fun verify(
            wire: ByteArray,
            expectedIssuer: ByteArray,
            localFingerprint: String,
            handshakeHash: ByteArray,
            nowSeconds: Long,
            replayCache: NonceReplayCache,
        ): CryptoResult<CapabilityManifest> {
            fun bad(msg: String) = CryptoResult.Err(CryptoError.SignatureInvalid("manifest rejected: $msg"))
            if (wire.size > 16 * 1024) return bad("too large")
            val doc = try {
                StrictJsonParser.parseObject(wire.toString(Charsets.UTF_8), StrictJsonParser.Limits(maxBytes = 16 * 1024))
            } catch (e: StrictJsonException) {
                return bad("json: ${e.message}")
            }
            when (val r = SchemaValidator.validate(SCHEMA, doc)) {
                is SchemaResult.Invalid -> return bad("schema ${r.path}: ${r.reason}")
                SchemaResult.Valid -> Unit
            }
            val ctx = doc.getValue("@context").jsonArray.map { it.jsonPrimitive.content }
            if (ctx != listOf("https://www.w3.org/ns/credentials/v2", CONTEXT_URL)) return bad("@context")
            val issuerDid = doc.getValue("issuer").jsonPrimitive.content
            val issuerPub = CryptoEngine.b64urlDecode(issuerDid.removePrefix("zcp-ed25519:")) ?: return bad("issuer encoding")
            if (!CryptoEngine.constantTimeEquals(issuerPub, expectedIssuer)) return bad("issuer is not the handshake-authenticated peer")
            val proof = doc.getValue("proof").jsonObject
            if (proof.getValue("verificationMethod").jsonPrimitive.content != issuerDid) return bad("verificationMethod != issuer")
            if (doc.getValue("aud").jsonPrimitive.content != localFingerprint) return bad("audience mismatch")
            if (doc.getValue("sessionBinding").jsonPrimitive.content != sessionBinding(handshakeHash)) return bad("not bound to this session")
            val iat = doc.getValue("iat").jsonPrimitive.long
            val exp = doc.getValue("exp").jsonPrimitive.long
            if (exp <= iat || exp - iat > MAX_LIFETIME_SECONDS) return bad("lifetime")
            if (iat > nowSeconds + 60) return bad("issued in the future")
            if (exp <= nowSeconds) return bad("expired")
            if (proof.getValue("created").jsonPrimitive.long != iat) return bad("proof.created != iat")

            val sig = CryptoEngine.b64urlDecode(proof.getValue("proofValue").jsonPrimitive.content) ?: return bad("proofValue encoding")
            val unsigned = JsonObject(doc + ("proof" to JsonObject(proof - "proofValue")))
            if (!CryptoEngine.ed25519Verify(issuerPub, DOMAIN + CanonicalJson.encodeToBytes(unsigned), sig)) return bad("signature")

            val nonce = doc.getValue("nonce").jsonPrimitive.content
            if (!replayCache.register(issuerDid + "|" + nonce, exp)) return bad("nonce replay")

            val caps = doc.getValue("capabilities").jsonArray.map { c ->
                val o = c.jsonObject
                CapabilityGrant(
                    action = CapabilityAction.fromWire(o.getValue("action").jsonPrimitive.content)!!,
                    resource = o.getValue("resource").jsonPrimitive.content,
                    maxBytes = o.getValue("maxBytes").jsonPrimitive.long,
                    maxCpuMillis = o.getValue("maxCpuMs").jsonPrimitive.long,
                    maxMemoryMb = o.getValue("maxMemoryMb").jsonPrimitive.long,
                )
            }
            if (caps.map { it.action }.toSet().size != caps.size) return bad("duplicate capability action")
            val hw = doc.getValue("hardware").jsonObject
            val hardware = HardwareSummary(
                batteryBucket = hw.getValue("battery").jsonPrimitive.content,
                charging = hw.getValue("charging").jsonPrimitive.content == "true",
                thermalBucket = hw.getValue("thermal").jsonPrimitive.content,
                storageBucket = hw.getValue("storage").jsonPrimitive.content,
                batteryCommitment = CommittedFact(hw.getValue("battery").jsonPrimitive.content, hw.getValue("batteryCommitment").jsonPrimitive.content),
                storageCommitment = CommittedFact(hw.getValue("storage").jsonPrimitive.content, hw.getValue("storageCommitment").jsonPrimitive.content),
            )
            return CryptoResult.Ok(
                CapabilityManifest(
                    id = doc.getValue("id").jsonPrimitive.content,
                    issuerPublicKey = issuerPub,
                    audienceFingerprint = localFingerprint,
                    nonce = nonce,
                    issuedAtSeconds = iat,
                    expiresAtSeconds = exp,
                    sessionBinding = doc.getValue("sessionBinding").jsonPrimitive.content,
                    capabilities = caps,
                    hardware = hardware,
                    agentModel = doc.getValue("agent").jsonObject.getValue("model").jsonPrimitive.content,
                ),
            )
        }
    }
}

/** Bounded single-use nonce registry with expiry-based eviction. */
class NonceReplayCache(private val capacity: Int = 4096, private val nowSeconds: () -> Long) {
    private val seen = LinkedHashMap<String, Long>()

    /** Returns false if [key] was already registered and has not expired. */
    @Synchronized
    fun register(key: String, expiresAtSeconds: Long): Boolean {
        val now = nowSeconds()
        val it = seen.entries.iterator()
        while (it.hasNext()) if (it.next().value <= now) it.remove()
        if (seen.containsKey(key)) return false
        if (seen.size >= capacity) {
            // Fail closed: refuse new registrations rather than evicting live nonces.
            return false
        }
        seen[key] = expiresAtSeconds
        return true
    }
}

// ------------------------------------------------------------------------------------------
// Capability tokens (macaroons)
// ------------------------------------------------------------------------------------------

/** Request attributes a token is evaluated against. */
data class CapabilityRequest(
    val sessionId: String,
    val audienceFingerprint: String,
    val contractId: String,
    val operation: String,
    val nowSeconds: Long,
    val bytes: Long,
    val cpuMillis: Long,
    val path: String,
)

sealed interface TokenVerdict {
    data class Authorized(val caveats: List<String>) : TokenVerdict
    data class Denied(val reason: String) : TokenVerdict
}

class CapabilityToken private constructor(
    val identifier: ByteArray,
    val caveats: List<String>,
    private val signature: ByteArray,
) {
    fun attenuate(caveat: String): CapabilityToken {
        validateCaveatSyntax(caveat)
        require(caveats.size < MAX_CAVEATS) { "too many caveats" }
        val sig = CryptoEngine.hmacSha256(signature, caveat.toByteArray())
        return CapabilityToken(identifier, caveats + caveat, sig)
    }

    fun encode(): String {
        val bb = ByteBuffer.allocate(1 + 2 + identifier.size + 1 + caveats.sumOf { 2 + it.toByteArray().size } + 32)
        bb.put(VERSION)
        bb.putShort(identifier.size.toShort()).put(identifier)
        bb.put(caveats.size.toByte())
        caveats.forEach { c -> val b = c.toByteArray(); bb.putShort(b.size.toShort()).put(b) }
        bb.put(signature)
        return CryptoEngine.b64url(bb.array())
    }

    /** Verifies the HMAC chain under [rootKey] and evaluates every caveat. Fail closed. */
    fun verify(rootKey: SecretBytes, request: CapabilityRequest): TokenVerdict {
        var sig = rootKey.withCopy { k -> CryptoEngine.hmacSha256(k, identifier) }
        for (c in caveats) {
            val next = CryptoEngine.hmacSha256(sig, c.toByteArray())
            sig.zeroize()
            sig = next
        }
        val ok = CryptoEngine.constantTimeEquals(sig, signature)
        sig.zeroize()
        if (!ok) return TokenVerdict.Denied("signature chain invalid")
        for (c in caveats) {
            val reason = evaluate(c, request)
            if (reason != null) return TokenVerdict.Denied("caveat '$c' failed: $reason")
        }
        val required = setOf("sid", "aud", "cid", "op", "exp")
        val present = caveats.map { parse(it)!!.first }.toSet()
        val missing = required - present
        if (missing.isNotEmpty()) return TokenVerdict.Denied("token lacks mandatory caveats $missing")
        return TokenVerdict.Authorized(caveats)
    }

    companion object {
        private const val VERSION: Byte = 1
        const val MAX_CAVEATS = 32
        private val CAVEAT = Regex("^([a-z_]{2,16}) (=|<=|prefix|in) ([A-Za-z0-9:._/,|-]{1,128})$")
        private val KNOWN_KEYS = setOf("sid", "aud", "cid", "op", "exp", "max_bytes", "max_cpu_ms", "path_prefix")

        fun mint(rootKey: SecretBytes, caveats: List<String>): CapabilityToken {
            val id = CryptoEngine.randomBytes(16)
            val sig = rootKey.withCopy { k -> CryptoEngine.hmacSha256(k, id) }
            var token = CapabilityToken(id, emptyList(), sig)
            for (c in caveats) token = token.attenuate(c)
            return token
        }

        fun decode(text: String): CapabilityToken? {
            val raw = CryptoEngine.b64urlDecode(text) ?: return null
            return try {
                val bb = ByteBuffer.wrap(raw)
                if (bb.get() != VERSION) return null
                val idLen = bb.short.toInt()
                if (idLen != 16) return null
                val id = ByteArray(idLen).also { bb.get(it) }
                val n = bb.get().toInt() and 0xFF
                if (n > MAX_CAVEATS) return null
                val caveats = List(n) {
                    val len = bb.short.toInt()
                    if (len !in 1..200) return null
                    String(ByteArray(len).also { b -> bb.get(b) }, Charsets.UTF_8)
                }
                val sig = ByteArray(32).also { bb.get(it) }
                if (bb.hasRemaining()) return null
                caveats.forEach { if (parse(it) == null) return null }
                CapabilityToken(id, caveats, sig)
            } catch (_: java.nio.BufferUnderflowException) {
                null
            }
        }

        private fun validateCaveatSyntax(c: String) {
            requireNotNull(parse(c)) { "malformed caveat '$c'" }
        }

        private fun parse(c: String): Triple<String, String, String>? {
            val m = CAVEAT.matchEntire(c) ?: return null
            val (k, op, v) = m.destructured
            if (k !in KNOWN_KEYS) return null
            return Triple(k, op, v)
        }

        /** Returns null if satisfied, otherwise a reason. */
        private fun evaluate(c: String, r: CapabilityRequest): String? {
            val (k, op, v) = parse(c) ?: return "unparseable"
            return when (k) {
                "sid" -> if (op == "=" && v == r.sessionId) null else "session mismatch"
                "aud" -> if (op == "=" && v == r.audienceFingerprint) null else "audience mismatch"
                "cid" -> if (op == "=" && v == r.contractId) null else "contract mismatch"
                "op" -> when (op) {
                    "=" -> if (v == r.operation) null else "operation not permitted"
                    "in" -> if (r.operation in v.split('|')) null else "operation not permitted"
                    else -> "bad operator"
                }
                "exp" -> if (op == "<=" && r.nowSeconds <= (v.toLongOrNull() ?: return "bad exp")) null else "expired"
                "max_bytes" -> if (op == "<=" && r.bytes <= (v.toLongOrNull() ?: return "bad max_bytes")) null else "byte budget exceeded"
                "max_cpu_ms" -> if (op == "<=" && r.cpuMillis <= (v.toLongOrNull() ?: return "bad max_cpu_ms")) null else "cpu budget exceeded"
                "path_prefix" -> {
                    if (op != "prefix") return "bad operator"
                    val norm = r.path
                    if (norm.contains("..") || norm.startsWith("/") || norm.contains('\\')) return "path not canonical"
                    if (norm == v || norm.startsWith(v.trimEnd('/') + "/")) null else "path outside prefix"
                }
                else -> "unknown caveat"
            }
        }
    }
}

// ------------------------------------------------------------------------------------------
// Settlement receipts
// ------------------------------------------------------------------------------------------

class SettlementReceipt(
    val contractId: String,
    val signerPublicKey: ByteArray,
    val sessionBinding: String,
    val bytesTransferred: Long,
    val merkleRootB64: String,
    val resultHashB64: String,
    val outcome: String,   // "fulfilled" | "partial" | "failed"
    val timestampSeconds: Long,
    val signatureB64: String,
) {
    fun toJson(): JsonObject = buildJsonObject {
        put("type", "ZcpSettlementReceipt")
        put("contractId", contractId)
        put("signer", CapabilityManifest.issuerDid(signerPublicKey))
        put("sessionBinding", sessionBinding)
        put("bytes", bytesTransferred)
        put("merkleRoot", merkleRootB64)
        put("resultHash", resultHashB64)
        put("outcome", outcome)
        put("ts", timestampSeconds)
        put("sig", signatureB64)
    }

    fun receiptHash(): ByteArray = CryptoEngine.sha256(CanonicalJson.encodeToBytes(toJson()))

    companion object {
        private val DOMAIN = "ZCP1-SETTLEMENT-v1\n".toByteArray()
        val OUTCOMES = listOf("fulfilled", "partial", "failed")

        private fun body(
            contractId: String, signer: ByteArray, binding: String, bytes: Long,
            root: String, result: String, outcome: String, ts: Long,
        ) = buildJsonObject {
            put("type", "ZcpSettlementReceipt")
            put("contractId", contractId)
            put("signer", CapabilityManifest.issuerDid(signer))
            put("sessionBinding", binding)
            put("bytes", bytes)
            put("merkleRoot", root)
            put("resultHash", result)
            put("outcome", outcome)
            put("ts", ts)
        }

        fun issue(
            signer: IdentitySigner, contractId: String, handshakeHash: ByteArray, bytes: Long,
            merkleRoot: ByteArray, resultHash: ByteArray, outcome: String, nowSeconds: Long,
        ): SettlementReceipt {
            require(outcome in OUTCOMES)
            val binding = CapabilityManifest.sessionBinding(handshakeHash)
            val rootB64 = CryptoEngine.b64url(merkleRoot)
            val resB64 = CryptoEngine.b64url(resultHash)
            val b = body(contractId, signer.publicKey, binding, bytes, rootB64, resB64, outcome, nowSeconds)
            val sig = signer.sign(DOMAIN + CanonicalJson.encodeToBytes(b))
            return SettlementReceipt(contractId, signer.publicKey, binding, bytes, rootB64, resB64, outcome, nowSeconds, CryptoEngine.b64url(sig))
        }

        val SCHEMA = JsonSchema.Obj(
            mapOf(
                "type" to JsonSchema.Str(enum = listOf("ZcpSettlementReceipt")),
                "contractId" to JsonSchema.Str(pattern = Regex("^ctr-[0-9a-f]{16}$"), maxLength = 20),
                "signer" to JsonSchema.Str(pattern = Regex("^zcp-ed25519:[A-Za-z0-9_-]{43}$"), maxLength = 64),
                "sessionBinding" to JsonSchema.Str(pattern = Regex("^[A-Za-z0-9_-]{43}$"), maxLength = 43),
                "bytes" to JsonSchema.Integer(minimum = 0, maximum = 1L shl 40),
                "merkleRoot" to JsonSchema.Str(pattern = Regex("^[A-Za-z0-9_-]{43}$"), maxLength = 43),
                "resultHash" to JsonSchema.Str(pattern = Regex("^[A-Za-z0-9_-]{43}$"), maxLength = 43),
                "outcome" to JsonSchema.Str(enum = OUTCOMES),
                "ts" to JsonSchema.Integer(minimum = 0),
                "sig" to JsonSchema.Str(pattern = Regex("^[A-Za-z0-9_-]{86}$"), maxLength = 86),
            ),
            setOf("type", "contractId", "signer", "sessionBinding", "bytes", "merkleRoot", "resultHash", "outcome", "ts", "sig"),
        )

        fun verify(json: JsonObject, expectedSigner: ByteArray, handshakeHash: ByteArray): CryptoResult<SettlementReceipt> {
            fun bad(m: String) = CryptoResult.Err(CryptoError.SignatureInvalid("settlement rejected: $m"))
            when (val r = SchemaValidator.validate(SCHEMA, json)) {
                is SchemaResult.Invalid -> return bad("${r.path}: ${r.reason}")
                SchemaResult.Valid -> Unit
            }
            fun s(k: String) = json.getValue(k).jsonPrimitive.content
            val signer = CryptoEngine.b64urlDecode(s("signer").removePrefix("zcp-ed25519:")) ?: return bad("signer")
            if (!CryptoEngine.constantTimeEquals(signer, expectedSigner)) return bad("signer is not the session peer")
            if (s("sessionBinding") != CapabilityManifest.sessionBinding(handshakeHash)) return bad("session binding")
            val bytes = json.getValue("bytes").jsonPrimitive.long
            val ts = json.getValue("ts").jsonPrimitive.long
            val b = body(s("contractId"), signer, s("sessionBinding"), bytes, s("merkleRoot"), s("resultHash"), s("outcome"), ts)
            val sig = CryptoEngine.b64urlDecode(s("sig")) ?: return bad("sig encoding")
            if (!CryptoEngine.ed25519Verify(signer, DOMAIN + CanonicalJson.encodeToBytes(b), sig)) return bad("signature")
            return CryptoResult.Ok(
                SettlementReceipt(s("contractId"), signer, s("sessionBinding"), bytes, s("merkleRoot"), s("resultHash"), s("outcome"), ts, s("sig")),
            )
        }
    }
}
