package dev.zcpmap.mesh

import dev.zcpmap.protocol.JsonSchema
import dev.zcpmap.protocol.SchemaResult
import dev.zcpmap.protocol.SchemaValidator
import dev.zcpmap.protocol.StrictJsonException
import dev.zcpmap.protocol.StrictJsonParser
import dev.zcpmap.protocol.CanonicalJson
import dev.zcpmap.security.CapabilityAction
import dev.zcpmap.security.CapabilityManifest
import dev.zcpmap.security.CryptoEngine
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.LinkOption

// ==========================================================================================
// Contracts
// ==========================================================================================

enum class TaskType(val wire: String) {
    COMPUTE_OFFLOAD("compute_offload"),
    DATA_EXCHANGE("data_exchange"),
    MODEL_SHARD_INFERENCE("model_shard_inference"),
    FILE_SHARE("file_share");

    companion object {
        fun fromWire(s: String) = entries.firstOrNull { it.wire == s }
    }
}

enum class TransferDirection(val wire: String) {
    PROPOSER_SENDS("proposer_sends"),
    ACCEPTOR_SENDS("acceptor_sends");

    companion object {
        fun fromWire(s: String) = entries.firstOrNull { it.wire == s }
    }
}

enum class ContractDecision(val wire: String) {
    ACCEPT("accept"), REJECT("reject"), COUNTER("counter");

    companion object {
        fun fromWire(s: String) = entries.firstOrNull { it.wire == s }
    }
}

enum class ContractOrigin { LOCAL, REMOTE }

enum class ContractStatus { PROPOSED, AWAITING_USER_APPROVAL, ACCEPTED, REJECTED, EXPIRED, EXECUTING, SETTLED, FAILED }

data class ContractTerms(
    val taskType: TaskType,
    val direction: TransferDirection,
    val maxBytes: Long,
    val cpuMillis: Long,
    val durationSeconds: Long,
    val credits: Long,
    /** Free text. When the contract came from a peer this is UNTRUSTED and already sanitized. */
    val summary: String,
)

data class ContractRecord(
    val contractId: String,
    val peerId: String,
    val origin: ContractOrigin,
    val terms: ContractTerms,
    val status: ContractStatus,
    val createdAtSeconds: Long,
    val expiresAtSeconds: Long,
    /** Capability token the peer minted that authorizes US to push data to THEM. */
    val outboundToken: String? = null,
    val counterOf: String? = null,
) {
    /** True when this device is the one that will receive bytes. */
    val localReceives: Boolean
        get() = (origin == ContractOrigin.REMOTE && terms.direction == TransferDirection.PROPOSER_SENDS) ||
            (origin == ContractOrigin.LOCAL && terms.direction == TransferDirection.ACCEPTOR_SENDS)
}

enum class Feasibility { FEASIBLE, NEEDS_USER_APPROVAL, INFEASIBLE }

data class EvaluationReport(
    val contractId: String,
    val verdict: Feasibility,
    val reasons: List<String>,
    val device: DeviceConstraints,
    val localReceives: Boolean,
)

/** Deterministic, non-LLM feasibility analysis. The agent may read it but cannot override it. */
class ContractEvaluator(private val policy: MeshPolicy) {
    fun evaluate(
        record: ContractRecord,
        device: DeviceConstraints,
        peerManifest: CapabilityManifest?,
        nowSeconds: Long,
    ): EvaluationReport {
        val hard = ArrayList<String>()
        val soft = ArrayList<String>()
        val t = record.terms
        if (nowSeconds >= record.expiresAtSeconds) hard += "contract expired"
        if (t.maxBytes <= 0) hard += "contract must move at least one byte"
        if (t.maxBytes > policy.maxTransferBytes) hard += "bytes ${t.maxBytes} exceed local policy ${policy.maxTransferBytes}"
        if (t.cpuMillis > policy.maxCpuMillisPerContract) hard += "cpu ${t.cpuMillis}ms exceeds local policy ${policy.maxCpuMillisPerContract}ms"
        if (device.batteryPercent < policy.minBatteryPercentForWork && !device.charging) {
            hard += "battery ${device.batteryPercent}% below ${policy.minBatteryPercentForWork}% and not charging"
        }
        if (device.thermal.severity > policy.maxThermalForWork.severity) hard += "thermal state ${device.thermal.wire} too high"
        if (record.localReceives) {
            val headroom = device.freeStorageBytes - policy.storageReserveBytes
            if (headroom < t.maxBytes) hard += "insufficient storage headroom ($headroom bytes after reserve)"
        } else {
            val grant = peerManifest?.grantFor(CapabilityAction.DATA_RECEIVE)
            if (grant == null) hard += "peer manifest does not grant data.receive"
            else if (grant.maxBytes < t.maxBytes) hard += "peer grants only ${grant.maxBytes} bytes for data.receive"
        }
        if (t.taskType == TaskType.COMPUTE_OFFLOAD || t.taskType == TaskType.MODEL_SHARD_INFERENCE) {
            val executorIsPeer = !record.localReceives
            if (executorIsPeer) {
                val g = peerManifest?.grantFor(
                    if (t.taskType == TaskType.COMPUTE_OFFLOAD) CapabilityAction.COMPUTE_OFFLOAD else CapabilityAction.INFERENCE_SHARD,
                )
                if (g == null) hard += "peer manifest does not grant ${t.taskType.wire}"
                else if (g.maxCpuMillis < t.cpuMillis) hard += "peer grants only ${g.maxCpuMillis}ms cpu"
            }
        }
        if (t.maxBytes > policy.userApprovalAboveBytes) soft += "transfer above ${policy.userApprovalAboveBytes} bytes requires user approval"
        val verdict = when {
            hard.isNotEmpty() -> Feasibility.INFEASIBLE
            soft.isNotEmpty() -> Feasibility.NEEDS_USER_APPROVAL
            else -> Feasibility.FEASIBLE
        }
        return EvaluationReport(record.contractId, verdict, hard + soft, device, record.localReceives)
    }
}

// ==========================================================================================
// Untrusted text sanitization (first line of the semantic firewall)
// ==========================================================================================

object UntrustedText {
    /**
     * Normalizes and strips characters that can hide instructions from humans or confuse
     * tokenizers: C0/C1 controls (except \n), bidi overrides/isolates, zero-width characters,
     * Unicode tag characters (U+E0000..U+E007F, used for invisible prompt injection), private-use
     * and unpaired surrogates. Collapses whitespace runs and truncates.
     */
    fun sanitize(input: String, maxChars: Int = 500): String {
        val nfkc = java.text.Normalizer.normalize(input, java.text.Normalizer.Form.NFKC)
        val sb = StringBuilder(minOf(nfkc.length, maxChars))
        var i = 0
        var lastWasSpace = false
        while (i < nfkc.length && sb.length < maxChars) {
            val cp = nfkc.codePointAt(i)
            i += Character.charCount(cp)
            val drop = when {
                cp == '\n'.code -> false
                cp < 0x20 || cp in 0x7F..0x9F -> true
                cp in 0x200B..0x200F || cp in 0x202A..0x202E || cp in 0x2060..0x206F || cp == 0xFEFF -> true
                cp in 0xE0000..0xE007F -> true
                cp in 0xE000..0xF8FF || cp in 0xF0000..0x10FFFF -> true
                Character.getType(cp) == Character.SURROGATE.toInt() -> true
                else -> false
            }
            if (drop) continue
            val isSpace = Character.isWhitespace(cp)
            if (isSpace && lastWasSpace) continue
            lastWasSpace = isSpace
            sb.appendCodePoint(if (isSpace && cp != '\n'.code) ' '.code else cp)
        }
        return sb.toString().trim()
    }
}

// ==========================================================================================
// Sandbox file store
// ==========================================================================================

sealed interface SandboxResult<out T> {
    data class Ok<T>(val value: T) : SandboxResult<T>
    data class Denied(val reason: String) : SandboxResult<Nothing>
}

/**
 * All payload I/O is confined to [root]. Outbound files must live under "outbox/"; inbound files
 * are written under "inbox/<contractId>/" with names generated locally — peer-supplied names are
 * never used as paths. Symlinks anywhere on the path are refused.
 */
class SandboxFileStore(rootDir: File, private val inboxQuotaBytes: Long) {
    val root: File = rootDir.canonicalFile

    init {
        File(root, "outbox").mkdirs()
        File(root, "inbox").mkdirs()
    }

    fun validateRelative(path: String): String? {
        if (path.length !in 1..200) return "path length out of range"
        if (!PATH.matches(path)) return "path contains forbidden characters"
        if (path.split('/').any { it == "." || it == ".." || it.isEmpty() }) return "path traversal segments are forbidden"
        return null
    }

    fun resolveOutbound(relative: String): SandboxResult<File> {
        validateRelative(relative)?.let { return SandboxResult.Denied(it) }
        if (!relative.startsWith("outbox/")) return SandboxResult.Denied("outbound payloads must live under outbox/")
        val f = File(root, relative)
        val canonical = try { f.canonicalFile } catch (e: IOException) { return SandboxResult.Denied("cannot canonicalize") }
        if (!canonical.path.startsWith(root.path + File.separator)) return SandboxResult.Denied("path escapes sandbox")
        var cur: File? = f
        while (cur != null && cur != root) {
            if (Files.isSymbolicLink(cur.toPath())) return SandboxResult.Denied("symlinks are forbidden")
            cur = cur.parentFile
        }
        if (!Files.isRegularFile(f.toPath(), LinkOption.NOFOLLOW_LINKS)) return SandboxResult.Denied("not a regular file")
        return SandboxResult.Ok(canonical)
    }

    /** Regular files under outbox/ (no symlinks), as sandbox-relative paths with sizes. */
    fun listOutbox(limit: Int = 200): List<Pair<String, Long>> {
        val outbox = File(root, "outbox")
        val out = ArrayList<Pair<String, Long>>()
        outbox.walkTopDown().onEnter { !Files.isSymbolicLink(it.toPath()) }.forEach { f ->
            if (out.size >= limit) return out
            if (!Files.isRegularFile(f.toPath(), LinkOption.NOFOLLOW_LINKS)) return@forEach
            val rel = f.relativeTo(root).invariantSeparatorsPath
            if (validateRelative(rel) == null) out += rel to f.length()
        }
        return out.sortedBy { it.first }
    }

    fun inboxUsedBytes(): Long = File(root, "inbox").walkTopDown().filter { it.isFile }.sumOf { it.length() }

    fun openInbound(contractId: String, transferIdHex: String, totalBytes: Long): SandboxResult<InboundFile> {
        if (!CONTRACT_ID.matches(contractId) || !HEX32.matches(transferIdHex)) return SandboxResult.Denied("bad identifiers")
        if (inboxUsedBytes() + totalBytes > inboxQuotaBytes) return SandboxResult.Denied("inbox quota exceeded")
        val dir = File(root, "inbox/$contractId")
        dir.mkdirs()
        val part = File(dir, "$transferIdHex.part")
        if (part.exists() || File(dir, "$transferIdHex.bin").exists()) return SandboxResult.Denied("transfer id reused")
        return SandboxResult.Ok(InboundFile(part, File(dir, "$transferIdHex.bin"), totalBytes, "inbox/$contractId/$transferIdHex.bin"))
    }

    class InboundFile internal constructor(
        private val part: File,
        private val final: File,
        private val totalBytes: Long,
        val relativeFinalPath: String,
    ) : AutoCloseable {
        private val raf = RandomAccessFile(part, "rw")
        private var written = 0L

        fun append(data: ByteArray) {
            if (written + data.size > totalBytes) throw IOException("write beyond declared size")
            raf.seek(written)
            raf.write(data)
            written += data.size
        }

        val bytesWritten: Long get() = written

        /** Verifies the full-file SHA-256 then atomically publishes the file. */
        fun commit(expectedSha256: ByteArray): Boolean {
            raf.fd.sync()
            raf.close()
            if (written != totalBytes) { part.delete(); return false }
            val md = java.security.MessageDigest.getInstance("SHA-256")
            part.inputStream().use { input ->
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    md.update(buf, 0, n)
                }
            }
            if (!CryptoEngine.constantTimeEquals(md.digest(), expectedSha256)) { part.delete(); return false }
            return part.renameTo(final)
        }

        /** Discards partial data (teardown / failed proof). */
        fun abort() {
            try { raf.close() } catch (_: IOException) {}
            part.delete()
        }

        override fun close() = abort()
    }

    companion object {
        private val PATH = Regex("^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")
        val CONTRACT_ID = Regex("^ctr-[0-9a-f]{16}$")
        private val HEX32 = Regex("^[0-9a-f]{32}$")
    }
}

// ==========================================================================================
// Peer-to-peer JSON messages (inside encrypted UWB_BIND / AGENT_PROPOSAL frames)
// ==========================================================================================

sealed interface MeshMessage {
    data class UwbParams(val address: ByteArray, val channel: Int?, val preamble: Int?, val provisionedSts: Boolean, val aoa: Boolean) : MeshMessage
    data class UwbResult(val medianCentimeters: Long, val samples: Int, val withinBound: Boolean) : MeshMessage
    data class ContractProposal(val contractId: String, val terms: ContractTerms, val expiresAtSeconds: Long, val inboundToken: String?, val counterOf: String?) : MeshMessage
    data class ContractResponse(val contractId: String, val decision: ContractDecision, val reasonCode: String, val token: String?) : MeshMessage
    data class TransferOffer(
        val contractId: String, val transferId: ByteArray, val totalBytes: Long, val chunkSize: Int,
        val chunkCount: Int, val merkleRoot: ByteArray, val sha256: ByteArray, val token: String,
    ) : MeshMessage
    data class TransferAccept(val transferId: ByteArray, val accepted: Boolean, val reasonCode: String) : MeshMessage
    data class TransferComplete(val transferId: ByteArray, val verified: Boolean) : MeshMessage
    data class Settlement(val receipt: JsonObject) : MeshMessage
}

object MeshMessages {
    private val B64_32 = Regex("^[A-Za-z0-9_-]{43}$")
    private val B64_16 = Regex("^[A-Za-z0-9_-]{22}$")
    private val TOKEN = Regex("^[A-Za-z0-9_-]{60,2400}$")
    private val CID = Regex("^ctr-[0-9a-f]{16}$")
    private val REASON = Regex("^[a-z_]{1,32}$")

    private fun t(name: String) = JsonSchema.Str(enum = listOf(name))

    private val schemas: Map<String, JsonSchema.Obj> = mapOf(
        "uwb_params" to JsonSchema.Obj(
            mapOf(
                "t" to t("uwb_params"),
                "addr" to JsonSchema.Str(pattern = Regex("^[A-Za-z0-9_-]{3,11}$"), maxLength = 11),
                "channel" to JsonSchema.Integer(minimum = 5, maximum = 14),
                "preamble" to JsonSchema.Integer(minimum = 9, maximum = 32),
                "psts" to JsonSchema.Bool(),
                "aoa" to JsonSchema.Bool(),
            ),
            setOf("t", "addr", "psts", "aoa"),
        ),
        "uwb_result" to JsonSchema.Obj(
            mapOf(
                "t" to t("uwb_result"),
                "median_cm" to JsonSchema.Integer(minimum = 0, maximum = 100_000),
                "samples" to JsonSchema.Integer(minimum = 0, maximum = 10_000),
                "within" to JsonSchema.Bool(),
            ),
            setOf("t", "median_cm", "samples", "within"),
        ),
        "contract_proposal" to JsonSchema.Obj(
            mapOf(
                "t" to t("contract_proposal"),
                "cid" to JsonSchema.Str(pattern = CID, maxLength = 20),
                "task" to JsonSchema.Str(enum = TaskType.entries.map { it.wire }),
                "direction" to JsonSchema.Str(enum = TransferDirection.entries.map { it.wire }),
                "bytes" to JsonSchema.Integer(minimum = 1, maximum = 1L shl 40),
                "cpu_ms" to JsonSchema.Integer(minimum = 0, maximum = 86_400_000),
                "duration_s" to JsonSchema.Integer(minimum = 1, maximum = 86_400),
                "credits" to JsonSchema.Integer(minimum = 0, maximum = 1_000_000),
                "summary" to JsonSchema.Str(minLength = 0, maxLength = 2000),
                "exp" to JsonSchema.Integer(minimum = 0),
                "token" to JsonSchema.Str(pattern = TOKEN, maxLength = 2400),
                "counter_of" to JsonSchema.Str(pattern = CID, maxLength = 20),
            ),
            setOf("t", "cid", "task", "direction", "bytes", "cpu_ms", "duration_s", "credits", "summary", "exp"),
        ),
        "contract_response" to JsonSchema.Obj(
            mapOf(
                "t" to t("contract_response"),
                "cid" to JsonSchema.Str(pattern = CID, maxLength = 20),
                "decision" to JsonSchema.Str(enum = ContractDecision.entries.map { it.wire }),
                "reason" to JsonSchema.Str(pattern = REASON, maxLength = 32),
                "token" to JsonSchema.Str(pattern = TOKEN, maxLength = 2400),
            ),
            setOf("t", "cid", "decision", "reason"),
        ),
        "transfer_offer" to JsonSchema.Obj(
            mapOf(
                "t" to t("transfer_offer"),
                "cid" to JsonSchema.Str(pattern = CID, maxLength = 20),
                "tid" to JsonSchema.Str(pattern = B64_16, maxLength = 22),
                "total" to JsonSchema.Integer(minimum = 1, maximum = 1L shl 40),
                "chunk" to JsonSchema.Integer(minimum = 1024, maximum = dev.zcpmap.protocol.ChunkBody.MAX_CHUNK_DATA.toLong()),
                "count" to JsonSchema.Integer(minimum = 1, maximum = Int.MAX_VALUE.toLong()),
                "root" to JsonSchema.Str(pattern = B64_32, maxLength = 43),
                "sha256" to JsonSchema.Str(pattern = B64_32, maxLength = 43),
                "token" to JsonSchema.Str(pattern = TOKEN, maxLength = 2400),
            ),
            setOf("t", "cid", "tid", "total", "chunk", "count", "root", "sha256", "token"),
        ),
        "transfer_accept" to JsonSchema.Obj(
            mapOf(
                "t" to t("transfer_accept"),
                "tid" to JsonSchema.Str(pattern = B64_16, maxLength = 22),
                "ok" to JsonSchema.Bool(),
                "reason" to JsonSchema.Str(pattern = REASON, maxLength = 32),
            ),
            setOf("t", "tid", "ok", "reason"),
        ),
        "transfer_complete" to JsonSchema.Obj(
            mapOf(
                "t" to t("transfer_complete"),
                "tid" to JsonSchema.Str(pattern = B64_16, maxLength = 22),
                "verified" to JsonSchema.Bool(),
            ),
            setOf("t", "tid", "verified"),
        ),
        "settlement" to JsonSchema.Obj(
            mapOf(
                "t" to t("settlement"),
                "receipt" to dev.zcpmap.security.SettlementReceipt.SCHEMA,
            ),
            setOf("t", "receipt"),
        ),
    )

    sealed interface Parsed {
        data class Ok(val message: MeshMessage) : Parsed
        data class Rejected(val reason: String) : Parsed
    }

    fun parse(bytes: ByteArray): Parsed {
        if (bytes.size > 8 * 1024) return Parsed.Rejected("message too large")
        val obj = try {
            StrictJsonParser.parseObject(bytes.toString(Charsets.UTF_8), StrictJsonParser.Limits(maxBytes = 8 * 1024, maxDepth = 6))
        } catch (e: StrictJsonException) {
            return Parsed.Rejected("json: ${e.message}")
        }
        val type = (obj["t"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return Parsed.Rejected("missing type")
        val schema = schemas[type] ?: return Parsed.Rejected("unknown message type")
        when (val r = SchemaValidator.validate(schema, obj)) {
            is SchemaResult.Invalid -> return Parsed.Rejected("schema ${r.path}: ${r.reason}")
            SchemaResult.Valid -> Unit
        }
        fun s(k: String) = obj.getValue(k).jsonPrimitive.content
        fun l(k: String) = obj.getValue(k).jsonPrimitive.long
        fun b(k: String) = obj.getValue(k).jsonPrimitive.content == "true"
        fun opt(k: String) = (obj[k] as? JsonPrimitive)?.takeIf { it.isString }?.content
        fun optL(k: String) = (obj[k] as? JsonPrimitive)?.takeIf { !it.isString }?.long
        fun b64(k: String) = CryptoEngine.b64urlDecode(s(k))
        val msg: MeshMessage = when (type) {
            "uwb_params" -> MeshMessage.UwbParams(
                b64("addr") ?: return Parsed.Rejected("addr"), optL("channel")?.toInt(), optL("preamble")?.toInt(), b("psts"), b("aoa"),
            )
            "uwb_result" -> MeshMessage.UwbResult(l("median_cm"), l("samples").toInt(), b("within"))
            "contract_proposal" -> MeshMessage.ContractProposal(
                contractId = s("cid"),
                terms = ContractTerms(
                    taskType = TaskType.fromWire(s("task"))!!,
                    direction = TransferDirection.fromWire(s("direction"))!!,
                    maxBytes = l("bytes"),
                    cpuMillis = l("cpu_ms"),
                    durationSeconds = l("duration_s"),
                    credits = l("credits"),
                    summary = UntrustedText.sanitize(s("summary")),
                ),
                expiresAtSeconds = l("exp"),
                inboundToken = opt("token"),
                counterOf = opt("counter_of"),
            )
            "contract_response" -> MeshMessage.ContractResponse(s("cid"), ContractDecision.fromWire(s("decision"))!!, s("reason"), opt("token"))
            "transfer_offer" -> {
                val count = l("count")
                MeshMessage.TransferOffer(
                    contractId = s("cid"),
                    transferId = b64("tid")?.takeIf { it.size == 16 } ?: return Parsed.Rejected("tid"),
                    totalBytes = l("total"),
                    chunkSize = l("chunk").toInt(),
                    chunkCount = count.toInt(),
                    merkleRoot = b64("root")?.takeIf { it.size == 32 } ?: return Parsed.Rejected("root"),
                    sha256 = b64("sha256")?.takeIf { it.size == 32 } ?: return Parsed.Rejected("sha256"),
                    token = s("token"),
                )
            }
            "transfer_accept" -> MeshMessage.TransferAccept(b64("tid")?.takeIf { it.size == 16 } ?: return Parsed.Rejected("tid"), b("ok"), s("reason"))
            "transfer_complete" -> MeshMessage.TransferComplete(b64("tid")?.takeIf { it.size == 16 } ?: return Parsed.Rejected("tid"), b("verified"))
            "settlement" -> MeshMessage.Settlement(obj.getValue("receipt").jsonObject)
            else -> return Parsed.Rejected("unknown message type")
        }
        return Parsed.Ok(msg)
    }

    fun encode(m: MeshMessage): ByteArray = CanonicalJson.encodeToBytes(
        when (m) {
            is MeshMessage.UwbParams -> buildJsonObject {
                put("t", "uwb_params"); put("addr", CryptoEngine.b64url(m.address))
                m.channel?.let { put("channel", it) }; m.preamble?.let { put("preamble", it) }
                put("psts", m.provisionedSts); put("aoa", m.aoa)
            }
            is MeshMessage.UwbResult -> buildJsonObject {
                put("t", "uwb_result"); put("median_cm", m.medianCentimeters); put("samples", m.samples); put("within", m.withinBound)
            }
            is MeshMessage.ContractProposal -> buildJsonObject {
                put("t", "contract_proposal"); put("cid", m.contractId); put("task", m.terms.taskType.wire)
                put("direction", m.terms.direction.wire); put("bytes", m.terms.maxBytes); put("cpu_ms", m.terms.cpuMillis)
                put("duration_s", m.terms.durationSeconds); put("credits", m.terms.credits); put("summary", m.terms.summary)
                put("exp", m.expiresAtSeconds); m.inboundToken?.let { put("token", it) }; m.counterOf?.let { put("counter_of", it) }
            }
            is MeshMessage.ContractResponse -> buildJsonObject {
                put("t", "contract_response"); put("cid", m.contractId); put("decision", m.decision.wire); put("reason", m.reasonCode)
                m.token?.let { put("token", it) }
            }
            is MeshMessage.TransferOffer -> buildJsonObject {
                put("t", "transfer_offer"); put("cid", m.contractId); put("tid", CryptoEngine.b64url(m.transferId))
                put("total", m.totalBytes); put("chunk", m.chunkSize); put("count", m.chunkCount)
                put("root", CryptoEngine.b64url(m.merkleRoot)); put("sha256", CryptoEngine.b64url(m.sha256)); put("token", m.token)
            }
            is MeshMessage.TransferAccept -> buildJsonObject {
                put("t", "transfer_accept"); put("tid", CryptoEngine.b64url(m.transferId)); put("ok", m.accepted); put("reason", m.reasonCode)
            }
            is MeshMessage.TransferComplete -> buildJsonObject {
                put("t", "transfer_complete"); put("tid", CryptoEngine.b64url(m.transferId)); put("verified", m.verified)
            }
            is MeshMessage.Settlement -> buildJsonObject { put("t", "settlement"); put("receipt", m.receipt) }
        },
    )

    /** Which frame type may carry which message: a UWB message in an AGENT_PROPOSAL frame is a violation. */
    fun allowedIn(m: MeshMessage, frameType: dev.zcpmap.protocol.FrameType): Boolean = when (m) {
        is MeshMessage.UwbParams, is MeshMessage.UwbResult -> frameType == dev.zcpmap.protocol.FrameType.UWB_BIND
        else -> frameType == dev.zcpmap.protocol.FrameType.AGENT_PROPOSAL
    }
}
