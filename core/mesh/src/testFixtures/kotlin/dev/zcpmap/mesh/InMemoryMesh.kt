package dev.zcpmap.mesh

import dev.zcpmap.protocol.HandshakeRole
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.consumeAsFlow
import kotlinx.coroutines.flow.flow
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

// ------------------------------------------------------------------------------------------
// In-memory test doubles for the transport and ranging ports
// ------------------------------------------------------------------------------------------

class InMemoryNetwork {
    val nodes = ConcurrentHashMap<String, FakeTransport>()
}

class InMemoryLink(override val linkId: String) : FrameLink {
    lateinit var peer: InMemoryLink
    private val inbox = Channel<ByteArray>(Channel.UNLIMITED)
    /** Test hook: transform (or drop with null, or duplicate with a list) outgoing frames. */
    @Volatile var interceptor: ((ByteArray) -> List<ByteArray>)? = null
    override val maxFrameBytes = 32_768
    override val incoming: Flow<ByteArray> = inbox.consumeAsFlow()

    override suspend fun send(frame: ByteArray) {
        require(frame.size <= maxFrameBytes) { "frame too large for link" }
        val out = interceptor?.invoke(frame) ?: listOf(frame)
        out.forEach { peer.inbox.trySend(it.copyOf()) }
    }

    override suspend fun close() {
        inbox.close()
        peer.inbox.close()
    }

    companion object {
        fun pair(a: String, b: String): Pair<InMemoryLink, InMemoryLink> {
            val x = InMemoryLink("$a->$b")
            val y = InMemoryLink("$b->$a")
            x.peer = y; y.peer = x
            return x to y
        }
    }
}

class FakeTransport(val name: String, private val net: InMemoryNetwork) : PeerTransport {
    private val events = MutableSharedFlow<DiscoveryEvent>(replay = 64, extraBufferCapacity = 64)
    override val discovery: SharedFlow<DiscoveryEvent> = events
    @Volatile var beacon: String? = null
    val links = CopyOnWriteArrayList<InMemoryLink>()

    override suspend fun startDiscovery(beaconToken: String) {
        beacon = beaconToken
        net.nodes[name] = this
        net.nodes.values.filter { it !== this && it.beacon != null }.forEach { other ->
            events.emit(DiscoveryEvent.PeerFound(other.name, other.beacon!!))
            other.events.emit(DiscoveryEvent.PeerFound(name, beaconToken))
        }
    }

    override suspend fun stopDiscovery() { beacon = null }

    override suspend fun connect(endpointId: String): FrameLink {
        val target = net.nodes[endpointId] ?: error("no such endpoint")
        val (mine, theirs) = InMemoryLink.pair(name, endpointId)
        links += mine
        target.links += theirs
        target.events.emit(DiscoveryEvent.InboundLink(name, beacon ?: "zcp-unknown", theirs))
        return mine
    }

    override suspend fun openBulkLink(endpointId: String, role: HandshakeRole, params: BulkLinkParams): FrameLink? = null
}

class FakeRanging(
    @Volatile var distance: Double,
    private val psts: Boolean = true,
    /** false = this phone has no UWB radio. */
    @Volatile var available: Boolean = true,
    /** true = the radio starts but the ranging session fails immediately (seen on some real phones). */
    @Volatile var failRanging: Boolean = false,
) : SecureRangingPort {
    val configs = CopyOnWriteArrayList<BoundRangingConfig>()
    override val isAvailable: Boolean get() = available

    override suspend fun prepare(role: HandshakeRole): PreparedRanging = object : PreparedRanging {
        override val local = UwbLocalParams(
            address = byteArrayOf((Math.random() * 255).toInt().toByte(), 0x11),
            channel = if (role == HandshakeRole.INITIATOR) 9 else null,
            preambleIndex = if (role == HandshakeRole.INITIATOR) 10 else null,
            supportsProvisionedSts = psts,
            supportsAngleOfArrival = true,
        )

        override fun start(config: BoundRangingConfig): Flow<RangingEvent> = flow {
            configs += config
            if (failRanging) {
                emit(RangingEvent.Failure("simulated radio failure"))
                return@flow
            }
            var t = 0L
            while (true) {
                emit(RangingEvent.Sample(distance, 12.0, -3.0, t))
                t += 50_000_000
                delay(50)
            }
        }

        override suspend fun close() {}
    }
}
