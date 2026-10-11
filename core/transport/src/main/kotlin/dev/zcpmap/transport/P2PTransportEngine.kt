package dev.zcpmap.transport

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.aware.AttachCallback
import android.net.wifi.aware.DiscoverySessionCallback
import android.net.wifi.aware.PeerHandle
import android.net.wifi.aware.PublishConfig
import android.net.wifi.aware.PublishDiscoverySession
import android.net.wifi.aware.SubscribeConfig
import android.net.wifi.aware.SubscribeDiscoverySession
import android.net.wifi.aware.WifiAwareManager
import android.net.wifi.aware.WifiAwareNetworkInfo
import android.net.wifi.aware.WifiAwareNetworkSpecifier
import android.net.wifi.aware.WifiAwareSession
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import com.google.android.gms.nearby.Nearby
import com.google.android.gms.nearby.connection.AdvertisingOptions
import com.google.android.gms.nearby.connection.ConnectionInfo
import com.google.android.gms.nearby.connection.ConnectionLifecycleCallback
import com.google.android.gms.nearby.connection.ConnectionResolution
import com.google.android.gms.nearby.connection.ConnectionsClient
import com.google.android.gms.nearby.connection.DiscoveredEndpointInfo
import com.google.android.gms.nearby.connection.DiscoveryOptions
import com.google.android.gms.nearby.connection.EndpointDiscoveryCallback
import com.google.android.gms.nearby.connection.Payload
import com.google.android.gms.nearby.connection.PayloadCallback
import com.google.android.gms.nearby.connection.PayloadTransferUpdate
import com.google.android.gms.nearby.connection.Strategy
import dev.zcpmap.mesh.BulkLinkParams
import dev.zcpmap.mesh.DiscoveryEvent
import dev.zcpmap.mesh.FrameLink
import dev.zcpmap.mesh.PeerTransport
import dev.zcpmap.protocol.HandshakeRole
import dev.zcpmap.protocol.StreamFrameDecoder
import dev.zcpmap.protocol.WireConstants
import dev.zcpmap.protocol.WireProtocolCodec
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.consumeAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.resume

/*
 * P2P transport:
 *
 *  Nearby Connections (Strategy.P2P_POINT_TO_POINT) — discovery and the primary link. The endpoint
 *  name we advertise is the rotating beacon token from StaticKeyRotator (random, unlinkable across
 *  15-minute epochs). Nearby's own 4-digit auth token is not used for security: authentication is
 *  entirely Noise XX + distance bounding above this layer. Only BYTES payloads are accepted; FILE and
 *  STREAM payloads are cancelled on arrival so a peer cannot write to storage via Nearby.
 *
 *  Wi-Fi Aware (NAN) — optional bulk link brought up after attestation. Discovery uses a match filter
 *  derived from the Noise exporter, the NDP is protected with a PSK derived from the same exporter, and
 *  the socket carries the same ZCP1 frames (which are AEAD-protected regardless).
 */
class P2PTransportEngine(
    private val context: Context,
    private val scope: CoroutineScope,
) : PeerTransport {
    private val connections: ConnectionsClient = Nearby.getConnectionsClient(context)
    private val _discovery = MutableSharedFlow<DiscoveryEvent>(extraBufferCapacity = 128, onBufferOverflow = BufferOverflow.DROP_OLDEST)
    override val discovery: SharedFlow<DiscoveryEvent> = _discovery

    private val links = ConcurrentHashMap<String, NearbyFrameLink>()
    private val pendingOutbound = ConcurrentHashMap<String, CompletableDeferred<NearbyFrameLink>>()
    private val endpointNames = ConcurrentHashMap<String, String>()
    @Volatile private var localBeacon: String = "zcp-0000000000000000"

    // ------------------------------------------------------------------ Nearby: discovery

    override suspend fun startDiscovery(beaconToken: String) {
        require(BEACON.matches(beaconToken))
        localBeacon = beaconToken
        connections.startAdvertising(
            beaconToken, SERVICE_ID, lifecycle,
            AdvertisingOptions.Builder().setStrategy(Strategy.P2P_POINT_TO_POINT).build(),
        ).await()
        connections.startDiscovery(
            SERVICE_ID, endpointDiscovery,
            DiscoveryOptions.Builder().setStrategy(Strategy.P2P_POINT_TO_POINT).build(),
        ).await()
        Log.i(TAG, "advertising + discovering as $beaconToken")
    }

    override suspend fun stopDiscovery() {
        connections.stopAdvertising()
        connections.stopDiscovery()
    }

    fun shutdown() {
        connections.stopAllEndpoints()
        links.values.forEach { it.closeLocal() }
        links.clear()
    }

    private val endpointDiscovery = object : EndpointDiscoveryCallback() {
        override fun onEndpointFound(endpointId: String, info: DiscoveredEndpointInfo) {
            if (info.serviceId != SERVICE_ID || !BEACON.matches(info.endpointName)) return
            endpointNames[endpointId] = info.endpointName
            _discovery.tryEmit(DiscoveryEvent.PeerFound(endpointId, info.endpointName))
        }

        override fun onEndpointLost(endpointId: String) {
            _discovery.tryEmit(DiscoveryEvent.PeerLost(endpointId))
        }
    }

    // ------------------------------------------------------------------ Nearby: connections

    private val lifecycle = object : ConnectionLifecycleCallback() {
        override fun onConnectionInitiated(endpointId: String, info: ConnectionInfo) {
            if (!BEACON.matches(info.endpointName) || links.size >= MAX_LINKS) {
                connections.rejectConnection(endpointId)
                return
            }
            endpointNames[endpointId] = info.endpointName
            val link = NearbyFrameLink(endpointId, connections)
            links[endpointId]?.closeLocal()
            links[endpointId] = link
            connections.acceptConnection(endpointId, payloads)
        }

        override fun onConnectionResult(endpointId: String, result: ConnectionResolution) {
            val link = links[endpointId]
            val pending = pendingOutbound.remove(endpointId)
            if (!result.status.isSuccess || link == null) {
                links.remove(endpointId)?.closeLocal()
                pending?.completeExceptionally(IOException("connection to $endpointId failed: ${result.status.statusCode}"))
                return
            }
            if (pending != null) {
                pending.complete(link)
            } else {
                _discovery.tryEmit(DiscoveryEvent.InboundLink(endpointId, endpointNames[endpointId] ?: "zcp-unknown", link))
            }
        }

        override fun onDisconnected(endpointId: String) {
            links.remove(endpointId)?.closeLocal()
        }
    }

    private val payloads = object : PayloadCallback() {
        override fun onPayloadReceived(endpointId: String, payload: Payload) {
            if (payload.type != Payload.Type.BYTES) {
                connections.cancelPayload(payload.id)
                return
            }
            val bytes = payload.asBytes() ?: return
            links[endpointId]?.deliver(bytes)
        }

        override fun onPayloadTransferUpdate(endpointId: String, update: PayloadTransferUpdate) = Unit
    }

    override suspend fun connect(endpointId: String): FrameLink {
        val deferred = CompletableDeferred<NearbyFrameLink>()
        pendingOutbound[endpointId] = deferred
        try {
            connections.requestConnection(localBeacon, endpointId, lifecycle).await()
            return withTimeout(CONNECT_TIMEOUT_MS) { deferred.await() }
        } catch (e: Exception) {
            pendingOutbound.remove(endpointId)
            connections.disconnectFromEndpoint(endpointId)
            throw if (e is IOException) e else IOException("connect failed: ${e.message}", e)
        }
    }

    private class NearbyFrameLink(
        private val endpointId: String,
        private val connections: ConnectionsClient,
    ) : FrameLink {
        private val inbox = Channel<ByteArray>(capacity = 256)
        override val linkId = "nearby:$endpointId"
        override val maxFrameBytes = WireConstants.NEARBY_MAX_FRAME
        override val incoming: Flow<ByteArray> = inbox.consumeAsFlow()

        fun deliver(bytes: ByteArray) {
            // A peer that floods faster than we can authenticate frames loses the link (fail closed).
            if (inbox.trySend(bytes).isFailure) {
                connections.disconnectFromEndpoint(endpointId)
                closeLocal()
            }
        }

        override suspend fun send(frame: ByteArray) {
            require(frame.size <= maxFrameBytes) { "frame exceeds Nearby BYTES limit" }
            connections.sendPayload(endpointId, Payload.fromBytes(frame)).await()
        }

        override suspend fun close() {
            connections.disconnectFromEndpoint(endpointId)
            closeLocal()
        }

        fun closeLocal() {
            inbox.close()
        }
    }

    // ------------------------------------------------------------------ Wi-Fi Aware bulk link

    override suspend fun openBulkLink(endpointId: String, role: HandshakeRole, params: BulkLinkParams): FrameLink? {
        if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE)) return null
        // The bulk link is optional: without the grant, transfers simply stay on Nearby Connections.
        if (!hasAwarePermissions()) {
            Log.i(TAG, "Wi-Fi Aware skipped: Nearby Wi-Fi devices permission not granted")
            return null
        }
        val wam = context.getSystemService(WifiAwareManager::class.java) ?: return null
        if (!wam.isAvailable) return null
        val thread = HandlerThread("zcp-aware").apply { start() }
        val handler = Handler(thread.looper)
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val cleanup = ArrayList<() -> Unit>()
        cleanup += { thread.quitSafely() }
        return try {
            withTimeoutOrNull(AWARE_TIMEOUT_MS) {
                val session = attach(wam, handler) ?: return@withTimeoutOrNull null
                cleanup += { session.close() }
                if (role == HandshakeRole.RESPONDER) publisherPath(session, handler, cm, params, cleanup)
                else subscriberPath(session, handler, cm, params, cleanup)
            }.also { link -> if (link == null) cleanup.asReversed().forEach { runCatching(it) } else (link as SocketFrameLink).onClose = { cleanup.asReversed().forEach { c -> runCatching(c) } } }
        } catch (e: Exception) {
            Log.w(TAG, "Wi-Fi Aware bulk link failed: ${e.message}")
            cleanup.asReversed().forEach { runCatching(it) }
            null
        }
    }

    private fun hasAwarePermissions(): Boolean =
        AWARE_PERMISSIONS.all { context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED }

    // Each Wi-Fi Aware call below also handles SecurityException at the call site: the user can revoke
    // NEARBY_WIFI_DEVICES at any moment, including between the check in openBulkLink and the call.
    private suspend fun attach(wam: WifiAwareManager, handler: Handler): WifiAwareSession? =
        suspendCancellableCoroutine { cont ->
            try {
                wam.attach(object : AttachCallback() {
                    override fun onAttached(session: WifiAwareSession) { if (cont.isActive) cont.resume(session) else session.close() }
                    override fun onAttachFailed() { if (cont.isActive) cont.resume(null) }
                }, handler)
            } catch (e: SecurityException) {
                Log.w(TAG, "Wi-Fi Aware attach refused: ${e.message}")
                if (cont.isActive) cont.resume(null)
            }
        }

    private suspend fun publisherPath(
        session: WifiAwareSession,
        handler: Handler,
        cm: ConnectivityManager,
        params: BulkLinkParams,
        cleanup: MutableList<() -> Unit>,
    ): FrameLink? {
        val server = withContext(Dispatchers.IO) { ServerSocket(0) }
        cleanup += { runCatching { server.close() } }
        val peer = CompletableDeferred<Pair<PublishDiscoverySession, PeerHandle>>()
        var publishSession: PublishDiscoverySession? = null
        try {
            session.publish(
                PublishConfig.Builder()
                    .setServiceName(SERVICE_NAME)
                    .setMatchFilter(listOf(params.matchToken))
                    .build(),
                object : DiscoverySessionCallback() {
                    override fun onPublishStarted(s: PublishDiscoverySession) { publishSession = s }
                    override fun onMessageReceived(peerHandle: PeerHandle, message: ByteArray) {
                        val s = publishSession ?: return
                        if (java.security.MessageDigest.isEqual(message, params.matchToken)) peer.complete(s to peerHandle)
                    }
                    override fun onSessionTerminated() { peer.completeExceptionally(IOException("publish terminated")) }
                },
                handler,
            )
        } catch (e: SecurityException) {
            throw IOException("Wi-Fi Aware publish refused: ${e.message}", e)
        }
        val (ps, handle) = peer.await()
        cleanup += { ps.close() }
        val spec = WifiAwareNetworkSpecifier.Builder(ps, handle)
            .setPskPassphrase(params.pskPassphrase)
            .setPort(server.localPort)
            .build()
        requestAwareNetwork(cm, spec, cleanup)
        val socket = withContext(Dispatchers.IO) {
            server.soTimeout = AWARE_TIMEOUT_MS.toInt()
            server.accept()
        }
        return SocketFrameLink("aware-pub", socket, scope)
    }

    private suspend fun subscriberPath(
        session: WifiAwareSession,
        handler: Handler,
        cm: ConnectivityManager,
        params: BulkLinkParams,
        cleanup: MutableList<() -> Unit>,
    ): FrameLink? {
        val found = CompletableDeferred<Pair<SubscribeDiscoverySession, PeerHandle>>()
        var subscribeSession: SubscribeDiscoverySession? = null
        try {
            session.subscribe(
                SubscribeConfig.Builder()
                    .setServiceName(SERVICE_NAME)
                    .setMatchFilter(listOf(params.matchToken))
                    .build(),
                object : DiscoverySessionCallback() {
                    override fun onSubscribeStarted(s: SubscribeDiscoverySession) { subscribeSession = s }
                    override fun onServiceDiscovered(peerHandle: PeerHandle, serviceSpecificInfo: ByteArray, matchFilter: List<ByteArray>) {
                        val s = subscribeSession ?: return
                        if (matchFilter.any { java.security.MessageDigest.isEqual(it, params.matchToken) }) found.complete(s to peerHandle)
                    }
                    override fun onSessionTerminated() { found.completeExceptionally(IOException("subscribe terminated")) }
                },
                handler,
            )
        } catch (e: SecurityException) {
            throw IOException("Wi-Fi Aware subscribe refused: ${e.message}", e)
        }
        val (ss, handle) = found.await()
        cleanup += { ss.close() }
        ss.sendMessage(handle, 1, params.matchToken)
        val spec = WifiAwareNetworkSpecifier.Builder(ss, handle).setPskPassphrase(params.pskPassphrase).build()
        val (network, info) = requestAwareNetwork(cm, spec, cleanup)
        val addr = info?.peerIpv6Addr ?: throw IOException("no peer IPv6 address")
        val port = info.port.takeIf { it > 0 } ?: throw IOException("publisher did not advertise a port")
        val socket: Socket = withContext(Dispatchers.IO) { network.socketFactory.createSocket(addr, port) }
        return SocketFrameLink("aware-sub", socket, scope)
    }

    private suspend fun requestAwareNetwork(
        cm: ConnectivityManager,
        spec: WifiAwareNetworkSpecifier,
        cleanup: MutableList<() -> Unit>,
    ): Pair<Network, WifiAwareNetworkInfo?> {
        val ready = CompletableDeferred<Pair<Network, WifiAwareNetworkInfo?>>()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                val info = caps.transportInfo as? WifiAwareNetworkInfo
                if (!ready.isCompleted) ready.complete(network to info)
            }
            override fun onUnavailable() { ready.completeExceptionally(IOException("Wi-Fi Aware network unavailable")) }
            override fun onLost(network: Network) { ready.completeExceptionally(IOException("Wi-Fi Aware network lost")) }
        }
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI_AWARE)
            .setNetworkSpecifier(spec)
            .build()
        cm.requestNetwork(request, callback)
        cleanup += { runCatching { cm.unregisterNetworkCallback(callback) } }
        return ready.await()
    }

    /** ZCP1 frames over a TCP socket, re-framed with the incremental stream decoder. */
    private class SocketFrameLink(name: String, private val socket: Socket, scope: CoroutineScope) : FrameLink {
        override val linkId = "$name:${socket.inetAddress?.hostAddress}"
        override val maxFrameBytes = WireConstants.NEARBY_MAX_FRAME
        private val inbox = Channel<ByteArray>(capacity = 512)
        override val incoming: Flow<ByteArray> = inbox.consumeAsFlow()
        private val writeLock = Mutex()
        private val codec = WireProtocolCodec(WireConstants.NEARBY_MAX_PAYLOAD)
        @Volatile var onClose: (() -> Unit)? = null
        private val reader: Job

        init {
            socket.tcpNoDelay = true
            reader = scope.launch(Dispatchers.IO) {
                val decoder = StreamFrameDecoder(codec, WireConstants.NEARBY_MAX_PAYLOAD)
                val buf = ByteArray(64 * 1024)
                try {
                    val input = socket.getInputStream()
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        when (val out = decoder.feed(buf, 0, n)) {
                            is StreamFrameDecoder.Output.Frames -> out.frames.forEach { f -> inbox.send(codec.encode(f)) }
                            is StreamFrameDecoder.Output.Fatal -> throw IOException("malformed stream: ${out.reason}")
                        }
                    }
                    inbox.close()
                } catch (e: Exception) {
                    inbox.close(e)
                } finally {
                    decoder.reset()
                    runCatching { socket.close() }
                }
            }
        }

        override suspend fun send(frame: ByteArray) {
            require(frame.size <= maxFrameBytes)
            writeLock.withLock {
                withContext(Dispatchers.IO) {
                    val out = socket.getOutputStream()
                    out.write(frame)
                    out.flush()
                }
            }
        }

        override suspend fun close() {
            reader.cancel()
            runCatching { socket.close() }
            inbox.close()
            onClose?.invoke()
            onClose = null
        }
    }

    companion object {
        private const val TAG = "ZcpTransport"
        const val SERVICE_ID = "dev.zcpmap.mesh.v1"
        private const val SERVICE_NAME = "zcpmap-bulk"
        private const val MAX_LINKS = 4
        private const val CONNECT_TIMEOUT_MS = 20_000L
        private const val AWARE_TIMEOUT_MS = 15_000L
        private val BEACON = Regex("^zcp-[0-9a-f]{16}$")

        /** Wi-Fi Aware attach/publish/subscribe need all of these (NEARBY_WIFI_DEVICES is a runtime grant). */
        private val AWARE_PERMISSIONS = arrayOf(
            Manifest.permission.ACCESS_WIFI_STATE,
            Manifest.permission.CHANGE_WIFI_STATE,
            Manifest.permission.NEARBY_WIFI_DEVICES,
        )
    }
}
