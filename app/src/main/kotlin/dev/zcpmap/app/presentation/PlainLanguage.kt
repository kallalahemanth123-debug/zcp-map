package dev.zcpmap.app.presentation

import dev.zcpmap.protocol.LifecyclePhase
import dev.zcpmap.protocol.TeardownReason

/*
 * Turns protocol states and teardown reasons into sentences a person can act on. The raw reason is
 * still written to the terminal log; these strings are what the peer cards show.
 */
internal object PlainLanguage {

    fun status(p: PeerUi): String = when (p.phase) {
        LifecyclePhase.IDLE -> "Found nearby · not connected"
        LifecyclePhase.UWB_RANGING -> "Opening a link…"
        LifecyclePhase.NOISE_HANDSHAKE -> when {
            p.codeCheck != null -> "Compare the code on both phones"
            p.noiseVerified -> "Identity checked · measuring distance…"
            else -> "Checking identity…"
        }
        LifecyclePhase.ATTESTATION_VERIFIED, LifecyclePhase.AGENT_NEGOTIATING, LifecyclePhase.SETTLEMENT_COMPLETE ->
            if (p.codeVerified) "Connected · verified by code" else "Connected · verified at %.2f m".format(p.boundDistanceMeters ?: 0.0)
        LifecyclePhase.TASK_EXECUTING -> "Transferring…"
        LifecyclePhase.TEARDOWN -> "Connection ended"
    }

    fun teardown(reason: TeardownReason, detail: String, radiusMeters: Double): String {
        val d = detail.lowercase()
        return when {
            "no uwb" in d || "uwb unavailable" in d || "has no uwb" in d ->
                "A phone without working UWB can't measure distance. If one of the phones has no UWB, turn on " +
                    "\"Allow phones without UWB (compare a code)\" in SETUP on both phones."
            "provisioned sts" in d ->
                "One phone's UWB chip can't do relay-proof ranging (provisioned STS). Run SELF-TEST: it offers a one-tap fix."
            "codes did not match" in d -> "The codes didn't match, so the connection was refused. Try again; if it keeps happening, someone may be interfering."
            reason == TeardownReason.PEER_ABORT -> when {
                "policy" in d -> "The other phone refused the connection because of its settings (usually UWB or provisioned STS). Run SELF-TEST on the other phone."
                "timeout" in d -> "The other phone gave up waiting. Keep the app open and the screen on on both phones, then try again."
                "distance" in d -> "The other phone measured that you were too far apart. Hold the phones closer."
                "ranging" in d -> "The other phone lost UWB contact. Keep the phones close and both apps open."
                "authentication" in d -> "The other phone couldn't verify this phone's identity. Turn on automatic date & time on both phones."
                "user_terminated" in d -> "The other phone ended the connection."
                else -> "The other phone ended the connection ($detail)."
            }
            reason == TeardownReason.TIMEOUT -> "The other phone didn't answer in time. Keep the app open and the screen on on both phones, then tap CONNECT again."
            reason == TeardownReason.DISTANCE_BOUND_EXCEEDED -> "The phones were farther apart than %.1f m. Hold them closer and try again.".format(radiusMeters)
            reason == TeardownReason.RANGING_LOST -> "UWB distance measurement stopped. Keep both phones close, unlocked, with the app open."
            reason == TeardownReason.AUTHENTICATION_FAILED -> "The identity check failed. Turn on automatic date & time on both phones and try again."
            reason == TeardownReason.LINK_LOST -> "The Bluetooth/Wi-Fi link dropped. Tap CONNECT to try again."
            reason == TeardownReason.LOCAL_REQUEST -> "Ended on this phone."
            reason == TeardownReason.POLICY_VIOLATION -> "Refused by this phone's settings: $detail"
            else -> "${reason.name.lowercase().replace('_', ' ')}: $detail"
        }
    }

    fun connectFailure(reason: String): String = when {
        reason.startsWith("link failed") -> "Couldn't open a Bluetooth/Wi-Fi link ($reason). Make sure the other phone is ONLINE with the app open, then try again."
        reason == "peer not discovered" -> "That phone is no longer visible. Wait until it shows up again."
        reason == "timeout" -> "The connection didn't finish in time. Keep both apps open and try again."
        reason.startsWith("session already exists") -> "Already connecting to that phone."
        else -> reason
    }
}
