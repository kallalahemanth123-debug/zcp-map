# ZCP-MAP — Zero-Cloud P2P Mesh Agent Protocol

Proximity-verified, serverless peer-to-peer negotiation between Android phones. **No cloud API is
used anywhere.** Each phone's negotiator is one of:

| Agent mode | What runs | Internet? |
|---|---|---|
| **Rule-based (default)** | Fixed rules + typed commands (`share photo.jpg`, `scan`, `wipe all`) | Never |
| **On-device model** | A `.litertlm` model on the phone via Google LiteRT-LM (e.g. Gemma3-1B-IT) | Never |
| **My own server** | Your model server on your Wi-Fi: Ollama, LM Studio, llama.cpp, vLLM (`/v1/chat/completions`) | Only to your server; plain `http://` is allowed only to local addresses |

Whatever the mode, every action goes through the same deterministic **airlock**, and the mesh
enforces all cryptography itself (Noise XX, UWB distance bounding, signed manifests, capability
tokens, Merkle-verified transfers, signed settlement).

```
:app              Compose UI (radar, badges, terminal, SETUP, SELF-TEST, + FILE), DI, LiteRT-LM engine
:core:transport   Android — UWB secure ranging, Nearby Connections, Wi-Fi Aware
:core:keystore    Android — Ed25519 identity in Keystore (StrongBox/TEE), secret vault
:core:agent       JVM — agent kernel, rule-based agent, on-device + own-server backends, airlock, MCP server
:core:mesh        JVM — session coordinator: handshake → distance bound → attestation → contracts → streaming
:core:security    JVM — Noise XX, ChaCha20-Poly1305 + replay window, HKDF, manifests, macaroons, receipts
:core:protocol    JVM — ZCP1 wire codec, Merkle tree, lifecycle FSM, strict JSON + schema
```

## Setting up each agent mode

Open **SETUP** while the mesh is OFFLINE.

**Rule-based** — nothing to install. Type `help` in the command bar. `share <file>` handshakes with
the nearest peer, proposes, streams, settles and wipes the session. Incoming offers are accepted if
they are file shares under your size limit.

**On-device model**
1. Download a `.litertlm` model to the phone, e.g. Gemma3-1B-IT from
   `huggingface.co/litert-community` (you must accept the Gemma licence there).
2. SETUP → On-device model → **IMPORT MODEL FILE** → pick the file.
3. Set *Context tokens* to the size the file was built for (the number after `ekv` in the file
   name, e.g. `ekv4096` → 4096).
4. GPU is faster but not every phone supports it; switch it off if loading fails.

Small models follow instructions less reliably than large ones. The airlock still blocks anything
unsafe; the worst case is that the agent does nothing useful, not something dangerous.

**My own server** (example: Ollama on a PC on the same Wi-Fi)
```
OLLAMA_HOST=0.0.0.0 OLLAMA_CONTEXT_LENGTH=16384 ollama serve
ollama pull qwen2.5:7b-instruct
```
SETUP → My own server → address `http://<PC-IP>:11434`, model `qwen2.5:7b-instruct`.
LM Studio: `http://<PC-IP>:1234`. If the model has no tool support the app switches to a text
tool format automatically.

## Testing

1. **On each phone:** tap **SELF-TEST**. It checks permissions, Bluetooth, Location, Play services,
   UWB (including whether the phone supports relay-proof *provisioned STS*), Wi-Fi Aware, the
   identity key, automatic time, free storage and the selected agent, and tells you how to fix
   anything that fails.
2. **On-phone automated tests:** with a phone plugged in,
   `./gradlew :core:keystore:connectedDebugAndroidTest :app:connectedDebugAndroidTest`.
3. **Two phones:** add a file with **+ FILE** on phone A, switch both ONLINE, hold them within the
   radius, type `share <file>` (rule mode) or an instruction (model modes).

If SELF-TEST reports that provisioned STS is unsupported, it offers a one-tap fix (see below).

## Verification status

- **JVM modules:** 69 tests pass with Kotlin 2.4.10 (same compiler as the real build). They cover
  RFC test vectors, the Noise XX handshake (also checked against an independent Python
  implementation), two-phone mesh simulations including attack cases, the airlock, both model
  backends (including a real HTTP round trip), and end-to-end runs where a model-driven agent and
  two rule-based agents move files over the real protocol stack.
- **Android modules** compile against the real Android 35 platform and the real LiteRT-LM v0.18.0
  Kotlin API, with other libraries checked against their published sources.
- **GitHub Actions** (`.github/workflows/build.yml`) runs the real Gradle build (debug + release
  APKs), all unit tests, Android lint, and the on-device tests on an Android emulator.
- **Not automatable:** UWB ranging, Nearby and Wi-Fi Aware between two physical phones. Use
  SELF-TEST and the two-phone steps above.

## Requirements and known constraints

**Building**
- **JDK 17 or 21.** Android Studio's bundled JDK (jbr-21) works out of the box. If Gradle is started
  on an older Java, or on a runtime without a compiler, `settings.gradle.kts` stops in the first
  second with instructions (tested with Java 11). The JDK is not downloaded automatically on purpose:
  it keeps the build free of extra download sources.
- **`gradle/libs.versions.toml`** holds every version (the `libs.` aliases). If it is missing, the
  build stops immediately and says so.
- **Repositories:** only Google Maven and Maven Central are allowed, and a module that declares its
  own repository fails the build on purpose. To use a library from elsewhere, add that repository in
  `settings.gradle.kts` (there is a commented example), restricted to the groups it serves.
- Versions: Kotlin 2.4.10 (required, because LiteRT-LM is compiled with it), AGP 8.11.1,
  Gradle 8.14.5, compileSdk 36, targetSdk 36. Bytecode target 17.

**Phones**
- **Android 13+ (minSdk 33).** This allows hardware-backed Ed25519 identity keys and the
  `NEARBY_WIFI_DEVICES` permission model. Nearly every UWB Android phone has been updated to
  Android 13 or later, and the UWB library itself already requires Android 12.
- **UWB is required for distance bounding.** Phones without UWB cannot form sessions (SELF-TEST
  reports this).
- **Provisioned STS (relay-proof distance).** If a phone's UWB chip lacks it, SELF-TEST shows a
  one-tap fix: allow such phones, with every transfer to or from them waiting for your APPROVE tap.
  The security reduction is visible and bounded, not silent. Phones that do support it are
  unaffected.
- **On-device model GPU.** "Try GPU first" falls back to the CPU automatically if the phone's GPU
  driver is unsupported; the agent label shows which one is in use. CPU is the default.
- **Clock:** phones must agree on the time within about a minute (automatic time on; SELF-TEST checks).
