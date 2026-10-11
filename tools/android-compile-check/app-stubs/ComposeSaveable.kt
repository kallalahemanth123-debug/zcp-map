package androidx.compose.runtime.saveable
@androidx.compose.runtime.Composable fun <T : Any> rememberSaveable(vararg inputs: Any?, key: String? = null, init: () -> T): T = init()
