package androidx.activity.compose
fun androidx.activity.ComponentActivity.setContent(parent: Any? = null, content: @androidx.compose.runtime.Composable () -> Unit) {}
class ManagedActivityResultLauncher<I, O> : androidx.activity.result.ActivityResultLauncher<I>()
@androidx.compose.runtime.Composable fun <I, O> rememberLauncherForActivityResult(contract: androidx.activity.result.contract.ActivityResultContract<I, O>, onResult: (O) -> Unit): ManagedActivityResultLauncher<I, O> = TODO()
