package androidx.activity.result.contract
abstract class ActivityResultContract<I, O>
class ActivityResultContracts { class RequestMultiplePermissions : ActivityResultContract<Array<String>, Map<String, @JvmSuppressWildcards Boolean>>()
 open class OpenDocument : ActivityResultContract<Array<String>, android.net.Uri?>() }
