@file:Suppress("unused", "UNUSED_PARAMETER")
package androidx.activity
import androidx.activity.result.ActivityResultCallback
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContract
open class ComponentActivity : android.app.Activity() {
    fun <I, O> registerForActivityResult(contract: ActivityResultContract<I, O>, callback: ActivityResultCallback<O>): ActivityResultLauncher<I> = TODO()
}
fun ComponentActivity.enableEdgeToEdge() {}
inline fun <reified VM : androidx.lifecycle.ViewModel> ComponentActivity.viewModels(noinline extrasProducer: (() -> Any)? = null, noinline factoryProducer: (() -> androidx.lifecycle.ViewModelProvider.Factory)? = null): Lazy<VM> = TODO()
