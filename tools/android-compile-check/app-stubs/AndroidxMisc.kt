@file:Suppress("unused", "UNUSED_PARAMETER")
package androidx.lifecycle
import android.app.Application
abstract class ViewModel { protected open fun onCleared() {} }
open class AndroidViewModel(private val application: Application) : ViewModel() { @Suppress("UNCHECKED_CAST") open fun <T : Application> getApplication(): T = application as T }
class ViewModelProvider { interface Factory { fun <T : ViewModel> create(modelClass: Class<T>): T = TODO() } }
val ViewModel.viewModelScope: kotlinx.coroutines.CoroutineScope get() = TODO()
