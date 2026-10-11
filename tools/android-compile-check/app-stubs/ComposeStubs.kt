// Compile-only stubs. Every signature was checked against androidx-main sources fetched from GitHub.
@file:Suppress("unused", "UNUSED_PARAMETER")
package androidx.compose.runtime
import kotlin.reflect.KProperty
@Target(AnnotationTarget.FUNCTION, AnnotationTarget.TYPE, AnnotationTarget.TYPE_PARAMETER, AnnotationTarget.PROPERTY_GETTER)
annotation class Composable
interface State<out T> { val value: T }
interface MutableState<T> : State<T> { override var value: T }
operator fun <T> State<T>.getValue(thisObj: Any?, property: KProperty<*>): T = value
operator fun <T> MutableState<T>.setValue(thisObj: Any?, property: KProperty<*>, value: T) { this.value = value }
fun <T> mutableStateOf(value: T): MutableState<T> = TODO()
@Composable inline fun <T> remember(crossinline calculation: () -> T): T = calculation()
@Composable inline fun <T> remember(key1: Any?, crossinline calculation: () -> T): T = calculation()
@Composable fun LaunchedEffect(key1: Any?, block: suspend kotlinx.coroutines.CoroutineScope.() -> Unit) {}
