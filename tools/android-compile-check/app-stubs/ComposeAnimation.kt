@file:Suppress("unused", "UNUSED_PARAMETER")
package androidx.compose.animation.core
import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
fun interface Easing { fun transform(fraction: Float): Float }
val LinearEasing: Easing = Easing { it }
enum class RepeatMode { Restart, Reverse }
interface DurationBasedAnimationSpec<T>
interface InfiniteRepeatableSpec<T>
fun <T> tween(durationMillis: Int = 300, delayMillis: Int = 0, easing: Easing = LinearEasing): DurationBasedAnimationSpec<T> = TODO()
fun <T> infiniteRepeatable(animation: DurationBasedAnimationSpec<T>, repeatMode: RepeatMode = RepeatMode.Restart): InfiniteRepeatableSpec<T> = TODO()
class InfiniteTransition
@Composable fun rememberInfiniteTransition(label: String = "InfiniteTransition"): InfiniteTransition = TODO()
@Composable fun InfiniteTransition.animateFloat(initialValue: Float, targetValue: Float, animationSpec: InfiniteRepeatableSpec<Float>, label: String = "FloatAnimation"): State<Float> = TODO()
