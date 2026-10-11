@file:Suppress("unused", "UNUSED_PARAMETER")
package androidx.compose.ui.graphics
import androidx.compose.ui.geometry.Offset
@JvmInline value class Color(val value: ULong) {
    fun copy(alpha: Float = 1f, red: Float = 0f, green: Float = 0f, blue: Float = 0f): Color = this
    companion object { val White: Color = TODO(); val Black: Color = TODO(); val Transparent: Color = TODO() }
}
fun Color(color: Long): Color = TODO()
abstract class Brush { companion object { fun sweepGradient(colors: List<Color>, center: Offset = Offset(0f, 0f)): Brush = TODO() } }
interface PathEffect { companion object { fun dashPathEffect(intervals: FloatArray, phase: Float = 0f): PathEffect = TODO() } }
interface Shape
