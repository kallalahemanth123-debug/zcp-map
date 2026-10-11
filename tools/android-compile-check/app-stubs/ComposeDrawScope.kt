@file:Suppress("unused", "UNUSED_PARAMETER")
package androidx.compose.ui.graphics.drawscope
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
sealed class DrawStyle
object Fill : DrawStyle()
class Stroke(val width: Float = 0f, val miter: Float = 4f, val pathEffect: PathEffect? = null) : DrawStyle()
interface DrawScope {
    val size: Size
    fun drawLine(color: Color, start: Offset, end: Offset, strokeWidth: Float = 0f, pathEffect: PathEffect? = null, alpha: Float = 1f)
    fun drawCircle(color: Color, radius: Float = 0f, center: Offset = Offset(0f, 0f), alpha: Float = 1f, style: DrawStyle = Fill)
    fun drawArc(color: Color, startAngle: Float, sweepAngle: Float, useCenter: Boolean, topLeft: Offset = Offset(0f, 0f), size: Size = Size(0f, 0f), alpha: Float = 1f, style: DrawStyle = Fill)
    fun drawArc(brush: Brush, startAngle: Float, sweepAngle: Float, useCenter: Boolean, topLeft: Offset = Offset(0f, 0f), size: Size = Size(0f, 0f), alpha: Float = 1f, style: DrawStyle = Fill)
}
