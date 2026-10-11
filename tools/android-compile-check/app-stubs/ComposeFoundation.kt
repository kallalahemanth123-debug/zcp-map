@file:Suppress("unused", "UNUSED_PARAMETER")
package androidx.compose.foundation
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.unit.Dp
@Composable fun Canvas(modifier: Modifier, onDraw: DrawScope.() -> Unit) {}
fun Modifier.background(color: Color, shape: Shape = TODO()): Modifier = this
fun Modifier.border(width: Dp, color: Color, shape: Shape = TODO()): Modifier = this
class ScrollState(initial: Int)
@Composable fun rememberScrollState(initial: Int = 0): ScrollState = ScrollState(initial)
fun Modifier.verticalScroll(state: ScrollState, enabled: Boolean = true, reverseScrolling: Boolean = false): Modifier = this
