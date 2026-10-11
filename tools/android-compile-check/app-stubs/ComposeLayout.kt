@file:Suppress("unused", "UNUSED_PARAMETER")
package androidx.compose.foundation.layout
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.Dp
object Arrangement {
    interface Horizontal; interface Vertical; interface HorizontalOrVertical : Horizontal, Vertical
    val Top: Vertical = TODO(); val Start: Horizontal = TODO()
    fun spacedBy(space: Dp): HorizontalOrVertical = TODO()
}
interface BoxScope { fun Modifier.align(alignment: Alignment): Modifier = this }
interface RowScope { fun Modifier.weight(weight: Float, fill: Boolean = true): Modifier = this }
interface ColumnScope { fun Modifier.weight(weight: Float, fill: Boolean = true): Modifier = this }
@Composable fun Box(modifier: Modifier = Modifier, contentAlignment: Alignment = TODO(), propagateMinConstraints: Boolean = false, content: @Composable BoxScope.() -> Unit) {}
@Composable fun Column(modifier: Modifier = Modifier, verticalArrangement: Arrangement.Vertical = Arrangement.Top, horizontalAlignment: Alignment.Horizontal = Alignment.Start, content: @Composable ColumnScope.() -> Unit) {}
@Composable fun Row(modifier: Modifier = Modifier, horizontalArrangement: Arrangement.Horizontal = Arrangement.Start, verticalAlignment: Alignment.Vertical = Alignment.Top, content: @Composable RowScope.() -> Unit) {}
@Composable fun Spacer(modifier: Modifier) {}
fun Modifier.aspectRatio(ratio: Float, matchHeightConstraintsFirst: Boolean = false): Modifier = this
fun Modifier.fillMaxSize(fraction: Float = 1f): Modifier = this
fun Modifier.fillMaxWidth(fraction: Float = 1f): Modifier = this
fun Modifier.height(height: Dp): Modifier = this
fun Modifier.width(width: Dp): Modifier = this
fun Modifier.size(size: Dp): Modifier = this
fun Modifier.padding(all: Dp): Modifier = this
fun Modifier.padding(horizontal: Dp = Dp(0f), vertical: Dp = Dp(0f)): Modifier = this
fun Modifier.padding(start: Dp = Dp(0f), top: Dp = Dp(0f), end: Dp = Dp(0f), bottom: Dp = Dp(0f)): Modifier = this
fun Modifier.imePadding(): Modifier = this
fun Modifier.statusBarsPadding(): Modifier = this
@androidx.compose.runtime.Composable fun Box(modifier: androidx.compose.ui.Modifier) {}
fun Modifier.heightIn(min: Dp = Dp(Float.NaN), max: Dp = Dp(Float.NaN)): Modifier = this
