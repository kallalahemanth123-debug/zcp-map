@file:Suppress("unused", "UNUSED_PARAMETER")
package androidx.compose.ui.text
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.TextUnit
class TextStyle(val color: Color? = null, val fontSize: TextUnit? = null, val fontWeight: FontWeight? = null, val fontFamily: FontFamily? = null)
class TextMeasurer
@androidx.compose.runtime.Composable fun rememberTextMeasurer(cacheSize: Int = 8): TextMeasurer = TODO()
fun DrawScope.drawText(textMeasurer: TextMeasurer, text: String, topLeft: Offset = Offset(0f, 0f), style: TextStyle = TextStyle(), overflow: TextOverflow = TextOverflow.Clip, softWrap: Boolean = true, maxLines: Int = Int.MAX_VALUE) {}
