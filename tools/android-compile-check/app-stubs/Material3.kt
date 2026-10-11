@file:Suppress("unused", "UNUSED_PARAMETER")
package androidx.compose.material3
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.TextUnit
class ColorScheme
private val U: Color get() = TODO()
fun darkColorScheme(primary: Color = U, onPrimary: Color = U, secondary: Color = U, background: Color = U, onBackground: Color = U, surface: Color = U, onSurface: Color = U, error: Color = U, outline: Color = U): ColorScheme = TODO()
@Composable fun MaterialTheme(colorScheme: ColorScheme = TODO(), content: @Composable () -> Unit) {}
@Composable fun Text(text: String, modifier: Modifier = Modifier, color: Color = U, fontSize: TextUnit = TODO(), fontWeight: FontWeight? = null, fontFamily: FontFamily? = null, overflow: TextOverflow = TextOverflow.Clip, softWrap: Boolean = true, maxLines: Int = Int.MAX_VALUE) {}
class ButtonColors
object ButtonDefaults { @Composable fun buttonColors(containerColor: Color = U, contentColor: Color = U, disabledContainerColor: Color = U, disabledContentColor: Color = U): ButtonColors = TODO() }
@Composable fun Button(onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true, colors: ButtonColors = TODO(), content: @Composable RowScope.() -> Unit) {}
@Composable fun OutlinedButton(onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true, colors: ButtonColors = TODO(), content: @Composable RowScope.() -> Unit) {}
@Composable fun TextButton(onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true, colors: ButtonColors = TODO(), content: @Composable RowScope.() -> Unit) {}
@Composable fun AlertDialog(onDismissRequest: () -> Unit, confirmButton: @Composable () -> Unit, modifier: Modifier = Modifier, dismissButton: (@Composable () -> Unit)? = null, icon: (@Composable () -> Unit)? = null, title: (@Composable () -> Unit)? = null, text: (@Composable () -> Unit)? = null, containerColor: Color = U) {}
class TextFieldColors
object OutlinedTextFieldDefaults { @Composable fun colors(focusedTextColor: Color = U, unfocusedTextColor: Color = U, cursorColor: Color = U, focusedBorderColor: Color = U, unfocusedBorderColor: Color = U): TextFieldColors = TODO() }
@Composable fun OutlinedTextField(value: String, onValueChange: (String) -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true, readOnly: Boolean = false, textStyle: TextStyle = TODO(), label: (@Composable () -> Unit)? = null, placeholder: (@Composable () -> Unit)? = null, isError: Boolean = false, visualTransformation: VisualTransformation = VisualTransformation.None, keyboardOptions: KeyboardOptions = TODO(), keyboardActions: KeyboardActions = TODO(), singleLine: Boolean = false, maxLines: Int = Int.MAX_VALUE, colors: TextFieldColors = TODO()) {}
class SliderColors
object SliderDefaults { @Composable fun colors(thumbColor: Color = U, activeTrackColor: Color = U, activeTickColor: Color = U, inactiveTrackColor: Color = U): SliderColors = TODO() }
@Composable fun Slider(value: Float, onValueChange: (Float) -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true, valueRange: ClosedFloatingPointRange<Float> = 0f..1f, steps: Int = 0, onValueChangeFinished: (() -> Unit)? = null, colors: SliderColors = TODO()) {}
class SwitchColors
object SwitchDefaults { @Composable fun colors(checkedThumbColor: Color = U, checkedTrackColor: Color = U, uncheckedThumbColor: Color = U, uncheckedTrackColor: Color = U): SwitchColors = TODO() }
@Composable fun Switch(checked: Boolean, onCheckedChange: ((Boolean) -> Unit)?, modifier: Modifier = Modifier, enabled: Boolean = true, colors: SwitchColors = TODO()) {}
class RadioButtonColors
object RadioButtonDefaults { @Composable fun colors(selectedColor: Color = U, unselectedColor: Color = U, disabledSelectedColor: Color = U, disabledUnselectedColor: Color = U): RadioButtonColors = TODO() }
@Composable fun RadioButton(selected: Boolean, onClick: (() -> Unit)?, modifier: Modifier = Modifier, enabled: Boolean = true, colors: RadioButtonColors = TODO()) {}
