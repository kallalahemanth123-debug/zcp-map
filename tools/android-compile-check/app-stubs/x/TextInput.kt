package androidx.compose.ui.text.input
@JvmInline value class ImeAction(val v: Int) { companion object { val Unspecified = ImeAction(-1); val Send = ImeAction(4); val Done = ImeAction(7) } }
interface VisualTransformation { companion object { val None: VisualTransformation = TODO() } }
class PasswordVisualTransformation(val mask: Char = '•') : VisualTransformation

@JvmInline value class KeyboardType(val v: Int) { companion object { val Text = KeyboardType(1); val Uri = KeyboardType(4); val Password = KeyboardType(7); val Decimal = KeyboardType(9) } }
