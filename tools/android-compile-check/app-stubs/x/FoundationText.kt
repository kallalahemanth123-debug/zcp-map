package androidx.compose.foundation.text
import androidx.compose.ui.text.input.ImeAction
interface KeyboardActionScope
class KeyboardActions(val onDone: (KeyboardActionScope.() -> Unit)? = null, val onGo: (KeyboardActionScope.() -> Unit)? = null, val onNext: (KeyboardActionScope.() -> Unit)? = null, val onPrevious: (KeyboardActionScope.() -> Unit)? = null, val onSearch: (KeyboardActionScope.() -> Unit)? = null, val onSend: (KeyboardActionScope.() -> Unit)? = null)
class KeyboardOptions(val capitalization: Int = 0, val autoCorrectEnabled: Boolean? = null, val keyboardType: androidx.compose.ui.text.input.KeyboardType = androidx.compose.ui.text.input.KeyboardType.Text, val imeAction: ImeAction = ImeAction.Unspecified)
