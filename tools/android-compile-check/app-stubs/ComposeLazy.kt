@file:Suppress("unused", "UNUSED_PARAMETER")
package androidx.compose.foundation.lazy
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
interface LazyItemScope
interface LazyListScope
fun <T> LazyListScope.items(items: List<T>, key: ((item: T) -> Any)? = null, contentType: (item: T) -> Any? = { null }, itemContent: @Composable LazyItemScope.(item: T) -> Unit) {}
class LazyListState { suspend fun animateScrollToItem(index: Int, scrollOffset: Int = 0) {} }
@Composable fun rememberLazyListState(initialFirstVisibleItemIndex: Int = 0, initialFirstVisibleItemScrollOffset: Int = 0): LazyListState = TODO()
@Composable fun LazyColumn(modifier: Modifier = Modifier, state: LazyListState = TODO(), reverseLayout: Boolean = false, content: LazyListScope.() -> Unit) {}
