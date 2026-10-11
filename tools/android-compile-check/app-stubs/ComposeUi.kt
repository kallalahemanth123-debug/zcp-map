@file:Suppress("unused", "UNUSED_PARAMETER")
package androidx.compose.ui
interface Modifier { fun then(other: Modifier): Modifier = this; companion object : Modifier }
interface Alignment {
    interface Vertical; interface Horizontal
    companion object {
        val TopStart: Alignment = TODO(); val Center: Alignment = TODO()
        val CenterVertically: Vertical = TODO(); val Top: Vertical = TODO()
        val End: Horizontal = TODO(); val Start: Horizontal = TODO(); val CenterHorizontally: Horizontal = TODO()
    }
}
