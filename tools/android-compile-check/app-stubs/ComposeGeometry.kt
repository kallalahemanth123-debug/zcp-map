package androidx.compose.ui.geometry
class Offset(val x: Float, val y: Float) { operator fun plus(other: Offset): Offset = Offset(x + other.x, y + other.y) }
class Size(val width: Float, val height: Float)
