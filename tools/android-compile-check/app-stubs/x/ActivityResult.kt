package androidx.activity.result
fun interface ActivityResultCallback<O> { fun onActivityResult(result: O) }
abstract class ActivityResultLauncher<I> { fun launch(input: I) {} }
