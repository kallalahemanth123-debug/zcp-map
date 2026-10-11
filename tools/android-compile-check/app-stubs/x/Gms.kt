package com.google.android.gms.common
open class GoogleApiAvailability { open fun isGooglePlayServicesAvailable(context: android.content.Context): Int = 0
  companion object { @JvmStatic fun getInstance(): GoogleApiAvailability = TODO() } }
object ConnectionResult { const val SUCCESS: Int = 0 }
