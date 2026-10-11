package dev.zcpmap.app

import android.app.Application
import android.os.StrictMode

class ZcpApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            // Surface accidental cleartext sockets and leaked closeables (sockets, ciphers, files) early.
            StrictMode.setVmPolicy(
                StrictMode.VmPolicy.Builder()
                    .detectCleartextNetwork()
                    .detectLeakedClosableObjects()
                    .penaltyLog()
                    .build(),
            )
        }
    }
}
