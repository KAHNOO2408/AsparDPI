package com.aspar.dpi

/**
 * پل ساده‌ی بین سرویس VPN و لایه‌ی Flutter.
 * سرویس لاگ‌ها را اینجا می‌فرستد و MainActivity آن‌ها را به EventChannel می‌رساند.
 */
object VpnBus {
    @Volatile var running: Boolean = false
    var sink: ((String) -> Unit)? = null

    fun log(line: String) {
        try {
            sink?.invoke(line)
        } catch (_: Throwable) {
        }
    }
}
