package com.aspar.dpi

import android.util.Base64
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * حل‌کننده‌ی DNS با DoH (DNS over HTTPS) روی IPِ خامِ ریزالورهای عمومی.
 *
 * دو ترفند با هم:
 *  1) چون به IP وصل می‌شویم (نه نامِ دامنه)، جاوا هیچ SNIای نمی‌فرستد؛ پس
 *     فیلترینگِ SNI چیزی برای تطبیق ندارد و اتصال را قطع نمی‌کند.
 *  2) چون کل پرس‌وجو داخلِ HTTPS رمزنگاری شده، مسمومیتِ DNS (تزریقِ IPِ 10.10.34.x)
 *     بی‌اثر می‌شود و IPِ واقعی برمی‌گردد.
 *
 * ترافیکِ این درخواست‌ها از خودِ اپِ ماست و اپِ ما با addDisallowedApplication از
 * VPN مستثناست، پس مستقیم از شبکه‌ی واقعی می‌رود و لوپ نمی‌شود.
 */
object Doh {
    // ریزالورهایی که گواهی‌شان شاملِ همان IP هم هست (پس با IP اعتبارسنجی پاس می‌شود).
    private val endpoints = listOf(
        "https://1.1.1.1/dns-query",
        "https://1.0.0.1/dns-query",
        "https://8.8.8.8/dns-query"
    )

    /** کوئریِ خامِ DNS (همان payloadِ UDP) را می‌گیرد و پاسخِ خامِ DNS را برمی‌گرداند. */
    fun resolve(query: ByteArray): ByteArray? {
        val b64 = Base64.encodeToString(query, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        for (ep in endpoints) {
            try {
                val url = URL("$ep?dns=$b64")
                val conn = url.openConnection() as HttpsURLConnection
                conn.requestMethod = "GET"
                conn.setRequestProperty("accept", "application/dns-message")
                conn.connectTimeout = 6000
                conn.readTimeout = 6000
                conn.instanceFollowRedirects = false
                val code = conn.responseCode
                if (code == 200) {
                    val bytes = conn.inputStream.use { it.readBytes() }
                    conn.disconnect()
                    if (bytes.isNotEmpty() && bytes.size <= 65535) return bytes
                } else {
                    conn.disconnect()
                }
            } catch (_: Throwable) {
                // این endpoint نشد؛ بعدی را امتحان کن
            }
        }
        return null
    }
}
