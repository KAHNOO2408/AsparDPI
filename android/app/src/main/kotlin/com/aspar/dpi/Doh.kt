package com.aspar.dpi

import android.util.Base64
import java.net.InetAddress
import java.net.Socket
import java.net.URL
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * حل‌کننده‌ی DNS با DoH، اما با حذفِ کاملِ SNI در دستِ handshake.
 *
 * فیلترینگِ شبکه معمولاً اتصالِ DoH را از روی SNI (مثلِ cloudflare-dns.com) ریست
 * می‌کند. اینجا با یک SocketFactory سفارشی، لیستِ serverName را خالی می‌کنیم تا
 * هیچ SNIای فرستاده نشود؛ در نتیجه فیلتر چیزی برای تطبیق ندارد. بررسی نامِ میزبان
 * هم خاموش می‌شود چون با IP وصل می‌شویم (برای resolveِ DNS کافی و بی‌خطر است).
 *
 * ترافیکِ این درخواست‌ها از خودِ اپِ ماست و اپِ ما با addDisallowedApplication از
 * VPN مستثناست، پس مستقیم می‌رود و لوپ نمی‌شود.
 */
object Doh {
    private val base = SSLSocketFactory.getDefault() as SSLSocketFactory

    private class NoSniFactory(private val d: SSLSocketFactory) : SSLSocketFactory() {
        override fun getDefaultCipherSuites(): Array<String> = d.defaultCipherSuites
        override fun getSupportedCipherSuites(): Array<String> = d.supportedCipherSuites

        private fun strip(s: Socket): Socket {
            if (s is SSLSocket) {
                val p = s.sslParameters
                p.serverNames = emptyList()               // بدون SNI
                p.endpointIdentificationAlgorithm = null  // بدون بررسی نامِ میزبان
                s.sslParameters = p
            }
            return s
        }

        override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean): Socket =
            strip(d.createSocket(s, host, port, autoClose))
        override fun createSocket(host: String?, port: Int): Socket =
            strip(d.createSocket(host, port))
        override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket =
            strip(d.createSocket(host, port, localHost, localPort))
        override fun createSocket(host: InetAddress?, port: Int): Socket =
            strip(d.createSocket(host, port))
        override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
            strip(d.createSocket(address, port, localAddress, localPort))
    }

    private val factory = NoSniFactory(base)
    private val allowAll = HostnameVerifier { _, _ -> true }

    private val endpoints = listOf(
        "https://1.1.1.1/dns-query",
        "https://8.8.8.8/dns-query",
        "https://9.9.9.9/dns-query"
    )

    @Volatile private var errLogged = 0

    fun resolve(query: ByteArray): ByteArray? {
        val b64 = Base64.encodeToString(query, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        for (ep in endpoints) {
            try {
                val conn = URL("$ep?dns=$b64").openConnection() as HttpsURLConnection
                conn.sslSocketFactory = factory
                conn.hostnameVerifier = allowAll
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
                    if (errLogged < 4) { errLogged++; VpnBus.log("DoH کد $code از $ep") }
                }
            } catch (e: Throwable) {
                if (errLogged < 4) {
                    errLogged++
                    VpnBus.log("DoH خطا ($ep): ${e.javaClass.simpleName} ${e.message}")
                }
            }
        }
        return null
    }
}
