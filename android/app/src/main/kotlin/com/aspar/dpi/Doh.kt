package com.aspar.dpi

import android.util.Base64
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * حل‌کننده‌ی DNS با DoH، اما روی مسیرِ TLS که ClientHello‌اش شکسته می‌شود.
 *
 * شبکه‌ی کاربر اتصال به IPهای معروفِ DoH (1.1.1.1، 8.8.8.8) را از روی IP ریست
 * می‌کند. پس به‌جای آن‌ها به یک IPِ عمومیِ CDNِ Cloudflare وصل می‌شویم و SNI را
 * cloudflare-dns.com می‌گذاریم، ولی ClientHello را درست وسطِ SNI به دو سگمنتِ TCP
 * می‌شکنیم — همان ترفندی که روی بقیه‌ی سایت‌ها جواب می‌دهد. چون این IP یک رنجِ
 * عمومیِ Cloudflare است (نه یک IPِ اختصاصیِ DoH)، IP-block نیست و با SNIِ شکسته
 * از فیلتر رد می‌شود.
 */
object Doh {
    private val base = SSLSocketFactory.getDefault() as SSLSocketFactory

    private const val SNI = "cloudflare-dns.com"
    private const val PATH = "/dns-query"
    // رنجِ عمومیِ CDNِ Cloudflare که cloudflare-dns.com هم روی آن سرو می‌شود.
    private val ips = listOf("104.16.248.249", "104.16.249.249")

    @Volatile private var errLogged = 0

    /** سوکتی که اولین نوشتن (ClientHello) را به دو سگمنت می‌شکند. */
    private class SplitSocket : Socket() {
        @Volatile private var firstDone = false
        override fun getOutputStream(): OutputStream {
            val real = super.getOutputStream()
            return object : OutputStream() {
                override fun write(b: Int) = real.write(b)
                override fun write(b: ByteArray, off: Int, len: Int) {
                    if (!firstDone) {
                        firstDone = true
                        var splitAt = TlsSplit.sniSplitOffset(b, off, len)
                        if (splitAt <= off || splitAt >= off + len) splitAt = off + len / 2
                        real.write(b, off, splitAt - off)
                        real.flush()
                        try { Thread.sleep(12) } catch (_: InterruptedException) {}
                        real.write(b, splitAt, off + len - splitAt)
                        real.flush()
                    } else {
                        real.write(b, off, len)
                    }
                }
                override fun flush() = real.flush()
                override fun close() = real.close()
            }
        }
    }

    fun resolve(query: ByteArray, protect: (Socket) -> Unit): ByteArray? {
        val b64 = Base64.encodeToString(query, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        for (ip in ips) {
            try {
                val plain = SplitSocket()
                try { plain.bind(InetSocketAddress(0)) } catch (_: Throwable) {}
                protect(plain)
                plain.tcpNoDelay = true
                plain.connect(InetSocketAddress(ip, 443), 7000)

                val ssl = base.createSocket(plain, SNI, 443, true) as SSLSocket
                ssl.soTimeout = 8000
                ssl.startHandshake()
                // جلوگیری از MITM: گواهی باید واقعاً مالِ cloudflare-dns.com باشد
                if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(SNI, ssl.session)) {
                    ssl.close()
                    throw javax.net.ssl.SSLException("hostname mismatch")
                }

                val out = ssl.getOutputStream()
                val req = "GET $PATH?dns=$b64 HTTP/1.1\r\n" +
                    "Host: $SNI\r\n" +
                    "accept: application/dns-message\r\n" +
                    "connection: close\r\n\r\n"
                out.write(req.toByteArray(Charsets.ISO_8859_1))
                out.flush()

                val raw = ssl.getInputStream().readBytes()
                ssl.close()

                val body = parseHttpBody(raw)
                if (body != null && body.isNotEmpty() && body.size <= 65535) return body
                if (errLogged < 4) { errLogged++; VpnBus.log("DoH پاسخ نامعتبر از $ip") }
            } catch (e: Throwable) {
                if (errLogged < 4) {
                    errLogged++
                    VpnBus.log("DoH خطا ($ip): ${e.javaClass.simpleName} ${e.message}")
                }
            }
        }
        return null
    }

    /** بدنه‌ی پاسخِ HTTP را درمی‌آورد (chunked را هم باز می‌کند). */
    private fun parseHttpBody(raw: ByteArray): ByteArray? {
        // مرزِ هدر/بدنه = \r\n\r\n
        var sep = -1
        var i = 0
        while (i + 3 < raw.size) {
            if (raw[i] == 13.toByte() && raw[i + 1] == 10.toByte() &&
                raw[i + 2] == 13.toByte() && raw[i + 3] == 10.toByte()
            ) { sep = i; break }
            i++
        }
        if (sep < 0) return null
        val headers = String(raw, 0, sep, Charsets.ISO_8859_1)
        val firstLine = headers.substringBefore("\r\n")
        if (!firstLine.contains(" 200")) return null
        val bodyStart = sep + 4
        val chunked = headers.lineSequence().any {
            it.lowercase().startsWith("transfer-encoding:") && it.lowercase().contains("chunked")
        }
        return if (chunked) dechunk(raw, bodyStart) else raw.copyOfRange(bodyStart, raw.size)
    }

    private fun dechunk(data: ByteArray, start: Int): ByteArray {
        val out = ByteArrayOutputStream()
        var i = start
        while (i < data.size) {
            // خطِ طول (hex) تا \r\n
            var le = i
            while (le + 1 < data.size && !(data[le] == 13.toByte() && data[le + 1] == 10.toByte())) le++
            val sizeStr = String(data, i, le - i, Charsets.ISO_8859_1).trim()
            val size = sizeStr.takeWhile { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }
                .toIntOrNull(16) ?: break
            i = le + 2
            if (size == 0) break
            if (i + size > data.size) break
            out.write(data, i, size)
            i += size + 2 // خودِ chunk + \r\n
        }
        return out.toByteArray()
    }
}
