package com.aspar.dpi

import java.io.DataInputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * حل‌کننده‌ی DNS روی TCP با همان ترفندِ شکستن.
 *
 * مسمومیتِ DNS در ایران معمولاً اسمِ دامنه را داخلِ کوئریِ DNS (به‌صورت متنِ باز)
 * می‌خواند و پاسخِ جعلی تزریق می‌کند. اگر کوئری را روی TCP بفرستیم و درست وسطِ
 * اسمِ دامنه به دو سگمنت بشکنیم، تزریق‌کننده نمی‌تواند نام را تطبیق بدهد و پاسخِ
 * واقعی از ریزالورِ بالادست می‌رسد.
 */
object DnsTcp {

    /**
     * کوئریِ DNS (همان payloadِ UDP) را روی TCP به ریزالور می‌فرستد و پاسخِ خام
     * DNS را برمی‌گرداند، یا null در صورت خطا/تایم‌اوت.
     */
    fun resolve(resolverIp: Int, query: ByteArray, protect: (Socket) -> Unit): ByteArray? {
        val sock = Socket()
        try {
            try { sock.bind(InetSocketAddress(0)) } catch (_: Throwable) {}
            protect(sock)
            sock.tcpNoDelay = true
            sock.soTimeout = 6000
            sock.connect(InetSocketAddress(Packets.ipToString(resolverIp), 53), 6000)

            val out = sock.getOutputStream()
            val len = query.size
            val msg = ByteArray(2 + len)
            msg[0] = ((len ushr 8) and 0xFF).toByte()
            msg[1] = (len and 0xFF).toByte()
            System.arraycopy(query, 0, msg, 2, len)

            // نقطه‌ی شکست را وسطِ qname می‌گذاریم.
            // ساختار: [2 بایت طول TCP][12 بایت هدر DNS][qname...]
            val qnameStart = 2 + 12
            val qnameLen = qnameLength(query) // در فضای payloadِ DNS
            var splitAt = qnameStart + (qnameLen / 2)
            if (splitAt <= qnameStart) splitAt = (qnameStart + 1).coerceAtMost(msg.size - 1)
            if (splitAt >= msg.size) splitAt = msg.size / 2

            out.write(msg, 0, splitAt)
            out.flush()
            Thread.sleep(10)
            out.write(msg, splitAt, msg.size - splitAt)
            out.flush()

            val din = DataInputStream(sock.getInputStream())
            val respLen = din.readUnsignedShort()
            if (respLen <= 0 || respLen > 65535) return null
            val resp = ByteArray(respLen)
            din.readFully(resp)
            return resp
        } catch (_: Throwable) {
            return null
        } finally {
            try { sock.close() } catch (_: Throwable) {}
        }
    }

    /** طولِ qname را در payloadِ DNS (از offset 12) حساب می‌کند. */
    private fun qnameLength(dns: ByteArray): Int {
        var i = 12
        var count = 0
        while (i < dns.size) {
            val l = dns[i].toInt() and 0xFF
            if (l == 0) { count += 1; break }
            if ((l and 0xC0) != 0) { count += 2; break } // pointer (بعید در کوئری)
            count += 1 + l
            i += 1 + l
        }
        return count.coerceAtLeast(1)
    }
}
