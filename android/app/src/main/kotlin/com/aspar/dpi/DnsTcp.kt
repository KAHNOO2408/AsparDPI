package com.aspar.dpi

import java.io.DataInputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * حل‌کننده‌ی DNS روی TCP با شکستِ بایتیِ دستی (که کاملاً خودمان بایت‌ها را
 * می‌نویسیم، برخلافِ DoH/SSLSocket که Conscrypt کنترلش را می‌گیرد).
 *
 * برای تشخیص: IPِ جوابِ هر ریزالور را در لاگ چاپ می‌کنیم تا ببینیم جوابِ واقعی
 * می‌گیریم یا باز هم IPِ مسموم (10.10.34.x).
 */
object DnsTcp {
    private val resolvers = listOf("1.1.1.1", "8.8.8.8", "9.9.9.9")
    @Volatile private var logged = 0

    fun resolve(query: ByteArray, protect: (Socket) -> Unit): ByteArray? {
        for (r in resolvers) {
            try {
                val resp = query1(r, query, protect)
                if (resp != null) {
                    if (logged < 8) { logged++; VpnBus.log("DNS✓ TCP $r → ${firstA(resp)}") }
                    return resp
                }
            } catch (e: Throwable) {
                if (logged < 8) { logged++; VpnBus.log("DNS✗ TCP $r: ${e.javaClass.simpleName} ${e.message}") }
            }
        }
        return null
    }

    private fun query1(ip: String, query: ByteArray, protect: (Socket) -> Unit): ByteArray? {
        val sock = Socket()
        try {
            try { sock.bind(InetSocketAddress(0)) } catch (_: Throwable) {}
            protect(sock)
            sock.tcpNoDelay = true
            sock.soTimeout = 6000
            sock.connect(InetSocketAddress(ip, 53), 6000)

            val out = sock.getOutputStream()
            val len = query.size
            val msg = ByteArray(2 + len)
            msg[0] = ((len ushr 8) and 0xFF).toByte()
            msg[1] = (len and 0xFF).toByte()
            System.arraycopy(query, 0, msg, 2, len)

            // شکست وسطِ qname: [2 طول][12 هدر][qname]
            val qnameStart = 2 + 12
            val qnameLen = qnameLength(query)
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
        } finally {
            try { sock.close() } catch (_: Throwable) {}
        }
    }

    private fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)

    /** اولین رکوردِ A در پاسخ را به‌صورت متن برمی‌گرداند (برای تشخیصِ مسموم‌بودن). */
    private fun firstA(resp: ByteArray): String {
        try {
            if (resp.size < 12) return "?"
            val qd = u16(resp, 4); val an = u16(resp, 6)
            if (an == 0) return "no-answer"
            var i = 12
            // رد شدن از سوال‌ها
            for (q in 0 until qd) {
                while (i < resp.size && resp[i].toInt() != 0) {
                    val l = resp[i].toInt() and 0xFF
                    if (l and 0xC0 != 0) { i += 1; break }
                    i += 1 + l
                }
                i += 1   // بایتِ صفر
                i += 4   // qtype + qclass
            }
            for (a in 0 until an) {
                if (i >= resp.size) break
                if ((resp[i].toInt() and 0xC0) == 0xC0) {
                    i += 2
                } else {
                    while (i < resp.size && resp[i].toInt() != 0) { val l = resp[i].toInt() and 0xFF; i += 1 + l }
                    i += 1
                }
                if (i + 10 > resp.size) break
                val type = u16(resp, i)
                val rdlen = u16(resp, i + 8)
                val rd = i + 10
                if (type == 1 && rdlen == 4 && rd + 4 <= resp.size) {
                    return "${resp[rd].toInt() and 0xFF}.${resp[rd + 1].toInt() and 0xFF}." +
                        "${resp[rd + 2].toInt() and 0xFF}.${resp[rd + 3].toInt() and 0xFF}"
                }
                i = rd + rdlen
            }
            return "no-A"
        } catch (_: Throwable) {
            return "?"
        }
    }

    private fun qnameLength(dns: ByteArray): Int {
        var i = 12
        var count = 0
        while (i < dns.size) {
            val l = dns[i].toInt() and 0xFF
            if (l == 0) { count += 1; break }
            if ((l and 0xC0) != 0) { count += 2; break }
            count += 1 + l
            i += 1 + l
        }
        return count.coerceAtLeast(1)
    }
}
