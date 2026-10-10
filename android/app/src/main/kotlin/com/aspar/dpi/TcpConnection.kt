package com.aspar.dpi

import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.LinkedBlockingQueue
import kotlin.concurrent.thread
import kotlin.random.Random

/**
 * یک اتصالِ TCP را بین اپِ داخل گوشی (سمتِ TUN) و سرورِ واقعی (سمتِ اینترنت)
 * رله می‌کند و روی اولین پکتِ TLS، ClientHello را می‌شکند.
 *
 * مدلِ نخ‌ها: برای هر اتصال یک نخ برای خواندن از بالادست (سرور→اپ) و یک نخ
 * برای نوشتن به بالادست (اپ→سرور). نخِ اصلیِ خواندن از TUN فقط داده را در صف
 * می‌گذارد و هیچ‌وقت بلاک نمی‌شود.
 */
class TcpConnection(
    private val svc: AsparVpnService,
    val appIp: Int, val appPort: Int,
    val serverIp: Int, val serverPort: Int,
    clientIsn: Long
) {
    private val lock = Object()

    private var localSeq: Long = Random.nextLong(0, 0x7FFFFFFFL) // ISN ما
    private var remoteSeq: Long = (clientIsn + 1) and 0xFFFFFFFFL  // بایت بعدیِ موردانتظار از اپ
    @Volatile private var appAcked: Long = 0
    @Volatile private var appWindow: Int = 65535

    @Volatile private var established = false
    @Volatile private var appFin = false
    @Volatile private var serverFin = false
    @Volatile var closed = false
        private set

    private var upstream: Socket? = null
    private val outQueue = LinkedBlockingQueue<ByteArray>(512)
    private val FIN_MARKER = ByteArray(0)

    private val isHttps = serverPort == 443
    @Volatile private var firstPayloadSeen = false

    private val window = 65535

    fun start() {
        thread(name = "up-connect") {
            val sock = Socket()
            try {
                // ابتدا bind تا file descriptor ساخته شود، سپس protect
                try { sock.bind(InetSocketAddress(0)) } catch (_: Throwable) {}
                if (!svc.protect(sock)) svc.logProtectFailOnce()
                sock.tcpNoDelay = true
                sock.connect(InetSocketAddress(Packets.ipToString(serverIp), serverPort), 8000)
                upstream = sock
                synchronized(lock) {
                    // SYN-ACK
                    val isn = localSeq
                    sendPacket(isn, remoteSeq, Packets.SYN or Packets.ACK, null, 0, 0, mss = 1460)
                    localSeq = (isn + 1) and 0xFFFFFFFFL
                    appAcked = localSeq // هنوز چیزی نفرستاده‌ایم؛ unacked = 0
                    established = true
                }
                startPumps()
            } catch (e: Throwable) {
                svc.log("اتصال ناموفق ${Packets.ipToString(serverIp)}:$serverPort → ${e.message}")
                sendRst()
                svc.removeConnection(this)
                try { sock.close() } catch (_: Throwable) {}
            }
        }
    }

    private fun startPumps() {
        // نخِ نوشتن: اپ → سرور
        thread(name = "up-writer") {
            try {
                val out = upstream!!.getOutputStream()
                while (!closed) {
                    val chunk = outQueue.take()
                    if (chunk === FIN_MARKER) {
                        try { upstream!!.shutdownOutput() } catch (_: Throwable) {}
                        continue
                    }
                    writeUpstream(out, chunk)
                }
            } catch (e: Throwable) {
                closeAll("writer: ${e.message}")
            }
        }
        // نخِ خواندن: سرور → اپ
        thread(name = "up-reader") {
            val buf = ByteArray(1400) // ≤ MSS
            try {
                val input = upstream!!.getInputStream()
                while (!closed) {
                    val n = input.read(buf)
                    if (n < 0) {
                        // EOF از سرور → FIN به اپ
                        synchronized(lock) {
                            sendPacket(localSeq, remoteSeq, Packets.FIN or Packets.ACK, null, 0, 0)
                            localSeq = (localSeq + 1) and 0xFFFFFFFFL
                            serverFin = true
                        }
                        break
                    }
                    if (n == 0) continue
                    awaitWindow(n)
                    if (closed) break
                    synchronized(lock) {
                        sendPacket(localSeq, remoteSeq, Packets.PSH or Packets.ACK, buf, 0, n)
                        localSeq = (localSeq + n) and 0xFFFFFFFFL
                    }
                }
            } catch (e: Throwable) {
                closeAll("reader: ${e.message}")
            }
        }
    }

    /** نوشتن به بالادست با شکوندنِ ClientHello روی اولین پکتِ HTTPS. */
    private fun writeUpstream(out: java.io.OutputStream, data: ByteArray) {
        if (isHttps && !firstPayloadSeen) {
            firstPayloadSeen = true
            if (TlsSplit.isTlsClientHello(data, 0, data.size)) {
                var splitAt = TlsSplit.sniSplitOffset(data, 0, data.size)
                if (splitAt <= 0 || splitAt >= data.size) {
                    // نقطه‌ی پیش‌فرض: کمی بعد از هدرِ رکورد
                    splitAt = if (data.size > 10) 3 else data.size / 2
                }
                try {
                    out.write(data, 0, splitAt)
                    out.flush()
                    Thread.sleep(12) // فاصله تا سگمنتِ اول قطعاً جدا برود
                    out.write(data, splitAt, data.size - splitAt)
                    out.flush()
                    svc.log("ClientHello شکسته شد در بایت $splitAt (${data.size} بایت)")
                    return
                } catch (e: Throwable) {
                    throw e
                }
            }
        }
        out.write(data)
        out.flush()
    }

    /** منتظر می‌ماند تا پنجره‌ی اپ جا برای n بایتِ تازه داشته باشد. */
    private fun awaitWindow(n: Int) {
        synchronized(lock) {
            var waited = 0
            while (!closed) {
                val unacked = (localSeq - appAcked) and 0xFFFFFFFFL
                if (unacked + n <= appWindow.coerceAtLeast(n)) return
                lock.wait(200)
                waited += 200
                if (waited > 10000) return // جلوگیری از گیرکردنِ ابدی
            }
        }
    }

    /** پکتی از اپ رسید که به این اتصال تعلق دارد (روی نخِ خواندنِ TUN). */
    fun onAppPacket(
        flags: Int, seq: Long, ack: Long, win: Int,
        payload: ByteArray, off: Int, len: Int
    ) {
        if (closed) return
        synchronized(lock) {
            // جلو رفتن ACK (با نادیده‌گرفتنِ wraparound که در عمل رخ نمی‌دهد)
            if (ack >= appAcked) appAcked = ack
            appWindow = win
            lock.notifyAll()
        }

        if ((flags and Packets.RST) != 0) {
            closeAll("اپ RST فرستاد")
            return
        }

        if ((flags and Packets.SYN) != 0 && !established) {
            // SYNِ تکراری تا وقتی هنوز SYN-ACK نفرستاده‌ایم؛ نادیده (هنوز در حال اتصالیم)
            return
        }

        if (len > 0) {
            synchronized(lock) {
                if (seq == remoteSeq) {
                    val copy = ByteArray(len)
                    System.arraycopy(payload, off, copy, 0, len)
                    if (outQueue.offer(copy)) {
                        remoteSeq = (remoteSeq + len) and 0xFFFFFFFFL
                        sendPacket(localSeq, remoteSeq, Packets.ACK, null, 0, 0)
                    }
                    // اگر صف پر بود: ACK نمی‌دهیم تا اپ دوباره بفرستد (کنترل جریان)
                } else {
                    // خارج از ترتیب یا تکراری → فقط دوباره ACK بده
                    sendPacket(localSeq, remoteSeq, Packets.ACK, null, 0, 0)
                }
            }
        }

        if ((flags and Packets.FIN) != 0 && !appFin) {
            synchronized(lock) {
                appFin = true
                remoteSeq = (remoteSeq + 1) and 0xFFFFFFFFL
                sendPacket(localSeq, remoteSeq, Packets.ACK, null, 0, 0)
            }
            outQueue.offer(FIN_MARKER) // به سرور بگو نوشتن تمام شد
            if (serverFin) closeAll("هر دو سمت FIN")
        }
    }

    private fun sendPacket(seq: Long, ack: Long, flags: Int, p: ByteArray?, off: Int, len: Int, mss: Int = -1) {
        val pkt = Packets.buildTcp(
            serverIp, serverPort, appIp, appPort,
            seq and 0xFFFFFFFFL, ack and 0xFFFFFFFFL,
            flags, window, p, off, len, mss
        )
        svc.writeToTun(pkt)
    }

    private fun sendRst() {
        try {
            val pkt = Packets.buildTcp(
                serverIp, serverPort, appIp, appPort,
                localSeq and 0xFFFFFFFFL, remoteSeq and 0xFFFFFFFFL,
                Packets.RST or Packets.ACK, window, null, 0, 0
            )
            svc.writeToTun(pkt)
        } catch (_: Throwable) {}
    }

    fun closeAll(reason: String) {
        if (closed) return
        closed = true
        synchronized(lock) { lock.notifyAll() }
        try { upstream?.close() } catch (_: Throwable) {}
        outQueue.offer(ByteArray(0))
        svc.removeConnection(this)
    }
}
