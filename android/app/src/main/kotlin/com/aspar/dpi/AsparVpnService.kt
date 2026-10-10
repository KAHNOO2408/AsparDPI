package com.aspar.dpi

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import kotlin.concurrent.thread

class AsparVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.aspar.dpi.START"
        const val ACTION_STOP = "com.aspar.dpi.STOP"
        private const val CHANNEL_ID = "aspar_dpi_vpn"
        private const val NOTIF_ID = 0x5D71
        const val VERSION = "v2 (bind+protect fix)"
        private const val MAX_CONNS = 600
    }

    private var tun: ParcelFileDescriptor? = null
    private var tunIn: FileInputStream? = null
    private var tunOut: FileOutputStream? = null
    private val tunWriteLock = Object()

    @Volatile private var running = false
    private var readerThread: Thread? = null

    private val conns = ConcurrentHashMap<Long, TcpConnection>()
    private val udpPool = Executors.newCachedThreadPool()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }
            else -> startVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        if (running) return
        startForegroundNotif()
        try {
            val builder = Builder()
                .setSession("AsparDPI")
                .setMtu(1500)
                .addAddress("10.111.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")
                // IPv6 را هم می‌گیریم ولی drop می‌کنیم تا نشتی/فیلتر نشود
                .addAddress("fd00:111::2", 128)
                .addRoute("::", 0)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                try { builder.addDisallowedApplication(packageName) } catch (_: Throwable) {}
            }

            val pfd = builder.establish() ?: throw IllegalStateException("establish() → null")
            tun = pfd
            tunIn = FileInputStream(pfd.fileDescriptor)
            tunOut = FileOutputStream(pfd.fileDescriptor)
            running = true
            VpnBus.running = true
            VpnBus.log("════ AsparDPI $VERSION ════")
            VpnBus.log("VPN روشن شد — کل ترافیک از تونل رد می‌شود")

            readerThread = thread(name = "tun-reader") { readerLoop() }
        } catch (e: Throwable) {
            VpnBus.log("خطا در روشن‌کردن VPN: ${e.message}")
            stopVpn()
        }
    }

    private fun readerLoop() {
        val input = tunIn ?: return
        val packet = ByteArray(32767)
        try {
            while (running) {
                val n = input.read(packet)
                if (n <= 0) { Thread.sleep(2); continue }
                val version = Packets.ipVersion(packet)
                if (version != 4) continue // IPv6 و غیره را drop می‌کنیم
                val ihl = Packets.ipHeaderLen(packet)
                if (ihl < 20) continue
                val totalLen = Packets.ipTotalLen(packet).coerceAtMost(n)
                when (Packets.ipProtocol(packet)) {
                    Packets.PROTO_TCP -> handleTcp(packet, ihl, totalLen)
                    Packets.PROTO_UDP -> handleUdp(packet, ihl, totalLen)
                }
            }
        } catch (e: Throwable) {
            if (running) VpnBus.log("حلقه‌ی خواندن قطع شد: ${e.message}")
        }
    }

    private fun key(appIp: Int, appPort: Int, srvIp: Int, srvPort: Int): Long {
        // کلیدِ یکتا برای هر چهارتاییِ اتصال
        return (appIp.toLong() and 0xFFFFFFFFL) xor
            ((appPort.toLong() and 0xFFFF) shl 32) xor
            ((srvIp.toLong() and 0xFFFFFFFFL) shl 16) xor
            ((srvPort.toLong() and 0xFFFF) shl 48)
    }

    private fun handleTcp(packet: ByteArray, ihl: Int, totalLen: Int) {
        val appIp = Packets.srcIp(packet)
        val srvIp = Packets.dstIp(packet)
        val appPort = Packets.u16(packet, ihl)
        val srvPort = Packets.u16(packet, ihl + 2)
        val seq = Packets.u32(packet, ihl + 4)
        val ack = Packets.u32(packet, ihl + 8)
        val dataOff = ((Packets.u8(packet, ihl + 12) ushr 4) and 0xF) * 4
        val flags = Packets.u8(packet, ihl + 13)
        val win = Packets.u16(packet, ihl + 14)
        val payloadOff = ihl + dataOff
        val payloadLen = (totalLen - payloadOff).coerceAtLeast(0)

        val k = key(appIp, appPort, srvIp, srvPort)
        var conn = conns[k]

        if ((flags and Packets.SYN) != 0 && (flags and Packets.ACK) == 0 && conn == null) {
            if (conns.size >= MAX_CONNS) return
            conn = TcpConnection(this, appIp, appPort, srvIp, srvPort, seq)
            conns[k] = conn
            conn.start()
            return
        }
        if (conn == null) return
        conn.onAppPacket(flags, seq, ack, win, packet, payloadOff, payloadLen)
    }

    private fun handleUdp(packet: ByteArray, ihl: Int, totalLen: Int) {
        val appIp = Packets.srcIp(packet)
        val srvIp = Packets.dstIp(packet)
        val appPort = Packets.u16(packet, ihl)
        val srvPort = Packets.u16(packet, ihl + 2)

        if (srvPort == 443) return // QUIC را drop می‌کنیم تا اپ‌ها به TLS/TCP برگردند

        val udpLen = Packets.u16(packet, ihl + 4)
        val payloadOff = ihl + 8
        val payloadLen = (udpLen - 8).coerceAtMost(totalLen - payloadOff).coerceAtLeast(0)
        if (payloadLen <= 0) return

        val data = ByteArray(payloadLen)
        System.arraycopy(packet, payloadOff, data, 0, payloadLen)

        if (srvPort == 53) {
            // DNS: روی TCP با شکستن می‌فرستیم تا مسمومیتِ DNS دور بخورد
            udpPool.submit {
                try {
                    val resp = DnsTcp.resolve(srvIp, data) { s -> protect(s) }
                    if (resp != null) {
                        val out = Packets.buildUdp(srvIp, srvPort, appIp, appPort, resp, 0, resp.size)
                        writeToTun(out)
                    }
                } catch (_: Throwable) {
                }
            }
            return
        }

        // سایر UDP: رله‌ی ساده
        udpPool.submit {
            try {
                val ds = DatagramSocket()
                protect(ds)
                ds.soTimeout = 5000
                val dst = InetSocketAddress(InetAddress.getByName(Packets.ipToString(srvIp)), srvPort)
                ds.send(DatagramPacket(data, data.size, dst))
                val resp = ByteArray(2048)
                val rp = DatagramPacket(resp, resp.size)
                ds.receive(rp)
                ds.close()
                val out = Packets.buildUdp(srvIp, srvPort, appIp, appPort, resp, 0, rp.length)
                writeToTun(out)
            } catch (_: Throwable) {
                // تایم‌اوت/خطا → بی‌پاسخ (اپ دوباره تلاش می‌کند)
            }
        }
    }

    fun log(s: String) = VpnBus.log(s)

    private var protectFailLogged = false
    fun logProtectFailOnce() {
        if (!protectFailLogged) {
            protectFailLogged = true
            VpnBus.log("protect() ناموفق — به addDisallowedApplication تکیه می‌شود")
        }
    }

    fun writeToTun(pkt: ByteArray) {
        val out = tunOut ?: return
        synchronized(tunWriteLock) {
            try {
                out.write(pkt)
            } catch (e: Throwable) {
                if (running) VpnBus.log("نوشتن به TUN خطا: ${e.message}")
            }
        }
    }

    fun removeConnection(c: TcpConnection) {
        val k = key(c.appIp, c.appPort, c.serverIp, c.serverPort)
        conns.remove(k, c)
    }

    private fun stopVpn() {
        running = false
        VpnBus.running = false
        for (c in conns.values) {
            try { c.closeAll("توقف VPN") } catch (_: Throwable) {}
        }
        conns.clear()
        try { tunIn?.close() } catch (_: Throwable) {}
        try { tunOut?.close() } catch (_: Throwable) {}
        try { tun?.close() } catch (_: Throwable) {}
        tun = null; tunIn = null; tunOut = null
        VpnBus.log("VPN خاموش شد")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        VpnBus.log("مجوز VPN توسط سیستم لغو شد")
        stopVpn()
        super.onRevoke()
    }

    private fun startForegroundNotif() {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "AsparDPI",
                NotificationManager.IMPORTANCE_LOW
            )
            nm.createNotificationChannel(channel)
        }
        val launch = packageManager.getLaunchIntentForPackage(packageName)
            ?: Intent(this, MainActivity::class.java)
        val openIntent = PendingIntent.getActivity(
            this, 0, launch,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                PendingIntent.FLAG_IMMUTABLE else 0
        )
        val notif: Notification =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                Notification.Builder(this, CHANNEL_ID)
                    .setContentTitle("AsparDPI روشن است")
                    .setContentText("عبور از فیلترینگِ SNI برای همه‌ی اپ‌ها")
                    .setSmallIcon(android.R.drawable.ic_dialog_info)
                    .setContentIntent(openIntent)
                    .setOngoing(true)
                    .build()
            else
                @Suppress("DEPRECATION")
                Notification.Builder(this)
                    .setContentTitle("AsparDPI روشن است")
                    .setContentText("عبور از فیلترینگِ SNI")
                    .setSmallIcon(android.R.drawable.ic_dialog_info)
                    .setContentIntent(openIntent)
                    .build()

        startForeground(NOTIF_ID, notif)
    }
}
