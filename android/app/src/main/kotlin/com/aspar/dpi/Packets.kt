package com.aspar.dpi

/**
 * ابزارهای سطح‌پایین برای خواندن و ساختن پکت‌های IPv4 / TCP / UDP.
 * همه‌چیز big-endian است (ترتیب بایت شبکه).
 *
 * فقط IPv4 بدون option پشتیبانی می‌شود (که برای TUN کافی است).
 */
object Packets {

    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    // ---- خواندن از بایت‌آرایه ----

    fun u8(b: ByteArray, i: Int): Int = b[i].toInt() and 0xFF
    fun u16(b: ByteArray, i: Int): Int = (u8(b, i) shl 8) or u8(b, i + 1)
    fun u32(b: ByteArray, i: Int): Long =
        ((u8(b, i).toLong() shl 24) or (u8(b, i + 1).toLong() shl 16) or
            (u8(b, i + 2).toLong() shl 8) or u8(b, i + 3).toLong())

    fun ipVersion(b: ByteArray): Int = (u8(b, 0) ushr 4)
    fun ipHeaderLen(b: ByteArray): Int = (u8(b, 0) and 0x0F) * 4
    fun ipProtocol(b: ByteArray): Int = u8(b, 9)
    fun ipTotalLen(b: ByteArray): Int = u16(b, 2)
    fun srcIp(b: ByteArray): Int = u32(b, 12).toInt()
    fun dstIp(b: ByteArray): Int = u32(b, 16).toInt()

    fun ipToString(ip: Int): String {
        return "${(ip ushr 24) and 0xFF}.${(ip ushr 16) and 0xFF}.${(ip ushr 8) and 0xFF}.${ip and 0xFF}"
    }

    // ---- چک‌سام ----

    /** چک‌سام استانداردِ یک‌متمم ۱۶بیتی روی بازه‌ای از آرایه. */
    private fun checksum(data: ByteArray, offset: Int, length: Int, initial: Long): Int {
        var sum = initial
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFF).toInt()
    }

    private fun writeU16(b: ByteArray, i: Int, v: Int) {
        b[i] = ((v ushr 8) and 0xFF).toByte()
        b[i + 1] = (v and 0xFF).toByte()
    }

    private fun writeU32(b: ByteArray, i: Int, v: Long) {
        b[i] = ((v ushr 24) and 0xFF).toByte()
        b[i + 1] = ((v ushr 16) and 0xFF).toByte()
        b[i + 2] = ((v ushr 8) and 0xFF).toByte()
        b[i + 3] = (v and 0xFF).toByte()
    }

    private fun writeU32(b: ByteArray, i: Int, v: Int) = writeU32(b, i, v.toLong() and 0xFFFFFFFFL)

    // ---- ساختن پکت TCP (جهت سرور→اپ) ----

    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10

    /**
     * یک پکت کاملِ IPv4+TCP می‌سازد.
     * srcIp/srcPort و dstIp/dstPort به ترتیبِ همان پکتی هستند که می‌سازیم
     * (یعنی برای جهت سرور→اپ: src = سرور، dst = اپ).
     */
    fun buildTcp(
        srcIp: Int, srcPort: Int,
        dstIp: Int, dstPort: Int,
        seq: Long, ack: Long,
        flags: Int, window: Int,
        payload: ByteArray?, payloadOff: Int, payloadLen: Int,
        mss: Int = -1
    ): ByteArray {
        val hasMss = mss > 0
        val tcpOptLen = if (hasMss) 4 else 0
        val tcpHeaderLen = 20 + tcpOptLen
        val total = 20 + tcpHeaderLen + payloadLen
        val b = ByteArray(total)

        // IPv4 header
        b[0] = 0x45
        b[1] = 0
        writeU16(b, 2, total)
        writeU16(b, 4, 0)
        writeU16(b, 6, 0x4000) // DF
        b[8] = 64 // TTL
        b[9] = PROTO_TCP.toByte()
        writeU16(b, 10, 0) // checksum placeholder
        writeU32(b, 12, srcIp)
        writeU32(b, 16, dstIp)

        val ipHdr = 20
        // TCP header
        writeU16(b, ipHdr + 0, srcPort)
        writeU16(b, ipHdr + 2, dstPort)
        writeU32(b, ipHdr + 4, seq)
        writeU32(b, ipHdr + 8, ack)
        b[ipHdr + 12] = ((tcpHeaderLen / 4) shl 4).toByte()
        b[ipHdr + 13] = flags.toByte()
        writeU16(b, ipHdr + 14, window)
        writeU16(b, ipHdr + 16, 0) // tcp checksum placeholder
        writeU16(b, ipHdr + 18, 0) // urgent
        if (hasMss) {
            b[ipHdr + 20] = 2 // kind=MSS
            b[ipHdr + 21] = 4 // len
            writeU16(b, ipHdr + 22, mss)
        }
        if (payload != null && payloadLen > 0) {
            System.arraycopy(payload, payloadOff, b, ipHdr + tcpHeaderLen, payloadLen)
        }

        // IP checksum
        writeU16(b, 10, checksum(b, 0, 20, 0))

        // TCP checksum با pseudo-header
        val tcpLen = tcpHeaderLen + payloadLen
        var pseudo = 0L
        pseudo += ((srcIp ushr 16) and 0xFFFF).toLong()
        pseudo += (srcIp and 0xFFFF).toLong()
        pseudo += ((dstIp ushr 16) and 0xFFFF).toLong()
        pseudo += (dstIp and 0xFFFF).toLong()
        pseudo += PROTO_TCP.toLong()
        pseudo += tcpLen.toLong()
        writeU16(b, ipHdr + 16, checksum(b, ipHdr, tcpLen, pseudo))

        return b
    }

    /** یک پکت IPv4+UDP می‌سازد (جهت سرور→اپ). */
    fun buildUdp(
        srcIp: Int, srcPort: Int,
        dstIp: Int, dstPort: Int,
        payload: ByteArray, payloadOff: Int, payloadLen: Int
    ): ByteArray {
        val udpLen = 8 + payloadLen
        val total = 20 + udpLen
        val b = ByteArray(total)

        b[0] = 0x45
        b[1] = 0
        writeU16(b, 2, total)
        writeU16(b, 4, 0)
        writeU16(b, 6, 0x4000)
        b[8] = 64
        b[9] = PROTO_UDP.toByte()
        writeU16(b, 10, 0)
        writeU32(b, 12, srcIp)
        writeU32(b, 16, dstIp)

        val ipHdr = 20
        writeU16(b, ipHdr + 0, srcPort)
        writeU16(b, ipHdr + 2, dstPort)
        writeU16(b, ipHdr + 4, udpLen)
        writeU16(b, ipHdr + 6, 0) // checksum placeholder
        System.arraycopy(payload, payloadOff, b, ipHdr + 8, payloadLen)

        writeU16(b, 10, checksum(b, 0, 20, 0))

        var pseudo = 0L
        pseudo += ((srcIp ushr 16) and 0xFFFF).toLong()
        pseudo += (srcIp and 0xFFFF).toLong()
        pseudo += ((dstIp ushr 16) and 0xFFFF).toLong()
        pseudo += (dstIp and 0xFFFF).toLong()
        pseudo += PROTO_UDP.toLong()
        pseudo += udpLen.toLong()
        var csum = checksum(b, ipHdr, udpLen, pseudo)
        if (csum == 0) csum = 0xFFFF
        writeU16(b, ipHdr + 6, csum)

        return b
    }
}
