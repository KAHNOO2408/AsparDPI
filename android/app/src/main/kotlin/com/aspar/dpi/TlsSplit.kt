package com.aspar.dpi

/**
 * پیدا کردن محلِ نام سرور (SNI) داخلِ یک ClientHello و تعیینِ نقطه‌ی شکستن.
 *
 * ایده: اگر پکتِ اولِ یک اتصالِ TLS را درست وسطِ رشته‌ی SNI به دو سگمنتِ TCP
 * جدا بشکنیم، DPIِ ساده‌ای که SNI را فقط داخلِ یک پکت می‌خواند دیگر نمی‌تواند
 * نام دامنه را تطبیق بدهد و اتصال را ریست نمی‌کند.
 */
object TlsSplit {

    private fun u8(b: ByteArray, i: Int) = b[i].toInt() and 0xFF
    private fun u16(b: ByteArray, i: Int) = (u8(b, i) shl 8) or u8(b, i + 1)

    /** آیا این دیتا با رکوردِ handshake از نوع TLS شروع می‌شود؟ (0x16 و نسخه 0x03xx) */
    fun isTlsClientHello(data: ByteArray, off: Int, len: Int): Boolean {
        if (len < 6) return false
        return u8(data, off) == 0x16 && u8(data, off + 1) == 0x03
    }

    /**
     * محلِ تقریبیِ وسطِ SNI را برمی‌گرداند (offset مطلق داخلِ data از ابتدای off).
     * اگر نتواند SNI را پارس کند، -1 می‌دهد تا از نقطه‌ی پیش‌فرض استفاده شود.
     */
    fun sniSplitOffset(data: ByteArray, off: Int, len: Int): Int {
        try {
            var p = off
            val end = off + len
            // رکورد TLS: type(1) version(2) length(2)
            if (end - p < 5) return -1
            p += 5 // از هدر رکورد رد شو
            // handshake: type(1)=0x01 length(3)
            if (end - p < 4) return -1
            if (u8(data, p) != 0x01) return -1
            p += 4 // type + length
            // client_version(2) + random(32)
            if (end - p < 34) return -1
            p += 34
            // session_id
            if (end - p < 1) return -1
            val sidLen = u8(data, p); p += 1 + sidLen
            // cipher_suites
            if (end - p < 2) return -1
            val csLen = u16(data, p); p += 2 + csLen
            // compression_methods
            if (end - p < 1) return -1
            val cmLen = u8(data, p); p += 1 + cmLen
            // extensions
            if (end - p < 2) return -1
            var extTotal = u16(data, p); p += 2
            val extEnd = minOf(p + extTotal, end)
            while (p + 4 <= extEnd) {
                val extType = u16(data, p)
                val extLen = u16(data, p + 2)
                val extDataStart = p + 4
                if (extType == 0x0000) {
                    // server_name extension
                    // server_name_list length(2)
                    var q = extDataStart
                    if (q + 2 > end) return -1
                    q += 2 // list length
                    // name_type(1) + name_length(2)
                    if (q + 3 > end) return -1
                    q += 1 // name_type (0 = host_name)
                    val nameLen = u16(data, q); q += 2
                    val nameStart = q
                    if (nameStart + nameLen > end) return -1
                    // وسطِ نام دامنه را نقطه‌ی شکست می‌گیریم
                    return nameStart + (nameLen / 2)
                }
                p = extDataStart + extLen
            }
            return -1
        } catch (_: Throwable) {
            return -1
        }
    }
}
