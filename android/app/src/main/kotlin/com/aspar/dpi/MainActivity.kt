package com.aspar.dpi

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    private val methodChannelName = "aspar/dpi/control"
    private val eventChannelName = "aspar/dpi/logs"
    private val vpnRequestCode = 0x1A5B

    private var pendingPrepareResult: MethodChannel.Result? = null
    private val main = Handler(Looper.getMainLooper())

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, methodChannelName)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "prepare" -> handlePrepare(result)
                    "start" -> {
                        val intent = Intent(this, AsparVpnService::class.java)
                        intent.action = AsparVpnService.ACTION_START
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                            startForegroundService(intent)
                        } else {
                            startService(intent)
                        }
                        result.success(true)
                    }
                    "stop" -> {
                        val intent = Intent(this, AsparVpnService::class.java)
                        intent.action = AsparVpnService.ACTION_STOP
                        startService(intent)
                        result.success(true)
                    }
                    "isRunning" -> result.success(VpnBus.running)
                    else -> result.notImplemented()
                }
            }

        EventChannel(flutterEngine.dartExecutor.binaryMessenger, eventChannelName)
            .setStreamHandler(object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                    VpnBus.sink = { line ->
                        main.post { events?.success(line) }
                    }
                }

                override fun onCancel(arguments: Any?) {
                    VpnBus.sink = null
                }
            })
    }

    /** اگر مجوز VPN از قبل داده شده true، در غیر این صورت صفحه‌ی اجازه‌ی سیستم را باز می‌کند. */
    private fun handlePrepare(result: MethodChannel.Result) {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            pendingPrepareResult = result
            startActivityForResult(intent, vpnRequestCode)
        } else {
            result.success(true)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == vpnRequestCode) {
            val granted = resultCode == Activity.RESULT_OK
            pendingPrepareResult?.success(granted)
            pendingPrepareResult = null
        }
    }
}
