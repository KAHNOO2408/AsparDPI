import 'package:flutter/services.dart';

/// پلِ بین Flutter و سرویسِ VPNِ کاتلین.
class VpnController {
  static const _control = MethodChannel('aspar/dpi/control');
  static const _logs = EventChannel('aspar/dpi/logs');

  /// استریمِ لاگ‌هایی که سرویسِ کاتلین می‌فرستد.
  Stream<String> logStream() =>
      _logs.receiveBroadcastStream().map((e) => e.toString());

  /// اجازه‌ی VPN را می‌گیرد (در صورت نیاز صفحه‌ی سیستم باز می‌شود).
  Future<bool> prepare() async {
    final ok = await _control.invokeMethod<bool>('prepare');
    return ok ?? false;
  }

  Future<void> start() => _control.invokeMethod('start');

  Future<void> stop() => _control.invokeMethod('stop');

  Future<bool> isRunning() async {
    final r = await _control.invokeMethod<bool>('isRunning');
    return r ?? false;
  }
}
