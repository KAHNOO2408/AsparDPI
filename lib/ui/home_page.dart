import 'dart:async';
import 'package:flutter/material.dart';
import '../core/app_version.dart';
import '../core/vpn_controller.dart';

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final _vpn = VpnController();
  final _log = <String>[];
  final _scroll = ScrollController();
  StreamSubscription<String>? _sub;
  bool _running = false;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    _addLog('════ نسخه: $kBuildVersion ════');
    _sub = _vpn.logStream().listen((line) => _addLog(line));
    _refreshState();
  }

  Future<void> _refreshState() async {
    final r = await _vpn.isRunning();
    if (mounted) setState(() => _running = r);
  }

  void _addLog(String line) {
    if (!mounted) return;
    setState(() {
      _log.add(line);
      if (_log.length > 400) _log.removeAt(0);
    });
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scroll.hasClients) {
        _scroll.animateTo(
          _scroll.position.maxScrollExtent,
          duration: const Duration(milliseconds: 200),
          curve: Curves.easeOut,
        );
      }
    });
  }

  Future<void> _toggle() async {
    if (_busy) return;
    setState(() => _busy = true);
    try {
      if (_running) {
        await _vpn.stop();
        setState(() => _running = false);
      } else {
        final granted = await _vpn.prepare();
        if (!granted) {
          _addLog('اجازه‌ی VPN داده نشد');
          return;
        }
        await _vpn.start();
        setState(() => _running = true);
      }
    } catch (e) {
      _addLog('خطا: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  void dispose() {
    _sub?.cancel();
    _scroll.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final version = kBuildVersion.split(' ').first;
    return Scaffold(
      appBar: AppBar(
        title: Text('AsparDPI  ·  $version'),
        centerTitle: true,
      ),
      body: Column(
        children: [
          const SizedBox(height: 24),
          Icon(
            _running ? Icons.shield : Icons.shield_outlined,
            size: 96,
            color: _running ? Colors.greenAccent : Colors.grey,
          ),
          const SizedBox(height: 12),
          Text(
            _running ? 'روشن — ترافیک از تونل رد می‌شود' : 'خاموش',
            style: Theme.of(context).textTheme.titleMedium,
          ),
          const SizedBox(height: 20),
          FilledButton.icon(
            onPressed: _busy ? null : _toggle,
            icon: Icon(_running ? Icons.stop : Icons.play_arrow),
            label: Text(_running ? 'خاموش کردن' : 'روشن کردن'),
            style: FilledButton.styleFrom(
              minimumSize: const Size(220, 52),
              backgroundColor: _running ? Colors.red : Colors.green,
            ),
          ),
          const SizedBox(height: 16),
          const Divider(),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12),
            child: Row(
              children: [
                const Text('لاگ'),
                const Spacer(),
                TextButton(
                  onPressed: () => setState(() => _log.clear()),
                  child: const Text('پاک کردن'),
                ),
              ],
            ),
          ),
          Expanded(
            child: Container(
              margin: const EdgeInsets.fromLTRB(12, 0, 12, 12),
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: Colors.black.withValues(alpha: 0.4),
                borderRadius: BorderRadius.circular(8),
              ),
              child: ListView.builder(
                controller: _scroll,
                itemCount: _log.length,
                itemBuilder: (_, i) => Text(
                  _log[i],
                  textDirection: TextDirection.ltr,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 11.5,
                    color: Colors.greenAccent,
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
