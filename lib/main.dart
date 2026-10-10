import 'package:flutter/material.dart';
import 'ui/home_page.dart';

void main() {
  runApp(const AsparDpiApp());
}

class AsparDpiApp extends StatelessWidget {
  const AsparDpiApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'AsparDPI',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF2E7D32),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      home: Directionality(
        textDirection: TextDirection.rtl,
        child: const HomePage(),
      ),
    );
  }
}
