import 'package:flutter/material.dart';
import 'package:flutter_popcorn_app/core/navigation/app_routes.dart';

void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'Auth App',
      initialRoute: AppRoutes.authScreen,
      routes: AppRoutes.routes,
    );
  }
}
