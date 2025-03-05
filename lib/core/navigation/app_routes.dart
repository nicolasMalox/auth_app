import 'package:flutter/material.dart';
import 'package:flutter_popcorn_app/presentation/screens/auth_screen.dart';

class AppRoutes {
  static const String authScreen = '/auth_screeb';

  static Map<String, WidgetBuilder> get routes => {
        authScreen: AuthScreen.builder,
      };
}
