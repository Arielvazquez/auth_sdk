import 'package:flutter/foundation.dart';

class AppLogger {
  static const _reset = '\x1B[0m';
  static const _green = '\x1B[32m';
  static const _yellow = '\x1B[33m';
  static const _red = '\x1B[31m';
  static const _blue = '\x1B[34m';

  static void info(String message) {
    debugPrint('$_green[INFO]$message$_reset');
  }

  static void warn(String message) {
    debugPrint('$_yellow[WARN]$message$_reset');
  }

  static void error(String message, [Object? err, StackTrace? st]) {
    debugPrint('$_red[ERROR]$message$_reset');
    if (err != null) debugPrint('   $_red$err$_reset');
    if (st != null) debugPrint('   $_red$st$_reset');
  }

  static void debug(String message) {
    debugPrint('$_blue[DEBUG]$message$_reset');
  }
}
