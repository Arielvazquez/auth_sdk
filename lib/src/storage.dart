// lib/src/storage.dart
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

abstract class TokenStorage {
  Future<void> writeAccess(String token);
  Future<void> writeRefresh(String? token);
  Future<String?> readAccess();
  Future<String?> readRefresh();
  Future<void> clear();
}

class SecureStorage implements TokenStorage {
  final _s = const FlutterSecureStorage();
  @override Future<void> writeAccess(String t) => _s.write(key:'jwt', value:t);
  @override Future<void> writeRefresh(String? t) async {
    if (t==null) { await _s.delete(key:'refresh'); } else { await _s.write(key:'refresh', value:t); }
  }
  @override Future<String?> readAccess()=> _s.read(key:'jwt');
  @override Future<String?> readRefresh()=> _s.read(key:'refresh');
  @override Future<void> clear() async { await _s.delete(key:'jwt'); await _s.delete(key:'refresh'); }
}
