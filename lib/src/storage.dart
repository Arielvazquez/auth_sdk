// lib/src/storage.dart
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

abstract class TokenStorage {
  Future<void> writeAccess(String token);
  Future<void> writeRefresh(String? token);
  Future<String?> readAccess();
  Future<String?> readRefresh();
  Future<void> clear();
}

/// Tokens en el almacenamiento seguro del sistema.
/// - Android: las opciones por defecto de `flutter_secure_storage` 9, que
///   cifran con una clave AES envuelta por una clave RSA del Android Keystore.
///   No se usa `encryptedSharedPreferences`: es de Jetpack Security, que
///   Google deprecó, y el plugin trasladaría lo ya guardado a otro archivo
///   (la app que use este SDK con otras opciones dejaría de encontrarlo).
/// - iOS: Keychain accesible después del primer desbloqueo y solo en este
///   dispositivo (no viaja en backups ni a otro iPhone). Ojo: el Keychain
///   sobrevive a la desinstalación; la app conviene que llame a [clear] la
///   primera vez que se abre después de instalarla.
class SecureStorage implements TokenStorage {
  final _s = const FlutterSecureStorage(
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
  );
  @override Future<void> writeAccess(String t) => _s.write(key:'jwt', value:t);
  @override Future<void> writeRefresh(String? t) async {
    if (t==null) { await _s.delete(key:'refresh'); } else { await _s.write(key:'refresh', value:t); }
  }
  @override Future<String?> readAccess()=> _s.read(key:'jwt');
  @override Future<String?> readRefresh()=> _s.read(key:'refresh');
  @override Future<void> clear() async { await _s.delete(key:'jwt'); await _s.delete(key:'refresh'); }
}
