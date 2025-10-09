import 'package:google_sign_in/google_sign_in.dart';

class GoogleSignInAdapter {
  static Future<String> signInAndGetIdToken({
    String? iosClientId,
    required String webClientId, // Web OAuth client ID (.apps.googleusercontent.com)
    bool fresh = false,
  }) async {

    final g = GoogleSignIn.instance;

    // Inicializar (v7)
    await g.initialize(
      clientId: iosClientId,                 // iOS (opcional)
      serverClientId: webClientId,           // Android/iOS → aud esperado
    );

    // Limpieza para evitar reauth/caches raros (MIUI/CM)
    if (fresh) {
      try { await g.disconnect(); } catch (_) {}
      try { await g.signOut(); } catch (_) {}
    }

    final account = await (g.supportsAuthenticate()
          ? g.authenticate()
          : Future.error(UnsupportedError('authenticate() no soportado')));
    
    final token = (await account.authentication).idToken;

    if (token == null || token.isEmpty) {
      throw Exception('No se obtuvo ID token');
    }

    return token;
  }
}
