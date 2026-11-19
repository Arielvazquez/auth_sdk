import 'package:google_sign_in/google_sign_in.dart';

class GoogleSignInAdapter {
  static Future<String> signInAndGetIdToken({
    String? iosClientId,
    required String webClientId, // Web OAuth client ID (.apps.googleusercontent.com)
    bool fresh = false,
    // 0.5.0: el de AuthClient.requestNonce(). Google lo pone en el id_token.
    String? nonce,
  }) async {

    final g = GoogleSignIn.instance;

    // Inicializar (v7). Se llama en cada login para pasar el nonce nuevo: en
    // Android `initialize` solo guarda los parámetros (google_sign_in_android
    // 7.2). En iOS no está probado.
    await g.initialize(
      clientId: iosClientId,                 // iOS (opcional)
      serverClientId: webClientId,           // Android/iOS → aud esperado
      nonce: nonce,
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
