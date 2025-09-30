// lib/src/providers/google_adapter.dart
import 'package:google_sign_in/google_sign_in.dart';

class GoogleSignInAdapter {
  Future<String> signInAndGetIdToken({String? iosClientId, String? webClientId}) async {
    // v7: singleton + initialize opcional
    await GoogleSignIn.instance.initialize(
      clientId: iosClientId,      // si hace falta
      serverClientId: webClientId // si hace falta
    );
    final acc = await GoogleSignIn.instance.authenticate();
    final auth = await acc.authentication;
    final idToken = auth.idToken;
    if (idToken == null) throw Exception('No ID token from Google');
    return idToken;
  }
}
