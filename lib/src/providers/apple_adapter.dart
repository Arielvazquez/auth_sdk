// lib/src/providers/apple_adapter.dart
import 'package:sign_in_with_apple/sign_in_with_apple.dart';

class AppleSignInAdapter {
  Future<String> signInAndGetIdToken() async {
    final cred = await SignInWithApple.getAppleIDCredential(
      scopes: [AppleIDAuthorizationScopes.email, AppleIDAuthorizationScopes.fullName],
    );
    final idToken = cred.identityToken;
    if (idToken == null) { throw Exception('No identityToken from Apple'); }
    return idToken;
  }
}
