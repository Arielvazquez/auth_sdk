// lib/src/config.dart
class AuthConfig {
  final Uri baseUrl; // ej: https://globa.space/ords/A255429/auth/
  final Duration accessLeeway; // margen al exp
  final String? iosGoogleClientId;
  final String? webGoogleClientId;

  const AuthConfig({
    required this.baseUrl,
    this.accessLeeway = const Duration(seconds: 15),
    this.iosGoogleClientId,
    this.webGoogleClientId,
  });

  Uri endpoint(String path) => baseUrl.resolve(path);
}
