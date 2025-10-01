// lib/src/config.dart
class AuthConfig {
  final Uri baseUrl;            // e.g. https://globa.space/ords/corpus/auth/
  final Duration accessLeeway;  // margen para exp
  final String? iosGoogleClientId;
  final String? webGoogleClientId;

  const AuthConfig._({
    required this.baseUrl,
    this.accessLeeway = const Duration(seconds: 15),
    this.iosGoogleClientId,
    this.webGoogleClientId,
  });

  factory AuthConfig({
    required Uri baseUrl,
    Duration accessLeeway = const Duration(seconds: 15),
    String? iosGoogleClientId,
    String? webGoogleClientId,
  }) {
    // Normaliza: asegura / final para que Uri.resolve() no pierda el último segmento
    final normalized = baseUrl.replace(
      path: baseUrl.path.endsWith('/') ? baseUrl.path : '${baseUrl.path}/',
    );
    return AuthConfig._(
      baseUrl: normalized,
      accessLeeway: accessLeeway,
      iosGoogleClientId: iosGoogleClientId,
      webGoogleClientId: webGoogleClientId,
    );
  }

  Uri endpoint(String path) {
    final p = path.startsWith('/') ? path.substring(1) : path;
    return baseUrl.resolve(p);
  }
}
