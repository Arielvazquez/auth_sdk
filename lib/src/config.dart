// lib/src/config.dart
class AuthConfig {
  final Uri baseUrl;            // e.g. https://globa.space/ords/corpus/auth/
  final Duration accessLeeway;  // margen para exp
  final String? iosGoogleClientId;
  final String? webGoogleClientId;

  /// Idioma de la app ("es", "en"…), para que el servidor arme los mails (por
  /// ejemplo, el código de verificación) en ese idioma. Va como `?lang=` en
  /// cada pedido. Es una función para tomar el idioma actual en cada pedido,
  /// por si el usuario lo cambia. Opcional: sin ella, los pedidos no cambian.
  final String Function()? language;

  const AuthConfig._({
    required this.baseUrl,
    this.accessLeeway = const Duration(seconds: 15),
    this.iosGoogleClientId,
    this.webGoogleClientId,
    this.language,
  });

  factory AuthConfig({
    required Uri baseUrl,
    Duration accessLeeway = const Duration(seconds: 15),
    String? iosGoogleClientId,
    String? webGoogleClientId,
    String Function()? language,
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
      language: language,
    );
  }

  Uri endpoint(String path) {
    final p = path.startsWith('/') ? path.substring(1) : path;
    final uri = baseUrl.resolve(p);
    final lang = language?.call().trim();
    if (lang == null || lang.isEmpty) return uri;
    return uri.replace(queryParameters: {...uri.queryParameters, 'lang': lang});
  }
}
