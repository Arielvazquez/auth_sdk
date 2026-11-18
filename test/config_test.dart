import 'package:auth_sdk/auth_sdk.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  final base = Uri.parse('https://example.test/ords/corpus/auth');

  test('sin idioma, el endpoint no cambia', () {
    final config = AuthConfig(baseUrl: base);
    expect(
      config.endpoint('register').toString(),
      'https://example.test/ords/corpus/auth/register',
    );
  });

  test('con idioma, va como ?lang=', () {
    final config = AuthConfig(baseUrl: base, language: () => 'en');
    expect(
      config.endpoint('forgot-password').toString(),
      'https://example.test/ords/corpus/auth/forgot-password?lang=en',
    );
  });

  test('toma el idioma actual en cada pedido', () {
    var lang = 'es';
    final config = AuthConfig(baseUrl: base, language: () => lang);
    expect(config.endpoint('login').queryParameters['lang'], 'es');
    lang = 'en';
    expect(config.endpoint('login').queryParameters['lang'], 'en');
  });

  test('un idioma vacío no agrega nada', () {
    final config = AuthConfig(baseUrl: base, language: () => ' ');
    expect(config.endpoint('login').hasQuery, isFalse);
  });
}
