import 'dart:async';
import 'dart:convert';

import 'package:auth_sdk/auth_sdk.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

class MemoryStorage implements TokenStorage {
  String? access;
  String? refresh;
  MemoryStorage({this.access, this.refresh});
  @override
  Future<void> writeAccess(String token) async => access = token;
  @override
  Future<void> writeRefresh(String? token) async => refresh = token;
  @override
  Future<String?> readAccess() async => access;
  @override
  Future<String?> readRefresh() async => refresh;
  @override
  Future<void> clear() async => access = refresh = null;
}

/// JWT sin firma válida (el SDK solo lee `exp`).
String jwt({required num exp}) {
  String b64(Map<String, dynamic> m) =>
      base64Url.encode(utf8.encode(jsonEncode(m))).replaceAll('=', '');
  return '${b64({'alg': 'HS256'})}.${b64({'sub': '1', 'exp': exp})}.firma';
}

num inSeconds(int s) => DateTime.now().millisecondsSinceEpoch ~/ 1000 + s;

final config = AuthConfig(baseUrl: Uri.parse('https://example.test/auth'));

http.Response json(int status, Map<String, dynamic> body) =>
    http.Response(jsonEncode(body), status, headers: {'content-type': 'application/json'});

void main() {
  group('refresh', () {
    test('si falla, todas las llamadas que esperaban reciben el error (no se cuelgan)', () async {
      var calls = 0;
      final gate = Completer<void>();
      final client = AuthClient(
        config: config,
        storage: MemoryStorage(refresh: 'rt'),
        httpClient: MockClient((req) async {
          calls++;
          await gate.future;
          return json(500, {'code': 'INTERNAL_SERVER_ERROR', 'error': 'x'});
        }),
      );
      final a = client.ensureSession();
      final b = client.ensureSession();
      gate.complete();
      await expectLater(a, throwsA(isA<ServerErrorException>()));
      await expectLater(b, throwsA(isA<ServerErrorException>()))
          .timeout(const Duration(seconds: 2));
      expect(calls, 1);
    });

    test('después de un refresh fallido, el siguiente vuelve a intentar', () async {
      var calls = 0;
      final client = AuthClient(
        config: config,
        storage: MemoryStorage(refresh: 'rt'),
        httpClient: MockClient((req) async {
          calls++;
          if (calls == 1) throw http.ClientException('sin red');
          return json(200, {'access_token': jwt(exp: inSeconds(3600)), 'token_type': 'Bearer', 'expires_in': 3600});
        }),
      );
      await expectLater(client.ensureSession(), throwsA(isA<NetworkException>()));
      expect(await client.ensureSession(), isTrue);
      expect(calls, 2);
    });

    test('401 en /token: lanza InvalidRefreshTokenException y borra los tokens', () async {
      final storage = MemoryStorage(access: jwt(exp: inSeconds(-60)), refresh: 'rt');
      final client = AuthClient(
        config: config,
        storage: storage,
        httpClient: MockClient((req) async =>
            json(401, {'code': 'INVALID_TOKEN', 'error': 'Invalid or expired token.'})),
      );
      await expectLater(client.ensureSession(), throwsA(isA<InvalidRefreshTokenException>()));
      expect(storage.access, isNull);
      expect(storage.refresh, isNull);
    });

    test('sin red o con error del servidor no se borra nada', () async {
      final old = jwt(exp: inSeconds(-60));
      for (final fail in <Future<http.Response> Function()>[
        () async => throw http.ClientException('sin red'),
        () async => json(503, {'code': 'X', 'error': 'caído'}),
      ]) {
        final storage = MemoryStorage(access: old, refresh: 'rt');
        final client = AuthClient(
          config: config,
          storage: storage,
          httpClient: MockClient((req) => fail()),
        );
        await expectLater(client.ensureSession(), throwsA(isA<AuthException>()));
        expect(storage.access, old);
        expect(storage.refresh, 'rt');
      }
    });

    test('pide rotar y guarda el refresh token nuevo', () async {
      final storage = MemoryStorage(refresh: 'viejo');
      Map<String, dynamic>? sent;
      final client = AuthClient(
        config: config,
        storage: storage,
        httpClient: MockClient((req) async {
          sent = jsonDecode(req.body) as Map<String, dynamic>;
          return json(200, {
              'access_token': jwt(exp: inSeconds(3600)),
              'token_type': 'Bearer',
              'expires_in': 3600,
              'refresh_token': 'nuevo',
            });
        }),
      );
      expect(await client.ensureSession(), isTrue);
      expect(sent, {'refresh_token': 'viejo', 'rotate': true});
      expect(storage.refresh, 'nuevo');
    });
  });

  group('refresh proactivo (token por vencer pero todavía válido)', () {
    test('sin red: devuelve true y conserva el token', () async {
      final current = jwt(exp: inSeconds(60));
      final storage = MemoryStorage(access: current, refresh: 'rt');
      final client = AuthClient(
        config: config,
        storage: storage,
        httpClient: MockClient((req) async => throw http.ClientException('sin red')),
      );
      expect(await client.ensureSession(), isTrue);
      expect(storage.access, current);
    });

    test('refresh token rechazado: lanza (la sesión terminó)', () async {
      final client = AuthClient(
        config: config,
        storage: MemoryStorage(access: jwt(exp: inSeconds(60)), refresh: 'rt'),
        httpClient: MockClient((req) async => json(401, {'code': 'INVALID_TOKEN', 'error': 'x'})),
      );
      await expectLater(client.ensureSession(), throwsA(isA<InvalidRefreshTokenException>()));
    });
  });

  test('con el reloj del teléfono corrido no renueva en cada pedido', () async {
    // El servidor va 3 horas atrasado respecto del teléfono: sus tokens de
    // 15 minutos, medidos con el reloj del teléfono, ya vencieron.
    var calls = 0;
    final server = DateTime.now().subtract(const Duration(hours: 3));
    final client = AuthClient(
      config: config,
      storage: MemoryStorage(refresh: 'rt'),
      httpClient: MockClient((req) async {
        calls++;
        final exp = server.millisecondsSinceEpoch ~/ 1000 + 900;
        return json(200, {'access_token': jwt(exp: exp), 'token_type': 'Bearer', 'expires_in': 900});
      }),
    );
    expect(await client.ensureSession(), isTrue); // sin access: renueva
    expect(await client.ensureSession(), isTrue);
    expect(await client.ensureSession(), isTrue);
    expect(calls, 1);
  });

  test('un exp con decimales se lee bien (no se toma como vencido)', () async {
    var calls = 0;
    final client = AuthClient(
      config: config,
      storage: MemoryStorage(access: jwt(exp: inSeconds(3600) + 0.5), refresh: 'rt'),
      httpClient: MockClient((req) async {
        calls++;
        return json(500, {});
      }),
    );
    expect(await client.ensureSession(), isTrue);
    expect(calls, 0);
  });

  test('me() manda el Bearer y, sin token, no manda "Bearer null"', () async {
    final seen = <String?>[];
    final storage = MemoryStorage(access: jwt(exp: inSeconds(3600)));
    final client = AuthClient(
      config: config,
      storage: storage,
      httpClient: MockClient((req) async {
        seen.add(req.headers['Authorization']);
        return json(200, {'id': 1});
      }),
    );
    await client.me();
    expect(seen.single, startsWith('Bearer ey'));
    expect(seen.single, isNot(contains('null')));
  });

  group('AuthConfig', () {
    test('rechaza http contra un servidor', () {
      expect(() => AuthConfig(baseUrl: Uri.parse('http://example.test/auth')), throwsArgumentError);
    });
    test('permite http contra la máquina local o el emulador', () {
      AuthConfig(baseUrl: Uri.parse('http://localhost:8080/auth'));
      AuthConfig(baseUrl: Uri.parse('http://10.0.2.2:8080/auth'));
    });
  });
}
