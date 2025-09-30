// lib/src/auth_client.dart
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'http_client.dart';
import 'config.dart';
import 'models.dart';
import 'storage.dart';
import '../util/logger.dart';

class AuthClient {
  final AuthConfig config;
  final TokenStorage storage;
  final http.Client _plain = http.Client();

  AuthClient({required this.config, required this.storage});

  // ============= Helpers =============
  Map<String, dynamic> _decodePayload(String jwt) {
    final p = jwt.split('.')[1];
    final payload = utf8.decode(base64Url.decode(base64Url.normalize(p)));
    return json.decode(payload) as Map<String, dynamic>;
    }

  Future<bool> _isExpired(String jwt, {Duration leeway = const Duration(seconds: 15)}) async {
    try {
      final payload = _decodePayload(jwt);
      final exp = payload['exp'] as int?;
      if (exp == null) return true;
      final expDt = DateTime.fromMillisecondsSinceEpoch(exp * 1000).subtract(leeway);
      return DateTime.now().isAfter(expDt);
    } catch (_) { return true; }
  }

  Future<http.Response> _postJson(Uri url, Map<String, dynamic> body) {
    return _plain.post(
      url,
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(body),
    );
  }

  String _err(http.Response r) {
    try {
      final e = jsonDecode(r.body);
      // intenta leer varios campos típicos
      return (e['code'] ??
              e['error'] ??
              e['message'] ??
              e['detail'] ??
              'HTTP ${r.statusCode}')
          .toString();
    } catch (_) {
      return 'HTTP ${r.statusCode}';
    }
  }

 // ============= Session Core =============
  Future<bool> ensureSession() async {
    final jwt = await storage.readAccess();
    if (jwt != null && !(await _isExpired(jwt, leeway: config.accessLeeway))) return true;
    return await _refresh();
  }

  Future<bool> _refresh() async {
    final rt = await storage.readRefresh();
    if (rt == null) return false;

    final res = await _postJson(config.endpoint('token'), {
      'refresh_token': rt,
    });

    if (res.statusCode == 200) {
      AppLogger.info('Refresh OK');
      final body = jsonDecode(res.body) as Map<String, dynamic>;
      final t = Tokens.fromJson(body);
      await storage.writeAccess(t.accessToken);
      await storage.writeRefresh(t.refreshToken);
      return true;
    }
    return false;
  }

  // ============= Auth (login / social) =============
  Future<Tokens> login(String email, String password, {bool remember=false}) async {

    final r = await _postJson(config.endpoint('login'), {
      'email': email,
      'password': password,
      'remember': remember,
    });

    if (r.statusCode != 200) throw Exception(_err(r));

    final t = Tokens.fromJson(jsonDecode(r.body) as Map<String, dynamic>);
    await storage.writeAccess(t.accessToken);
    await storage.writeRefresh(t.refreshToken);
    return t;
  }

  Future<Tokens> socialLogin(String provider, String idToken, {bool remember=true}) async {

    final r = await _postJson(config.endpoint('social-login'), {
      'provider': provider,
      'idToken': idToken,
      'remember': remember,
    });
    
    if (r.statusCode != 200) throw Exception(_err(r));

    final t = Tokens.fromJson(jsonDecode(r.body) as Map<String, dynamic>);
    await storage.writeAccess(t.accessToken);
    await storage.writeRefresh(t.refreshToken);
    return t;
  }

  // ============= Profile =============
  Future<Map<String,dynamic>> me() async {
    // aseguro sesión
    if (!await ensureSession()) throw Exception('No session');

    final client = AuthHttpClient(
      http.Client(), 
      storage, 
      () async {
        final ok = await _refresh();
        return ok ? await storage.readAccess() : null;
      }, 
      config
    );

    final r = await client.get(config.endpoint('me'));
    if (r.statusCode != 200) throw Exception(_err(r));
    return jsonDecode(r.body) as Map<String, dynamic>;
  }

  // ============= New endpoints =============
  /// Registro de usuario.
  /// Devuelve el JSON del backend (p.ej. { message, otp?, userId? }).
  Future<Map<String, dynamic>> register({
    required String email,
    required String password,
    String? name,
    String? phone,

  }) async {
    final r = await _postJson(config.endpoint('register'), {
      'email': email,
      'password': password,
      if (name != null) 'name': name,
      if (phone != null) 'phone': phone,
    });

    // algunos backends devuelven 201 Created
    if (r.statusCode != 200 && r.statusCode != 201) {
      throw Exception(_err(r));
    }
    return jsonDecode(r.body) as Map<String, dynamic>;
  }

  /// Verifica email con un código/OTP enviado por correo.
  Future<void> verifyEmail(String email,String code) async {
    final r = await _postJson(config.endpoint('verify-email'), {
      'email': email,
      'code': code, // o 'otp' según tu backend; mantené paridad en ORDS
    });

    if (r.statusCode != 200 && r.statusCode != 204) {
      throw Exception(_err(r));
    }
  }

  /// Dispara el mail de recuperación de contraseña.
  Future<void> forgotPassword(String email) async {
    final r = await _postJson(config.endpoint('forgot-password'), {
      'email': email,
    });

    if (r.statusCode != 200 && r.statusCode != 204) {
      throw Exception(_err(r));
    }
  }

  /// Resetea la contraseña con el código/OTP recibido por mail.
  Future<void> resetPassword({
    required String email,
    required String code,
    required String newPassword,
  }) async {
    final r = await _postJson(config.endpoint('reset-password'), {
      'email': email,
      'code': code, // o 'otp' según ORDS
      'newPassword': newPassword,
    });

    if (r.statusCode != 200 && r.statusCode != 204) {
      throw Exception(_err(r));
    }
  }

  /// Agrega contraseña a una cuenta social (requiere sesión activa).
  /// Si el backend devuelve tokens nuevos, los guarda; si no, solo 204.
  Future<void> addPassword({
    required String password,
    bool remember = true,
  }) async {
    if (!await ensureSession()) throw Exception('No session');

    final client = AuthHttpClient(
      http.Client(),
      storage,
      () async {
        final ok = await _refresh();
        return ok ? await storage.readAccess() : null;
      },
      config,
    );

    final r = await client.post(
      config.endpoint('add-password'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'password': password,
        'remember': remember,
      }),
    );

    if (r.statusCode == 200) {
      // algunos backends devuelven tokens al agregar password
      try {
        final body = jsonDecode(r.body) as Map<String, dynamic>;
        if (body.containsKey('access_token')) {
          final t = Tokens.fromJson(body);
          await storage.writeAccess(t.accessToken);
          await storage.writeRefresh(t.refreshToken);
        }
      } catch (_) {
        // si no es JSON o no tiene tokens, lo ignoramos
      }
      return;
    }

    if (r.statusCode != 204) {
      throw Exception(_err(r));
    }
  }

  // ============= Logout =============
  Future<void> logout() async {
    final rt = await storage.readRefresh();
    if (rt != null) {
      try {
        await _postJson(config.endpoint('logout'), {
          'refresh_token': rt,
        });
      } catch (_) {}
    }
    await storage.clear();
  }


}
