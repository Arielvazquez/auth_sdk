// lib/src/auth_client.dart
import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart' as http;

//import 'http_client.dart';
import 'config.dart';
import 'models.dart';
import 'storage.dart';
import '../util/logger.dart';


/// =====================
/// Excepciones tipadas
/// =====================
sealed class AuthException implements Exception {
  final String code;
  final String message;
  final int? status;
  AuthException(this.code, this.message, {this.status});
  @override
  String toString() => '$code: $message${status != null ? ' (HTTP $status)' : ''}';
}

class BadRequestException extends AuthException { BadRequestException(String code, String msg, {int? status}) : super(code, msg, status: status); }
class InvalidCredentialsException extends AuthException { InvalidCredentialsException(String msg, {int? status}) : super('INVALID_CREDENTIALS', msg, status: status); }
class EmailNotVerifiedException extends AuthException { EmailNotVerifiedException(String msg, {int? status}) : super('EMAIL_NOT_VERIFIED', msg, status: status); }
class InvalidExternalTokenException extends AuthException { InvalidExternalTokenException(String msg, {int? status}) : super('INVALID_EXTERNAL_TOKEN', msg, status: status); }
class InvalidRefreshTokenException extends AuthException { InvalidRefreshTokenException(String msg, {int? status}) : super('INVALID_REFRESH_TOKEN', msg, status: status); }
class InvalidAuthTokenException extends AuthException { InvalidAuthTokenException(String msg, {int? status}) : super('INVALID_AUTH_TOKEN', msg, status: status); }
class AccessDeniedException extends AuthException { AccessDeniedException(String msg, {int? status}) : super('ACCESS_DENIED', msg, status: status); }
class PasswordExistsException extends AuthException { PasswordExistsException(String msg, {int? status}) : super('USER_PASSWORD_EXISTS', msg, status: status); }
class ConflictUserExistsException extends AuthException { ConflictUserExistsException(String msg, {int? status}) : super('EMAIL_ALREADY_EXISTS', msg, status: status); }
class RateLimitedException extends AuthException { RateLimitedException(String msg, {int? status}) : super('RATE_LIMITED', msg, status: status); }
class ServerErrorException extends AuthException { ServerErrorException(String msg, {int? status}) : super('INTERNAL_SERVER_ERROR', msg, status: status); }
class NetworkException extends AuthException { NetworkException(String msg) : super('NETWORK', msg); }
class UnknownAuthException extends AuthException { UnknownAuthException(String msg, {int? status}) : super('UNKNOWN', msg, status: status); }

/// =====================
/// Auth HTTP: helper privado
/// =====================
class _AuthHttp {
  final http.Client _client;
  final Duration timeout;
  _AuthHttp(this._client, {this.timeout = const Duration(seconds: 20)});

  Future<http.Response> postJson(Uri url, Map<String, dynamic> body, {Map<String, String>? headers}) async {
    try {
      return await _client
          .post(url, headers: {'Content-Type': 'application/json', ...?headers}, body: jsonEncode(body))
          .timeout(timeout);
    } on TimeoutException {
      throw NetworkException('Request timed out');
    } on http.ClientException catch (e) {
      throw NetworkException('Client error: ${e.message}');
    } catch (e) {
      throw NetworkException('Network error: $e');
    }
  }

  Future<http.Response> get(Uri url, {Map<String, String>? headers}) async {
    try {
      return await _client.get(url, headers: headers).timeout(timeout);
    } on TimeoutException {
      throw NetworkException('Request timed out');
    } on http.ClientException catch (e) {
      throw NetworkException('Client error: ${e.message}');
    } catch (e) {
      throw NetworkException('Network error: $e');
    }
  }
}


/// =====================
/// AuthClient SDK
/// =====================
class AuthClient {
  final AuthConfig config;
  final TokenStorage storage;
  final _AuthHttp _plain = _AuthHttp(http.Client());


  AuthClient({required this.config, required this.storage});

  // -------- Helpers JWT --------
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

  // -------- Error mapping centralizado ------
  Never _throwFor(http.Response r) {
    String code = 'UNKNOWN';
    String msg = 'HTTP ${r.statusCode}';
    try {
      final e = jsonDecode(r.body) as Map<String, dynamic>;
      code = (e['code'] as String?)?.toUpperCase() ?? code;
      msg  = (e['error'] as String?) ?? (e['message'] as String?) ?? msg;
    } catch (_) {}

    switch (r.statusCode) {
      case 400: throw BadRequestException(code, msg, status: r.statusCode);
      case 401:
        switch (code) {
          case 'INVALID_CREDENTIALS': throw InvalidCredentialsException(msg, status: r.statusCode);
          case 'INVALID_TOKEN': // usado en verify/reset
          case 'INVALID_AUTH_TOKEN': throw InvalidAuthTokenException(msg, status: r.statusCode);
          case 'INVALID_REFRESH_TOKEN': throw InvalidRefreshTokenException(msg, status: r.statusCode);
          default: throw InvalidAuthTokenException(msg, status: r.statusCode);
        }
      case 403:
        if (code == 'EMAIL_NOT_VERIFIED') throw EmailNotVerifiedException(msg, status: r.statusCode);
        throw AccessDeniedException(msg, status: r.statusCode);
      case 409:
        if (code == 'EMAIL_ALREADY_EXISTS') throw ConflictUserExistsException(msg, status: r.statusCode);
        if (code == 'USER_PASSWORD_EXISTS') throw PasswordExistsException(msg, status: r.statusCode);
        throw ConflictUserExistsException(msg, status: r.statusCode);
      case 429: throw RateLimitedException(msg, status: r.statusCode);
      case 500: throw ServerErrorException(msg, status: r.statusCode);
      default:  throw UnknownAuthException(msg, status: r.statusCode);
    }
  }

  // -------- Refresh token flow (/token → TokensPartial) --------
  Future<bool> _refresh() async {
    final rt = await storage.readRefresh();
    if (rt == null) return false;

    final r = await _plain.postJson(config.endpoint('token'), {
      'refresh_token': rt,
    });

    if (r.statusCode == 200) {
      AppLogger.info('Refresh OK');
      final body = jsonDecode(r.body) as Map<String, dynamic>;
      final t = TokensPartial.fromJson(body); // access_token + expires_in
      await storage.writeAccess(t.accessToken);
      // El refresh token NO cambia en /token (según OpenAPI), no lo tocamos.
      return true;
    }

    // Si falla, limpiamos el access (no el refresh, por si el caller quiere intentar logout)
    await storage.writeAccess('');
    // Propagamos error específico
    _throwFor(r);
  }

  // -------- Sesión --------
  Future<bool> ensureSession() async {
    final jwt = await storage.readAccess();
    if (jwt != null && jwt.isNotEmpty && !(await _isExpired(jwt, leeway: config.accessLeeway))) {
      return true;
    }
    return await _refresh();
  }

  // -------- Cliente autenticado con retry 401 --------
  Future<http.Response> _authedGet(Uri url) async {
    Future<Map<String, String>> _hdrs() async => {
      'Authorization': 'Bearer ${await storage.readAccess()}',
    };
    final c = _AuthHttp(http.Client());
    final first = await c.get(url, headers: await _hdrs());
    if (first.statusCode != 401) return first;

    final ok = await _refresh();
    if (!ok) return first;

    final second = await c.get(url, headers: await _hdrs());
    return second;
  }

  Future<http.Response> _authedPost(Uri url, Map<String, dynamic> body) async {
    Future<Map<String, String>> _hdrs() async => {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ${await storage.readAccess()}',
    };
    final c = _AuthHttp(http.Client());
    final first = await c.postJson(url, body, headers: await _hdrs());
    if (first.statusCode != 401) return first;

    final ok = await _refresh();
    if (!ok) return first;

    final second = await c.postJson(url, body, headers: await _hdrs());
    return second;
  }

  // =========================
  // Endpoints públicos
  // =========================
  Future<Map<String, dynamic>> register({
    required String email,
    required String password,
    String? name,
    String? phone,
  }) async {
    final r = await _plain.postJson(config.endpoint('register'), {
      'email': email,
      'password': password,
      if (name != null) 'name': name,
      if (phone != null) 'phone': phone,
    });

    if (r.statusCode == 200 || r.statusCode == 201) {
      return jsonDecode(r.body) as Map<String, dynamic>;
    }
    _throwFor(r);
  }

  Future<void> verifyEmail(String email, String code) async {
    final r = await _plain.postJson(config.endpoint('verify-email'), {
      'email': email,
      'code': code,
    });
    if (r.statusCode == 200) return;
    _throwFor(r);
  }

  Future<void> forgotPassword(String email) async {
    final r = await _plain.postJson(config.endpoint('forgot-password'), {
      'email': email,
    });
    if (r.statusCode == 200) return;
    _throwFor(r);
  }

  Future<void> resetPassword({
    required String email,
    required String code,
    required String newPassword,
  }) async {
    final r = await _plain.postJson(config.endpoint('reset-password'), {
      'email': email,
      'code': code,
      'new_password': newPassword,
    });
    if (r.statusCode == 200) return;
    _throwFor(r);
  }

  // =========================
  // Auth (login / social)
  // =========================
  Future<Tokens> login(String email, String password, {bool remember = false}) async {
    final r = await _plain.postJson(config.endpoint('login'), {
      'email': email,
      'password': password,
      'remember': remember,
    });

    if (r.statusCode == 200) {
      final t = Tokens.fromJson(jsonDecode(r.body) as Map<String, dynamic>);
      await storage.writeAccess(t.accessToken);
      await storage.writeRefresh(t.refreshToken);
      return t;
    }
    _throwFor(r);
  }

  Future<Tokens> socialLogin(String provider, String idToken, {bool remember = true}) async {
    final r = await _plain.postJson(config.endpoint('social-login'), {
      'provider': provider,   // 'google' | 'apple'
      'id_token': idToken,    // <- snake_case según OpenAPI
      'remember': remember,
    });

    if (r.statusCode == 200) {
      final t = Tokens.fromJson(jsonDecode(r.body) as Map<String, dynamic>);
      await storage.writeAccess(t.accessToken);
      await storage.writeRefresh(t.refreshToken);
      return t;
    }
    _throwFor(r);
  }

  // =========================
  // Autenticado
  // =========================
  Future<Map<String, dynamic>> me() async {
    if (!await ensureSession()) {
      throw InvalidAuthTokenException('No active session');
    }
    final r = await _authedGet(config.endpoint('me'));
    if (r.statusCode == 200) {
      return jsonDecode(r.body) as Map<String, dynamic>;
    }
    _throwFor(r);
  }

  Future<void> addPassword({required String newPassword}) async {
    if (!await ensureSession()) {
      throw InvalidAuthTokenException('No active session');
    }

    final r = await _authedPost(config.endpoint('add-password'), {
      'new_password': newPassword,
    });

    if (r.statusCode == 200) {
      // Algunos backends podrían devolver tokens nuevos (no está en tu spec, pero lo soportamos).
      try {
        final body = jsonDecode(r.body) as Map<String, dynamic>;
        if (body.containsKey('access_token') && body.containsKey('refresh_token')) {
          final t = Tokens.fromJson(body);
          await storage.writeAccess(t.accessToken);
          await storage.writeRefresh(t.refreshToken);
        }
      } catch (_) {}
      return;
    }
    if (r.statusCode == 204) return; // por si algún backend decide 204
    _throwFor(r);
  }

  // =========================
  // Logout
  // =========================
  Future<void> logout() async {
    final rt = await storage.readRefresh();
    if (rt != null && rt.isNotEmpty) {
      try {
        await _plain.postJson(config.endpoint('logout'), {'refresh_token': rt});
      } catch (_) {
        // Ignoramos errores de red en logout.
      }
    }
    await storage.clear();
  }

  // =========================
  // Test utilitario (opcional)
  // =========================
  Future<Map<String, dynamic>> test() async {
    final r = await _plain.postJson(config.endpoint('test'), {});
    if (r.statusCode == 200 || r.statusCode == 204) {
      if (r.body.isEmpty) return {};
      return jsonDecode(r.body) as Map<String, dynamic>;
    }
    _throwFor(r);
  }

}
