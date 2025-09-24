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

  // ============= Public API =============
  Future<bool> ensureSession() async {
    final jwt = await storage.readAccess();
    if (jwt != null && !(await _isExpired(jwt, leeway: config.accessLeeway))) return true;
    return await _refresh();
  }

  Future<bool> _refresh() async {
    final rt = await storage.readRefresh();
    if (rt == null) return false;
    final res = await _plain.post(
      config.endpoint('token'),
      headers: {'Content-Type':'application/json'},
      body: jsonEncode({'refresh_token': rt}),
    );
    if (res.statusCode == 200) {
      final body = jsonDecode(res.body);
      AppLogger.info('Login response: $body');
      final t = Tokens.fromJson(body);
      await storage.writeAccess(t.accessToken);
      return true;
    }
    return false;
  }

  Future<Tokens> login(String email, String password, {bool remember=false}) async {
    final r = await _plain.post(
      config.endpoint('login'),
      headers: {'Content-Type':'application/json'},
      body: jsonEncode({'email': email, 'password': password, 'remember': remember}),
    );
    if (r.statusCode != 200) throw Exception(_err(r));
    final t = Tokens.fromJson(jsonDecode(r.body));
    await storage.writeAccess(t.accessToken);
    await storage.writeRefresh(t.refreshToken);
    return t;
  }

  Future<Tokens> socialLogin(String provider, String idToken, {bool remember=true}) async {
    final r = await _plain.post(
      config.endpoint('social-login'),
      headers: {'Content-Type':'application/json'},
      body: jsonEncode({'provider': provider, 'idToken': idToken, 'remember': remember}),
    );
    if (r.statusCode != 200) throw Exception(_err(r));
    final t = Tokens.fromJson(jsonDecode(r.body));
    await storage.writeAccess(t.accessToken);
    await storage.writeRefresh(t.refreshToken);
    return t;
  }

  Future<Map<String,dynamic>> me() async {
    // aseguro sesión
    if (!await ensureSession()) throw Exception('No session');
    final client = AuthHttpClient(http.Client(), storage, () async {
      final ok = await _refresh();
      return ok ? await storage.readAccess() : null;
    }, config);

    final r = await client.get(config.endpoint('me'));
    if (r.statusCode != 200) throw Exception(_err(r));
    return jsonDecode(r.body);

  }

/*
  Future<Map<String,dynamic>> me() async {
    // aseguro sesión
    if (!await ensureSession()) 
      throw Exception('No session');

    Future<http.Response> _call(String token) {
      return _plain.get(
        config.endpoint('me'),
        headers: {
          'Authorization': 'Bearer $token',
          'Accept': 'application/json',
        },
      );
    }

    var jwt = await storage.readAccess();
    if (jwt == null) throw Exception('No token');

    // Primer intento
    var r = await _call(jwt);

    // Si 401, intenta refrescar y reintenta una vez
    if (r.statusCode == 401) {
      final ok = await _refresh();
      if (!ok) throw Exception('Unauthorized');
      jwt = await storage.readAccess();
      if (jwt == null) throw Exception('No token after refresh');
      r = await _call(jwt);
    }

    if (r.statusCode != 200) {
      throw Exception(_err(r));
    }
    return jsonDecode(r.body) as Map<String, dynamic>;
  }
  
*/
  Future<void> logout() async {
    final rt = await storage.readRefresh();
    if (rt != null) {
      try {
        await _plain.post(config.endpoint('logout'),
          headers: {'Content-Type':'application/json'},
          body: jsonEncode({'refresh_token': rt}),
        );
      } catch (_) {}
    }
    await storage.clear();
  }

  String _err(http.Response r) {
    try { final e = jsonDecode(r.body); return e['error'] ?? 'HTTP ${r.statusCode}'; }
    catch (_) { return 'HTTP ${r.statusCode}'; }
  }
}
