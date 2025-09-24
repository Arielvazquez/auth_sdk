// lib/src/http_client.dart
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'storage.dart';
import 'config.dart';

typedef TokenRefresher = Future<String?> Function();

class AuthHttpClient extends http.BaseClient {
  final http.Client _inner;
  final TokenStorage _storage;
  final TokenRefresher _refresh;
  final AuthConfig config;

  AuthHttpClient(this._inner, this._storage, this._refresh, this.config);

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    // Adjunta Bearer si existe
    final jwt = await _storage.readAccess();
    if (jwt != null) {
      request.headers['Authorization'] = 'Bearer $jwt';
    }
    request.headers.putIfAbsent('Accept', ()=>'application/json');

    var res = await _inner.send(request);
    if (res.statusCode == 401) {
      // intenta refrescar
      final newToken = await _refresh();
      if (newToken != null) {
        // Reintenta una vez
        final clone = await _clone(request);
        clone.headers['Authorization'] = 'Bearer $newToken';
        res = await _inner.send(clone);
      }
    }
    return res;
  }

  Future<http.BaseRequest> _clone(http.BaseRequest r) async {
    final c = http.Request(r.method, r.url)
      ..headers.addAll(r.headers);
    if (r is http.Request) {
      c.bodyBytes = await r.finalize().toBytes(); // ya consumido en send, por eso clonamos antes si es posible
    }
    return c;
  }
}
