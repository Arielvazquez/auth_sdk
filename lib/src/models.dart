class Tokens {
  final String accessToken;
  final String refreshToken;
  final String tokenType;
  final int expiresIn;

  Tokens({
    required this.accessToken,
    required this.refreshToken,
    required this.tokenType,
    required this.expiresIn,
  });

  factory Tokens.fromJson(Map<String, dynamic> j) {
    // aceptar snake/camel y tipos mixtos
    String? s(dynamic v) => (v == null) ? null : v.toString();
    int toInt(dynamic v) =>
        v is int ? v : int.tryParse(s(v) ?? '') ?? 0;

    final at = s(j['access_token'] ?? j['accessToken']);
    final rt = s(j['refresh_token'] ?? j['refreshToken']);
    final tt = s(j['token_type'] ?? j['tokenType']);
    final ei = j['expires_in'] ?? j['expiresIn'];

    if (at == null || tt == null) {
      throw FormatException('Missing token fields: access_token/token_type');
    }

    return Tokens(
      accessToken: at,
      refreshToken: rt ?? '',     // opcional si tu backend no lo envía
      tokenType: tt,
      expiresIn: toInt(ei),
    );
  }
}
