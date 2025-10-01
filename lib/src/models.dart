class Tokens {
  final String accessToken;
  final String refreshToken;
  final String tokenType; // "Bearer"
  final int expiresIn; // segundos
  final DateTime? refreshExpiresAt; // ISO-8601 opcional

  Tokens({
    required this.accessToken,
    required this.refreshToken,
    required this.tokenType,
    required this.expiresIn,
    this.refreshExpiresAt,
  });

  factory Tokens.fromJson(Map<String, dynamic> json) {
    return Tokens(
      accessToken: json['access_token'] as String,
      refreshToken: json['refresh_token'] as String,
      tokenType: json['token_type'] as String,
      expiresIn: (json['expires_in'] as num).toInt(),
      refreshExpiresAt: json['refresh_expires_at'] == null
          ? null
          : DateTime.parse(json['refresh_expires_at'] as String),
    );
  }

  Map<String, dynamic> toJson() => {
        'access_token': accessToken,
        'refresh_token': refreshToken,
        'token_type': tokenType,
        'expires_in': expiresIn,
        if (refreshExpiresAt != null)
          'refresh_expires_at': refreshExpiresAt!.toIso8601String(),
      };
}

class TokensPartial {
  final String accessToken;
  final String tokenType; // "Bearer"
  final int expiresIn; // segundos

  TokensPartial({
    required this.accessToken,
    required this.tokenType,
    required this.expiresIn,
  });

  factory TokensPartial.fromJson(Map<String, dynamic> json) {
    return TokensPartial(
      accessToken: json['access_token'] as String,
      tokenType: json['token_type'] as String,
      expiresIn: (json['expires_in'] as num).toInt(),
    );
  }

  Map<String, dynamic> toJson() => {
        'access_token': accessToken,
        'token_type': tokenType,
        'expires_in': expiresIn,
      };
}