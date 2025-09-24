// lib/src/models.dart
class Tokens {
  final String accessToken;
  final String? refreshToken;
  final int? expiresIn;

  Tokens({required this.accessToken, this.refreshToken, this.expiresIn});

  factory Tokens.fromJson(Map<String,dynamic> j) => Tokens(
    accessToken: j['access_token'],
    refreshToken: j['refresh_token'],
    expiresIn: j['expires_in'],
  );
}

class User {
  final int id;
  final String email;
  final String? name;
  final String? role;

  User({required this.id, required this.email, this.name, this.role});

  factory User.fromJson(Map<String,dynamic> j) =>
      User(id: j['id'], email: j['email'], name: j['name'], role: j['role']);
}
