# auth_sdk

SDK interno de GLOBA, en Flutter/Dart, para autenticar apps contra el backend de auth (ORDS): email y contraseña, Google, manejo de tokens (access y refresh con rotación) y endpoints de la cuenta.

## Uso

```yaml
dependencies:
  auth_sdk:
    git:
      url: https://github.com/Arielvazquez/auth_sdk.git
```

```dart
final auth = AuthClient(
  config: AuthConfig(
    baseUrl: Uri.parse('https://<host>/ords/<schema>/auth/'),
    webGoogleClientId: '...apps.googleusercontent.com',
    language: () => 'es', // opcional: idioma de los mails
  ),
  storage: SecureStorage(),
);

await auth.login(email, password);   // remember: true por defecto
await auth.ensureSession();          // antes de cada pedido autenticado
await auth.logout();
```

Las excepciones son subclases de `AuthException` (por ejemplo `InvalidCredentialsException`, `InvalidRefreshTokenException`, `NetworkException`, `RateLimitedException`).

El contexto completo (endpoints, sesión, errores, seguridad y pendientes) está en [CONTEXT.md](CONTEXT.md).

## Desarrollo

```bash
flutter test
flutter analyze lib test
```
