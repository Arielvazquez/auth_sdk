# auth_sdk — Contexto del proyecto

SDK interno en Flutter/Dart para autenticar apps contra el backend de auth de GLOBA, que es un servicio REST en ORDS (por ejemplo `https://globa.space/ords/corpus/auth/`). Cubre el login con email y contraseña, el login social con Google y Apple, el manejo de tokens (access y refresh) y los endpoints de la cuenta.

> Estado: versión `0.1.0`, `publish_to: none`, de uso interno. La estructura todavía es la de una **app** Flutter (`lib/main.dart` "Hello World" y carpetas de plataforma de template), no la de un package.

## Stack

- Dart `^3.9.0` / Flutter
- `flutter_secure_storage ^9.2.4`: guarda los tokens
- `google_sign_in ^7.2.0`: API v7, con `initialize` y `authenticate`
- `sign_in_with_apple ^7.0.1`
- `http`: se usa pero **no está declarado** en `pubspec.yaml` (llega como dependencia transitiva)

## Estructura

```
lib/
  auth_sdk.dart                 # API pública (exports)
  src/
    config.dart                 # AuthConfig: baseUrl, leeway, client IDs de Google, idioma
    auth_client.dart            # AuthClient + excepciones tipadas + _AuthHttp (helper privado)
    http_client.dart            # AuthHttpClient (BaseClient con Bearer + retry 401), hoy sin uso interno
    models.dart                 # Tokens, TokensPartial
    storage.dart                # TokenStorage (interfaz) + SecureStorage
    providers/
      google_adapter.dart       # Devuelve el id_token de Google
      apple_adapter.dart        # Devuelve el identityToken de Apple
    widgets/                    # apple/google_signin_button.dart (archivos vacíos)
  util/logger.dart              # AppLogger (debugPrint con colores)
test/config_test.dart           # Tests de AuthConfig.endpoint / ?lang=
```

## Uso básico

```dart
final auth = AuthClient(
  config: AuthConfig(
    baseUrl: Uri.parse('https://globa.space/ords/corpus/auth/'),
    webGoogleClientId: '...apps.googleusercontent.com',
    iosGoogleClientId: '...',
    language: () => currentLocale.languageCode, // opcional → ?lang=
  ),
  storage: SecureStorage(),
);

await auth.login(email, password, remember: true);
final me = await auth.me();

// Social
final idToken = await GoogleSignInAdapter.signInAndGetIdToken(
  webClientId: cfg.webGoogleClientId!, iosClientId: cfg.iosGoogleClientId);
await auth.socialLogin('google', idToken);

await auth.logout();
```

## Endpoints del backend

Las rutas son relativas a `baseUrl`. Si `language` está configurado, cada pedido lleva además `?lang=`.

| Método SDK | Endpoint | Body | Respuesta OK |
|---|---|---|---|
| `register` | `POST register` | `email, password, name?, phone?` | 200/201 JSON |
| `verifyEmail` | `POST verify-email` | `email, code` | 200 |
| `forgotPassword` | `POST forgot-password` | `email` | 200 |
| `resetPassword` | `POST reset-password` | `email, code, new_password` | 200 |
| `login` | `POST login` | `email, password, remember` | 200 `Tokens` |
| `socialLogin` | `POST social-login` | `provider ('google'\|'apple'), id_token, remember` | 200 `Tokens` |
| (refresh interno) | `POST token` | `refresh_token` | 200 `TokensPartial` |
| `me` | `GET me` (Bearer) | — | 200 JSON |
| `addPassword` | `POST add-password` (Bearer) | `new_password` | 200 (puede traer tokens nuevos) / 204 |
| `logout` | `POST logout` | `refresh_token` | se ignoran los errores |
| `test` | `POST test` | `{}` | 200/204 |

Los JSON van en **snake_case**: `access_token`, `refresh_token`, `token_type`, `expires_in`, `refresh_expires_at` (ISO-8601, opcional).

## Manejo de sesión

- Las claves en el storage son `jwt` (access token) y `refresh` (refresh token).
- `ensureSession()`:
  - sin access token → refresh;
  - access token vencido (`exp - accessLeeway`) → refresh obligatorio;
  - por vencer (`accessLeeway + 90s`) → refresh proactivo.
- `_refresh()` comparte un único `Completer` entre llamadas concurrentes para no hacer refresh en paralelo. `/token` devuelve **solo** el access token: el refresh token no rota.
- `_authedGet` y `_authedPost` reintentan una sola vez si reciben 401, después de un refresh.
- El JWT se decodifica **sin verificar la firma**, solo para leer `exp`. Nunca hay que confiar en sus claims del lado del cliente.

## Errores

El cliente traduce la respuesta HTTP a una subclase de `AuthException`, que es una `sealed class` con `code`, `message` y `status`. Lee `code` y `error`/`message` del body:

| HTTP | `code` | Excepción |
|---|---|---|
| 400 | * | `BadRequestException` |
| 401 | `INVALID_CREDENTIALS` | `InvalidCredentialsException` |
| 401 | `INVALID_TOKEN`, `INVALID_AUTH_TOKEN`, otro | `InvalidAuthTokenException` |
| 401 | `INVALID_REFRESH_TOKEN` | `InvalidRefreshTokenException` |
| 403 | `EMAIL_NOT_VERIFIED` / otro | `EmailNotVerifiedException` / `AccessDeniedException` |
| 409 | `EMAIL_ALREADY_EXISTS` / `USER_PASSWORD_EXISTS` | `ConflictUserExistsException` / `PasswordExistsException` |
| 429 | * | `RateLimitedException` |
| 500 | * | `ServerErrorException` |
| red o timeout (20 s) | `NETWORK` | `NetworkException` |
| otro | * | `UnknownAuthException` |

## Convenciones

- Comentarios y mensajes de commit en **español**. Los commits recientes usan como prefijo la versión, por ejemplo `1.8 FIX ensureSession`.
- Trabajo en ramas `feature/*` → PR a `main`.
- Tests con `flutter test`.

## Problemas conocidos / pendientes de seguridad

Surgieron de una revisión de seguridad del 2026-11-18. Se listan de mayor a menor prioridad.

1. **No se obliga a usar HTTPS** en `AuthConfig.baseUrl`.
2. **`remember: false` igual guarda el refresh token** en el storage del dispositivo. Además el default no es coherente: `login` usa `false` y `socialLogin` usa `true`.
3. **No hay `nonce`** en Sign in with Apple ni en Google, lo que permite el replay de un `id_token`. Hace falta un cambio coordinado con el backend.
4. **`AuthHttpClient`** agrega el Bearer a cualquier host, con riesgo de filtrar el token, y `_clone` vuelve a hacer `finalize()` sobre un request ya enviado, lo que lanza `StateError` y rompe el reintento.
5. **`_refresh()` no completa el `Completer` cuando hay un error**, así que las llamadas concurrentes que lo estaban esperando se quedan colgadas.
6. **No se borra un refresh token inválido** (`INVALID_REFRESH_TOKEN`).
7. **El refresh token no rota.** Hace falta un cambio en el backend, y el SDK debería guardar el `refresh_token` si viene en `/token`.
8. **`FlutterSecureStorage` está con los defaults.** Falta `encryptedSharedPreferences` en Android, `first_unlock_this_device` en iOS y `allowBackup=false`. El Keychain sobrevive a la desinstalación.
9. **Web:** los tokens quedan en `localStorage`, expuestos a XSS. En web conviene una cookie `HttpOnly` para el refresh token.
10. **El refresh proactivo** lanza la excepción y borra un access token que todavía era válido, en contra de lo que dice el comentario.
11. **Higiene:**
    - `debugPrint` también imprime en release;
    - falta declarar `http`;
    - se crea un `http.Client` en cada pedido y no se cierra;
    - se envía `Bearer null` cuando no hay token;
    - `lang` no se valida;
    - `fromJson` puede lanzar `TypeError`;
    - las carpetas de plataforma son de template y el release se firma con debug keys.

**Lo que se espera del backend:**
- rate limiting en `login`, `verify-email` y `reset-password`;
- que no se puedan enumerar cuentas;
- códigos de un solo uso y de vida corta;
- revocación del refresh token en `logout`;
- validar `aud`, `iss`, `exp` y `nonce` del `id_token`;
- lista blanca para `lang`.
