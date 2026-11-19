# auth_sdk — Contexto del proyecto

SDK interno en Flutter/Dart para autenticar apps contra el backend de auth de GLOBA, que es un servicio REST en ORDS (por ejemplo `https://globa.space/ords/corpus/auth/`). Cubre el login con email y contraseña, el login social con Google y Apple, el manejo de tokens (access y refresh) y los endpoints de la cuenta.

> Estado: versión `0.3.0`, `publish_to: none`, de uso interno. La estructura todavía es la de una **app** Flutter (`lib/main.dart` "Hello World" y carpetas de plataforma de template), no la de un package.

## Stack

- Dart `^3.9.0` / Flutter
- `flutter_secure_storage ^9.2.4`: guarda los tokens
- `google_sign_in ^7.2.0`: API v7, con `initialize` y `authenticate`
- `sign_in_with_apple ^7.0.1`
- `http ^1.2.2`: los pedidos al backend (un solo `http.Client` por `AuthClient`, inyectable para tests)

## Estructura

```
lib/
  auth_sdk.dart                 # API pública (exports)
  src/
    config.dart                 # AuthConfig: baseUrl, leeway, client IDs de Google, idioma
    auth_client.dart            # AuthClient + excepciones tipadas + _AuthHttp (helper privado)
    models.dart                 # Tokens, TokensPartial
    storage.dart                # TokenStorage (interfaz) + SecureStorage
    providers/
      google_adapter.dart       # Devuelve el id_token de Google
      apple_adapter.dart        # Devuelve el identityToken de Apple
    widgets/                    # apple/google_signin_button.dart (archivos vacíos)
  util/logger.dart              # AppLogger (debugPrint con colores, solo en debug)
test/
  config_test.dart              # AuthConfig.endpoint / ?lang=
  auth_client_test.dart         # refresh, ensureSession, Bearer, solo https (con MockClient)
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
| (refresh interno) | `POST token` | `refresh_token, rotate: true` | 200 `TokensPartial` + `refresh_token` nuevo |
| `me` | `GET me` (Bearer) | — | 200 JSON |
| `addPassword` | `POST add-password` (Bearer) | `new_password` | 200 (puede traer tokens nuevos) / 204 |
| `logout` | `POST logout` | `refresh_token` | se ignoran los errores |

`AuthClient.test()` se borró en 0.2.0: el endpoint `POST test` ya no existe en el backend (404 desde IA-079 de Corpus, porque exponía datos del servidor).

Los JSON van en **snake_case**: `access_token`, `refresh_token`, `token_type`, `expires_in`, `refresh_expires_at` (ISO-8601, opcional).

## Manejo de sesión

- Las claves en el storage son `jwt` (access token) y `refresh` (refresh token).
- `ensureSession()`:
  - sin access token → refresh;
  - access token vencido (`exp - accessLeeway`) → refresh obligatorio;
  - por vencer (`accessLeeway + 90s`) → refresh proactivo.
- Proactivo: si falla por la red o por el servidor, devuelve `true` con el token que todavía sirve; solo lanza si el servidor rechazó la sesión.
- `_refresh()` comparte un único `Future` entre llamadas concurrentes: todas reciben el mismo resultado o el mismo error, y no se hace refresh en paralelo.
- **401 en `/token`:** lanza `InvalidRefreshTokenException` y borra los dos tokens. El backend responde `code: INVALID_TOKEN`, pero en `/token` siempre se trata del refresh token.
- **Sin red o con error del servidor:** lanza `NetworkException` u otra `AuthException` y **no borra nada**. Corpus usa el access token guardado, aunque esté vencido, para el modo sin conexión.
- **Rotación (desde 0.3.0):** el SDK manda `rotate: true` en `/token` y guarda el `refresh_token` nuevo que vuelve.
  - El backend revoca el que se mandó.
  - Si después llega uno ya rotado:
    - con menos de 60 s: da otro (la app y su tarea en segundo plano renovando a la vez);
    - si su reemplazo nunca se usó: da otro (se perdió la respuesta);
    - si su reemplazo ya se usó: alguien lo robó, y se cierran todas las sesiones del usuario.
  - Los clientes que no mandan `rotate` (0.2.0 o anteriores) siguen sin rotación.
- `baseUrl` tiene que ser `https`; `http` solo se acepta contra `localhost`, `127.0.0.1` o `10.0.2.2` (el emulador).
- `_authedGet` y `_authedPost` reintentan una sola vez si reciben 401, después de un refresh.
- El JWT se decodifica **sin verificar la firma**, solo para leer `exp`. Nunca hay que confiar en sus claims del lado del cliente.

## Errores

El cliente traduce la respuesta HTTP a una subclase de `AuthException`, que es una `sealed class` con `code`, `message` y `status`. Lee `code` y `error`/`message` del body:

| HTTP | `code` | Excepción |
|---|---|---|
| 400 | * | `BadRequestException` |
| 401 | `INVALID_CREDENTIALS` | `InvalidCredentialsException` |
| 401 | `INVALID_TOKEN`, `INVALID_AUTH_TOKEN`, otro | `InvalidAuthTokenException` |
| 401 | `INVALID_REFRESH_TOKEN`, o cualquier 401 en `/token` | `InvalidRefreshTokenException` |
| 403 | `EMAIL_NOT_VERIFIED` / otro | `EmailNotVerifiedException` / `AccessDeniedException` |
| 409 | `EMAIL_ALREADY_EXISTS` / `USER_PASSWORD_EXISTS` | `ConflictUserExistsException` / `PasswordExistsException` |
| 429 | * | `RateLimitedException` |
| 500 | * | `ServerErrorException` |
| red o timeout (20 s) | `NETWORK` | `NetworkException` |
| otro | * | `UnknownAuthException` |

Desde IA-079 de Corpus (2026-11-18), el body de error trae `code`, `error`, `request_id` y `timestamp`, y a veces `details.context`. Ya **no** trae `details.sqlerrm`: el detalle de los 500 queda en la base (`CRP_ERROR_LOG`), buscable por `request_id`.

## Convenciones

- Comentarios y mensajes de commit en **español**. Los commits recientes usan como prefijo la versión, por ejemplo `1.8 FIX ensureSession`.
- Trabajo en ramas `feature/*` → PR a `main`.
- Tests con `flutter test`.

## Problemas conocidos / pendientes de seguridad

Surgieron de una revisión de seguridad del 2026-11-18.

**Arreglado en 0.3.0** (IA-083 de Corpus): el SDK pide la rotación del refresh token.

**Arreglado en 0.2.0** (IA-080 de Corpus):
- **El refresh que fallaba dejaba colgadas** las llamadas concurrentes que lo esperaban.
- **El refresh proactivo:** lanzaba la excepción y borraba un access token que todavía era válido. Sin conexión, la app no podía seguir.
- **No se borraba un refresh token rechazado.**
- **HTTPS obligatorio** en `baseUrl`.
- **`AuthHttpClient` borrado:** agregaba el Bearer a cualquier host y su reintento lanzaba `StateError`; nadie lo usaba.
- **Higiene:**
  - `http` declarado;
  - un solo `http.Client` y `close()`;
  - sin `Bearer null`;
  - `exp` con decimales;
  - `AppLogger` solo en debug;
  - `test()` borrado.

**Pendiente:**
1. **`remember: false` igual guarda el refresh token** en el dispositivo (el backend lo hace durar 1 día en vez de 30). Además el default no es coherente: `login` usa `false` y `socialLogin`, `true`. Cambiarlo es una decisión de producto: sin "recordarme", la sesión no sobreviviría a cerrar la app.
2. **No hay `nonce`** en Sign in with Apple ni en Google, lo que permite el replay de un `id_token`. Hace falta un cambio coordinado con el backend.
3. **`FlutterSecureStorage` está con los defaults:** falta `encryptedSharedPreferences` en Android y `first_unlock_this_device` en iOS.
   - Ojo: activar `encryptedSharedPreferences` deja sin acceso a lo guardado antes, así que cierra la sesión de todos una vez.
   - Corpus ya tiene `allowBackup="false"`.
   - El Keychain sobrevive a la desinstalación.
4. **Web:** los tokens quedan en `localStorage`, expuestos a XSS. En web conviene una cookie `HttpOnly` para el refresh token.
5. **Higiene:**
   - `fromJson` puede lanzar `TypeError` si el backend cambia el formato;
   - las carpetas de plataforma son de template y el release se firma con debug keys;
   - la estructura sigue siendo la de una app, no la de un package.

## Backend de auth (revisado el 2026-11-18)
El backend está en el repo de Corpus (`corpus_mobile_app`):
- `database/package_bodies/AUTH_PKG.sql`;
- `ERR_PKG.sql`;
- los handlers `database/ords/handlers/auth_module__*.sql`.

El detalle de los hallazgos está en `SECURITY_AUDIT.md` de ese repo, sección 29.

**Bien:**
- **Códigos:** 6 dígitos con `DBMS_CRYPTO.randombytes`, 15 minutos, de un solo uso, 5 intentos fallidos por código y 5 pedidos por mail cada 24 h. "Olvidé mi contraseña" no revela si el mail tiene cuenta.
- **Refresh token:** 32 bytes al azar. `logout` lo revoca.
- **Google:** el token se verifica con Google; se exige `iss`, que `aud` sea de nuestro proyecto, `exp` y `email_verified`. Apple se rechaza mientras no se verifique.
- **Configuración:** el secreto del JWT (HS256) está en `AUTH_CONFIG`, no en el código. `BYPASS_OTP = N` en producción.
- **`lang`:** se toman las dos primeras letras; `es` da español y cualquier otro valor, inglés. No hace falta lista blanca.

**Arreglado en IA-079 (Corpus #130):**
- **Robo de cuenta con Google:** una cuenta sin verificar que se verifica con Google pierde la contraseña que tenía, sus códigos y sus sesiones.
- **Cambiar la contraseña cierra todas las sesiones:** revoca todos los refresh tokens del usuario.
- **`/auth/test` borrado.**
- **Errores sin `sqlerrm`.**

**Arreglado en IA-083 (2026-11-18):**
- **Límite de logins fallidos:** 10 por mail en 15 minutos, la cuenta exista o no; después, 429 `TOO_MANY_LOGIN_ATTEMPTS`. Cambiar la contraseña con el código del mail lo destraba.
- **Contraseñas con PBKDF2-HMAC-SHA256** (50.000 iteraciones, unos 0,45 s):
  - las del formato viejo se migran en el próximo login;
  - con un mail sin cuenta se hace el mismo trabajo, así que el tiempo de respuesta no revela qué mails tienen cuenta.
- **Access token de 15 minutos.**
- **Refresh tokens:** se guarda su SHA-256 y rotan si el cliente lo pide (ver "Manejo de sesión").
- **`logout`:** respondía 555 y nunca revocaba el refresh token (le faltaba el parámetro `X-APEX-STATUS-CODE`). Ahora lo revoca.

**Pendiente:**
- **El access token no se puede revocar:** dura hasta 15 minutos después de un logout o de un cambio de contraseña.
- **El registro revela si un mail tiene cuenta:** responde 409 `EMAIL_ALREADY_EXISTS`.
- **No hay `nonce`** en el login con Google.
