# Changelog

## 0.1.1 (2026-10-21)

- `SignInWithIdentviaButton`: the disabled colour uses `withAlpha` instead of `withValues`, so the package analyzes and builds on Flutter 3.24 again (`withValues` needs 3.27+).
- CI: matrix fail-fast is off. `.gitignore` now excludes nested build output, APK/AAB files and local live-test state.

## 0.1.0 — 2026-10-21

- First release.
- `IdentviaClient`: OpenID Connect authorization code flow with mandatory PKCE S256, `state`, `nonce` and the RFC 9207 `iss` response parameter, in the system browser (ASWebAuthenticationSession on iOS/macOS, Chrome Custom Tabs on Android, the system browser with a loopback listener on Windows/Linux; embedded webviews are off).
- Validates ID tokens: RS256/ES256 signature against the JWKS (refetched on an unknown `kid`, at most every 30 s), `iss`, `aud`/`azp`, `exp`/`iat`, `nonce`, `at_hash`, `auth_time`/`max_age`. Rejects `alg: none` and HS* algorithms.
- Refresh-token rotation with single-flight refresh. When the server detects reuse, the client signs the user out locally.
- `SecureTokenStore` (Keychain, first-unlock-this-device; EncryptedSharedPreferences), with the refresh token in its own entry.
- `userinfo()` (checks `sub`), `signOut()` (revocation plus optional RP-initiated logout), `changes` stream.
- `SignInWithIdentviaButton` and `IdentviaMark` widgets.
- `authorizationDetails` (RFC 9396 RAR, `AuthorizationDetail.agentTask`) — requires server 2026-10-21_5+; throws `UnsupportedException` otherwise.
