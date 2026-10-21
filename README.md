# identvia (Flutter)

Sign in with [Identvia](https://identvia.com) in Flutter apps: OpenID Connect + PKCE in the **system browser**, secure token storage, refresh-token rotation and a branded button.

- iOS 12+ / macOS (ASWebAuthenticationSession), Android (Chrome Custom Tabs), Windows/Linux (system browser + loopback).
- Public clients only. **Never put a client secret in an app.** This package doesn't accept one.
- Pairwise `sub`: each app gets its own stable user ID. Store `session.user.sub`, not the email.

## Install

```sh
flutter pub add identvia
```

## 1. Register your app

At <https://identvia.com/developers>, create a **public** client (no secret) and register a redirect URI. Two options:

| Redirect | Notes |
|---|---|
| `com.example.app:/oauth/identvia` | Reverse-domain private-use scheme (RFC 8252 §7.1). Works everywhere. |
| `https://app.example.com/oauth/identvia` | Claimed https link (App Links / Universal Links). iOS 17.4+ for ASWebAuthenticationSession. |

On desktop, use `http://localhost:<port>/callback`.

## 2. Platform setup

**Android:** in `android/app/src/main/AndroidManifest.xml`, inside `<application>`:

```xml
<activity android:name="com.linusu.flutter_web_auth_2.CallbackActivity" android:exported="true">
  <intent-filter android:label="flutter_web_auth_2">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="com.example.app" />
  </intent-filter>
</activity>
```

**iOS/macOS:** no URL-type entry is needed; ASWebAuthenticationSession catches the callback. For macOS, enable Keychain Sharing and the outgoing-network entitlement.

## 3. Quickstart

```dart
import 'package:identvia/identvia.dart';

final identvia = IdentviaClient(
  clientId: 'oid_…',
  redirectUri: 'com.example.app:/oauth/identvia',
  // scopes default to openid email profile offline_access
);

// Restore on launch
final existing = await identvia.currentSession();

// Sign in
SignInWithIdentviaButton(onPressed: () async {
  try {
    final session = await identvia.signIn();
    print(session.user.sub);
  } on CancelledException {
    // user closed the browser
  }
});

// Call your API with a fresh access token (refreshes and rotates automatically)
final token = await identvia.getAccessToken();
await http.get(api, headers: {'Authorization': 'Bearer $token'});

// Sign out (revokes the refresh token; federated: true also ends the Identvia browser session)
await identvia.signOut();
```

Options: `signIn(prompt: 'login' | 'consent' | 'select_account', maxAge:, loginHint:, uiLocales:)`, `IdentviaClient(ephemeralSession: true)` for private browsing, plus custom `TokenStore`, `AuthBrowser` and `http.Client` for testing.

### Agent authorization (requires server 2026-10-21_5+)

```dart
await identvia.signIn(authorizationDetails: [AuthorizationDetail.agentTask('Book a table for two on Friday')]);
```

This throws `UnsupportedException` when the server doesn't advertise `authorization_details_types_supported`. Token exchange and CIBA need a client secret, so they belong in your backend (`@identvia/js/server`, `Identvia.AspNetCore`), not in an app.

## Security

- Every sign-in uses PKCE S256, `state`, `nonce` and RFC 9207 `iss`. A response whose redirect isn't exactly yours is rejected.
- ID tokens are verified: RS256/ES256 against the JWKS, plus `iss`, `aud`, `azp`, `exp`, `iat`, `nonce` and `at_hash`.
- Tokens are stored in the Keychain (`first_unlock_this_device`) or EncryptedSharedPreferences. The refresh token sits in its own entry.
- A refresh token that the server rejects as reused signs the user out.
- Embedded webviews are never used.

## Example

See [`example/`](example/): `flutter run --dart-define=IDENTVIA_CLIENT_ID=oid_…`.

## Tests

```sh
flutter test                                                    # unit + widget tests (fake Identvia)
IDENTVIA_LIVE_STATE=/tmp/live-state.json flutter test test_live # against a real server
```

MIT © Identvia
