import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';
import 'package:flutter/services.dart' show PlatformException;

import 'errors.dart';

/// Opens the authorization URL in the **system browser** and returns the redirect URL.
abstract class AuthBrowser {
  Future<String> authenticate(String url, Uri redirectUri,
      {required bool ephemeral});
}

/// ASWebAuthenticationSession (iOS/macOS), Chrome Custom Tabs (Android), and on Windows/Linux the system
/// browser with a loopback listener. Embedded webviews are switched off (`useWebview: false`), as RFC 8252 requires.
class FlutterWebAuth2Browser implements AuthBrowser {
  const FlutterWebAuth2Browser();
  @override
  Future<String> authenticate(String url, Uri redirectUri,
      {required bool ephemeral}) async {
    final https = redirectUri.scheme == 'https';
    final loopback = redirectUri.scheme == 'http';
    try {
      return await FlutterWebAuth2.authenticate(
        url: url,
        callbackUrlScheme: loopback
            ? 'http://${redirectUri.host}:${redirectUri.port}'
            : redirectUri.scheme,
        options: FlutterWebAuth2Options(
          preferEphemeral: ephemeral,
          useWebview: false,
          httpsHost: https ? redirectUri.host : null,
          httpsPath: https ? redirectUri.path : null,
        ),
      );
    } on PlatformException catch (e) {
      if (e.code == 'CANCELED') throw CancelledException();
      rethrow;
    }
  }
}

/// Secure key-value storage for tokens.
abstract class TokenStore {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

/// iOS/macOS Keychain (first unlock, this device only), Android EncryptedSharedPreferences (Keystore-backed).
class SecureTokenStore implements TokenStore {
  SecureTokenStore([FlutterSecureStorage? storage])
      : _s = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
              iOptions: IOSOptions(
                  accessibility:
                      KeychainAccessibility.first_unlock_this_device),
              mOptions: MacOsOptions(
                  accessibility:
                      KeychainAccessibility.first_unlock_this_device),
            );
  final FlutterSecureStorage _s;
  @override
  Future<String?> read(String key) => _s.read(key: key);
  @override
  Future<void> write(String key, String value) =>
      _s.write(key: key, value: value);
  @override
  Future<void> delete(String key) => _s.delete(key: key);
}

/// For tests, or when you don't want sessions to survive restarts.
class MemoryTokenStore implements TokenStore {
  final Map<String, String> values = {};
  @override
  Future<String?> read(String key) async => values[key];
  @override
  Future<void> write(String key, String value) async => values[key] = value;
  @override
  Future<void> delete(String key) async => values.remove(key);
}
