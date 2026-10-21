import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import 'adapters.dart';
import 'errors.dart';
import 'jwt.dart';
import 'pkce.dart';

const String kDefaultIssuer = 'https://id.identvia.com';
const _loopback = {'localhost', '127.0.0.1', '::1', '[::1]'};

/// Validates a native redirect URI (RFC 8252): https, http loopback, or a reverse-domain private-use scheme.
Uri assertNativeRedirect(String uri) {
  final u = Uri.tryParse(uri);
  if (u == null || !u.hasScheme) {
    throw ConfigurationException('redirectUri "$uri" is not an absolute URI.');
  }
  if (u.hasFragment || uri.contains('#')) {
    throw ConfigurationException('redirectUri must not contain a #fragment.');
  }
  if (u.userInfo.isNotEmpty) {
    throw ConfigurationException('redirectUri must not contain credentials.');
  }
  if (u.scheme == 'https' && u.host.isNotEmpty) return u;
  if (u.scheme == 'http' && _loopback.contains(u.host)) return u;
  if (RegExp(r'^[a-z][a-z0-9+\-]*(\.[a-z0-9+\-]+)+$').hasMatch(u.scheme)) {
    return u;
  }
  throw ConfigurationException(
      'redirectUri must be https://, http://localhost, or a reverse-domain scheme such as com.example.app:/callback.');
}

class AuthorizationDetail {
  AuthorizationDetail(this.type, [Map<String, dynamic> fields = const {}])
      : fields = Map.of(fields);

  /// `agent_task` (RFC 9396 type accepted by Identvia by default).
  factory AuthorizationDetail.agentTask(String description,
          {List<String>? actions}) =>
      AuthorizationDetail('agent_task', {
        'description': description,
        if (actions != null) 'actions': actions
      });
  final String type;
  final Map<String, dynamic> fields;
  Map<String, dynamic> toJson() => {'type': type, ...fields};
}

class IdentviaTokens {
  IdentviaTokens(
      {required this.accessToken,
      required this.expiresAt,
      this.refreshToken,
      this.idToken,
      this.scope,
      this.authorizationDetails});
  factory IdentviaTokens.fromJson(Map<String, dynamic> j) => IdentviaTokens(
        accessToken: j['accessToken'] as String,
        expiresAt: DateTime.fromMillisecondsSinceEpoch(j['expiresAt'] as int),
        refreshToken: j['refreshToken'] as String?,
        idToken: j['idToken'] as String?,
        scope: j['scope'] as String?,
        authorizationDetails:
            (j['authorizationDetails'] as List?)?.cast<Map<String, dynamic>>(),
      );
  final String accessToken;
  final DateTime expiresAt;
  String? refreshToken;
  String? idToken;
  final String? scope;
  final List<Map<String, dynamic>>? authorizationDetails;
  Map<String, dynamic> toJson({bool includeRefresh = true}) => {
        'accessToken': accessToken,
        'expiresAt': expiresAt.millisecondsSinceEpoch,
        if (includeRefresh && refreshToken != null)
          'refreshToken': refreshToken,
        if (idToken != null) 'idToken': idToken,
        if (scope != null) 'scope': scope,
        if (authorizationDetails != null)
          'authorizationDetails': authorizationDetails,
      };
}

class IdentviaSession {
  IdentviaSession(this.user, this.tokens);
  final IdTokenClaims user;
  final IdentviaTokens tokens;
}

/// The values to keep between opening the browser and the callback (single use).
class AuthTransaction {
  AuthTransaction(this.state, this.nonce, this.verifier, this.maxAge);
  final String state, nonce, verifier;
  final int? maxAge;
}

/// Identvia client for Flutter apps (public client: PKCE, never a client secret).
class IdentviaClient {
  IdentviaClient({
    String issuer = kDefaultIssuer,
    required this.clientId,
    required String redirectUri,
    List<String> scopes = const ['email', 'profile', 'offline_access'],
    AuthBrowser? browser,
    TokenStore? store,
    http.Client? httpClient,
    this.ephemeralSession = false,
    this.refreshLeeway = const Duration(seconds: 60),
    DateTime Function()? clock,
  })  : issuer = _normalizeIssuer(issuer),
        redirectUri = assertNativeRedirect(redirectUri),
        scopes = {'openid', ...scopes}.toList(),
        _browser = browser ?? const FlutterWebAuth2Browser(),
        _store = store ?? SecureTokenStore(),
        _http = httpClient ?? http.Client(),
        _clock = clock ?? DateTime.now {
    if (clientId.trim().isEmpty) {
      throw ConfigurationException('clientId is required.');
    }
  }

  final String issuer;
  final String clientId;
  final Uri redirectUri;
  final List<String> scopes;
  final bool ephemeralSession;
  final Duration refreshLeeway;
  final AuthBrowser _browser;
  final TokenStore _store;
  final http.Client _http;
  final DateTime Function() _clock;
  Map<String, dynamic>? _discovery;
  List<Jwk>? _jwks;
  DateTime? _jwksAt;
  IdentviaSession? _session;
  bool _loaded = false;
  Future<IdentviaSession?>? _refreshing;
  bool _signingIn = false;
  final _changes = StreamController<IdentviaSession?>.broadcast();

  /// Emits the session after sign-in/refresh and `null` after sign-out.
  Stream<IdentviaSession?> get changes => _changes.stream;

  static String _normalizeIssuer(String i) {
    final s = i.replaceAll(RegExp(r'/+$'), '');
    final u = Uri.tryParse(s);
    if (u == null ||
        !(u.scheme == 'https' ||
            (u.scheme == 'http' && _loopback.contains(u.host))) ||
        u.hasQuery ||
        u.hasFragment) {
      throw ConfigurationException(
          'issuer must be an https:// URL without query or fragment.');
    }
    return s;
  }

  // ------------------------------------------------------------------ http
  Future<(int, Map<String, dynamic>)> _json(Future<http.Response> req) async {
    http.Response r;
    try {
      r = await req.timeout(const Duration(seconds: 15));
    } catch (e) {
      throw IdentviaException('network_error', 'Could not reach Identvia.');
    }
    if (r.body.isEmpty) return (r.statusCode, <String, dynamic>{});
    try {
      final d = jsonDecode(r.body);
      return (
        r.statusCode,
        d is Map<String, dynamic> ? d : <String, dynamic>{}
      );
    } catch (_) {
      throw IdentviaException(
          'http_error', 'Unexpected response (HTTP ${r.statusCode}).');
    }
  }

  Future<Map<String, dynamic>> discovery() async {
    if (_discovery != null) return _discovery!;
    final (s, d) = await _json(_http.get(
        Uri.parse('$issuer/.well-known/openid-configuration'),
        headers: {'Accept': 'application/json'}));
    if (s != 200) {
      throw IdentviaException('http_error', 'Discovery failed (HTTP $s).');
    }
    if (d['issuer'] != issuer) {
      throw ConfigurationException(
          'Discovery issuer does not match the configured issuer.');
    }
    for (final k in ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
      if (d[k] is! String) throw ConfigurationException('Discovery has no $k.');
    }
    final m = d['code_challenge_methods_supported'];
    if (m is List && !m.contains('S256')) {
      throw ConfigurationException('Server does not support PKCE S256.');
    }
    return _discovery = d;
  }

  Future<String> _endpoint(String name) async {
    final v = (await discovery())[name];
    if (v is! String) {
      throw UnsupportedException('$name is not available on this server.');
    }
    return v;
  }

  Future<Jwk?> _key(String kid) async {
    Future<void> load() async {
      final (s, d) =
          await _json(_http.get(Uri.parse(await _endpoint('jwks_uri'))));
      if (s != 200 || d['keys'] is! List) {
        throw IdentviaException('http_error', 'JWKS fetch failed.');
      }
      _jwks = (d['keys'] as List)
          .whereType<Map<String, dynamic>>()
          .map(Jwk.new)
          .where((k) => k.use == null || k.use == 'sig')
          .toList();
      _jwksAt = _clock();
    }

    if (_jwks == null) await load();
    var k = _jwks!.where((x) => x.kid == kid).firstOrNull;
    if (k == null &&
        _clock().difference(_jwksAt!) > const Duration(seconds: 30)) {
      await load(); // key rotation; at most every 30 s
      k = _jwks!.where((x) => x.kid == kid).firstOrNull;
    }
    return k;
  }

  IdTokenValidator get _validator => IdTokenValidator(
      issuer: issuer, clientId: clientId, getKey: _key, clock: _clock);

  Future<Map<String, dynamic>> _post(
      String url, Map<String, String?> form) async {
    final body = {
      for (final e in form.entries)
        if (e.value != null) e.key: e.value!,
      'client_id': clientId
    };
    final (s, d) = await _json(_http.post(Uri.parse(url),
        headers: {'Accept': 'application/json'}, body: body));
    if (s < 200 || s >= 300) {
      throw TokenException(
          d['error'] is String ? d['error'] as String : 'http_error',
          d['error_description'] as String?,
          s);
    }
    return d;
  }

  IdentviaTokens _tokens(Map<String, dynamic> d) {
    if (d['access_token'] is! String ||
        (d['token_type'] as String?)?.toLowerCase() != 'bearer') {
      throw TokenException('invalid_response', 'No Bearer access token.', 200);
    }
    return IdentviaTokens(
      accessToken: d['access_token'] as String,
      expiresAt: _clock().add(Duration(
          seconds: d['expires_in'] is int ? d['expires_in'] as int : 600)),
      refreshToken: d['refresh_token'] as String?,
      idToken: d['id_token'] as String?,
      scope: d['scope'] as String?,
      authorizationDetails:
          (d['authorization_details'] as List?)?.cast<Map<String, dynamic>>(),
    );
  }

  // ------------------------------------------------------------------ sign-in
  /// Builds the authorization request (exposed for custom browsers and tests).
  Future<(Uri, AuthTransaction)> createAuthorizationRequest(
      {List<String>? scopes,
      String? prompt,
      int? maxAge,
      String? loginHint,
      List<String>? uiLocales,
      List<AuthorizationDetail>? authorizationDetails}) async {
    final d = await discovery();
    if (prompt != null && !['none', 'login', 'consent'].contains(prompt)) {
      throw ConfigurationException('prompt must be none, login or consent.');
    }
    final pkce = Pkce.generate();
    final tx =
        AuthTransaction(randomToken(), randomToken(), pkce.verifier, maxAge);
    String? details;
    if (authorizationDetails != null) {
      final types = d['authorization_details_types_supported'];
      if (types is! List) {
        throw UnsupportedException(
            'This Identvia server does not support authorization_details (requires server 2026-10-21_5+).');
      }
      for (final a in authorizationDetails) {
        if (!types.contains(a.type)) {
          throw ConfigurationException(
              'authorization_details type "${a.type}" is not accepted by this server.');
        }
      }
      details =
          jsonEncode(authorizationDetails.map((a) => a.toJson()).toList());
    }
    final q = <String, String>{
      'response_type': 'code',
      'client_id': clientId,
      'redirect_uri': redirectUri.toString(),
      'scope': (scopes == null ? this.scopes : {'openid', ...scopes}.toList())
          .join(' '),
      'state': tx.state,
      'nonce': tx.nonce,
      'code_challenge': pkce.challenge,
      'code_challenge_method': 'S256',
      if (prompt != null) 'prompt': prompt,
      if (maxAge != null) 'max_age': '$maxAge',
      if (loginHint != null) 'login_hint': loginHint,
      if (uiLocales != null) 'ui_locales': uiLocales.join(' '),
      if (details != null) 'authorization_details': details,
    };
    final base = Uri.parse(d['authorization_endpoint'] as String);
    return (base.replace(queryParameters: {...base.queryParameters, ...q}), tx);
  }

  /// Completes the flow from the URL the browser returned to.
  Future<IdentviaSession> completeAuthorization(
      String returnedUrl, AuthTransaction tx) async {
    final u = Uri.tryParse(returnedUrl);
    if (u == null ||
        u.scheme != redirectUri.scheme ||
        u.host != redirectUri.host ||
        (u.path.isEmpty ? '/' : u.path) !=
            (redirectUri.path.isEmpty ? '/' : redirectUri.path)) {
      throw InvalidStateException('Sign-in returned to an unexpected address.');
    }
    final q = u.queryParameters;
    final state = q['state'];
    if (state == null || !safeEquals(state, tx.state)) {
      throw InvalidStateException(
          'Sign-in response does not match this sign-in (state). Try again.');
    }
    final iss = q['iss'];
    if (iss != null) {
      if (iss != issuer) {
        throw InvalidStateException(
            'Sign-in response came from a different issuer.');
      }
    } else if ((await discovery())[
            'authorization_response_iss_parameter_supported'] ==
        true) {
      throw InvalidStateException('Sign-in response is missing iss.');
    }
    if (q['error'] != null) {
      throw AuthorizationException(q['error']!, q['error_description']);
    }
    final code = q['code'];
    if (code == null || code.isEmpty) {
      throw InvalidStateException('Sign-in response has no code.');
    }
    final t = _tokens(await _post(await _endpoint('token_endpoint'), {
      'grant_type': 'authorization_code',
      'code': code,
      'redirect_uri': redirectUri.toString(),
      'code_verifier': tx.verifier,
    }));
    if (t.idToken == null) throw ValidationException('No ID token returned.');
    final user = await _validator.validate(t.idToken!,
        nonce: tx.nonce,
        requireNonce: true,
        maxAge: tx.maxAge,
        accessToken: t.accessToken);
    return IdentviaSession(user, t);
  }

  /// Opens the system browser, signs in, and stores the session securely.
  Future<IdentviaSession> signIn(
      {List<String>? scopes,
      String? prompt,
      int? maxAge,
      String? loginHint,
      List<String>? uiLocales,
      List<AuthorizationDetail>? authorizationDetails}) async {
    if (_signingIn) {
      throw IdentviaException(
          'in_progress', 'A sign-in is already in progress.');
    }
    _signingIn = true;
    try {
      final (url, tx) = await createAuthorizationRequest(
          scopes: scopes,
          prompt: prompt,
          maxAge: maxAge,
          loginHint: loginHint,
          uiLocales: uiLocales,
          authorizationDetails: authorizationDetails);
      final back = await _browser.authenticate(url.toString(), redirectUri,
          ephemeral: ephemeralSession);
      final s = await completeAuthorization(back, tx);
      await _save(s);
      return s;
    } finally {
      _signingIn = false;
    }
  }

  // ------------------------------------------------------------------ session
  String _k(String n) =>
      'identvia.${clientId.replaceAll(RegExp(r'[^A-Za-z0-9._-]'), '_')}.$n';

  Future<IdentviaSession?> currentSession() async {
    if (_loaded) return _session;
    final meta = await _store.read(_k('session'));
    final rt = await _store.read(_k('rt'));
    if (meta != null) {
      try {
        final j = jsonDecode(meta) as Map<String, dynamic>;
        final t = IdentviaTokens.fromJson(j['tokens'] as Map<String, dynamic>)
          ..refreshToken = rt;
        _session = IdentviaSession(
            IdTokenClaims(j['user'] as Map<String, dynamic>), t);
      } catch (_) {
        _session = null;
      }
    }
    _loaded = true;
    return _session;
  }

  Future<void> _save(IdentviaSession? s) async {
    _session = s;
    _loaded = true;
    if (s == null) {
      await _store.delete(_k('session'));
      await _store.delete(_k('rt'));
    } else {
      await _store.write(
          _k('session'),
          jsonEncode({
            'user': s.user.toJson(),
            'tokens': s.tokens.toJson(includeRefresh: false)
          }));
      final rt = s.tokens.refreshToken;
      if (rt != null) {
        await _store.write(_k('rt'), rt);
      } else {
        await _store.delete(_k('rt'));
      }
    }
    _changes.add(s);
  }

  /// A valid access token, refreshed (with rotation) when it is about to expire. Throws TokenException('login_required').
  Future<String> getAccessToken({bool forceRefresh = false}) async {
    var s = await currentSession();
    if (s == null) {
      throw TokenException('login_required', 'Not signed in.', 401);
    }
    if (!forceRefresh &&
        s.tokens.expiresAt.subtract(refreshLeeway).isAfter(_clock())) {
      return s.tokens.accessToken;
    }
    _refreshing ??= _refresh(s).whenComplete(() => _refreshing = null);
    s = await _refreshing;
    if (s == null) {
      throw TokenException(
          'login_required', 'Your session ended. Please sign in again.', 401);
    }
    return s.tokens.accessToken;
  }

  Future<IdentviaSession?> _refresh(IdentviaSession s) async {
    final rt = s.tokens.refreshToken;
    if (rt == null) {
      await _save(null);
      return null;
    }
    try {
      final t = _tokens(await _post(await _endpoint('token_endpoint'),
          {'grant_type': 'refresh_token', 'refresh_token': rt}));
      var user = s.user;
      if (t.idToken != null) {
        user =
            await _validator.validate(t.idToken!, accessToken: t.accessToken);
        if (user.sub != s.user.sub) {
          throw ValidationException(
              'Refreshed ID token is for a different user.');
        }
      } else {
        t.idToken = s.tokens.idToken;
      }
      t.refreshToken ??= rt;
      final next = IdentviaSession(user, t);
      await _save(next);
      return next;
    } on TokenException catch (e) {
      if (e.error == 'invalid_grant' || e.status == 401) {
        await _save(
            null); // rotated-out token reused somewhere → Identvia revoked the chain
        return null;
      }
      rethrow;
    }
  }

  Future<Map<String, dynamic>> userinfo() async {
    final s = await currentSession();
    final at = await getAccessToken();
    final (code, d) = await _json(_http
        .get(Uri.parse(await _endpoint('userinfo_endpoint')), headers: {
      'Authorization': 'Bearer $at',
      'Accept': 'application/json'
    }));
    if (code == 401) {
      throw TokenException('invalid_token', 'Access token rejected.', 401);
    }
    if (code != 200 || d['sub'] is! String) {
      throw IdentviaException('http_error', 'Userinfo failed (HTTP $code).');
    }
    if (s != null && !safeEquals(s.user.sub, d['sub'] as String)) {
      throw ValidationException('Userinfo is for a different user.');
    }
    return d;
  }

  /// Revokes the refresh token and deletes the stored session. [federated] also ends the Identvia browser session.
  Future<void> signOut(
      {bool federated = false, String? postLogoutRedirectUri}) async {
    final s = await currentSession();
    await _save(null);
    if (s != null) {
      final token = s.tokens.refreshToken ?? s.tokens.accessToken;
      try {
        await _post(await _endpoint('revocation_endpoint'), {
          'token': token,
          'token_type_hint':
              s.tokens.refreshToken != null ? 'refresh_token' : 'access_token'
        });
      } catch (_) {/* local sign-out already happened */}
    }
    if (federated) {
      final back =
          assertNativeRedirect(postLogoutRedirectUri ?? redirectUri.toString());
      final end = Uri.parse(await _endpoint('end_session_endpoint'))
          .replace(queryParameters: {
        'client_id': clientId,
        if (s?.tokens.idToken != null) 'id_token_hint': s!.tokens.idToken!,
        'post_logout_redirect_uri': back.toString(),
      });
      try {
        await _browser.authenticate(end.toString(), back,
            ephemeral: ephemeralSession);
      } catch (_) {}
    }
  }

  void dispose() {
    _changes.close();
    _http.close();
  }
}
