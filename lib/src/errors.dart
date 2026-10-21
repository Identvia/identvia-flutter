/// Base class for everything the SDK throws. [code] is stable.
class IdentviaException implements Exception {
  IdentviaException(this.code, this.message);
  final String code;
  final String message;
  @override
  String toString() => 'IdentviaException($code): $message';
}

class ConfigurationException extends IdentviaException {
  ConfigurationException(String m) : super('configuration_error', m);
}

/// The callback doesn't belong to a sign-in this app started (state, iss or redirect mismatch).
class InvalidStateException extends IdentviaException {
  InvalidStateException(String m) : super('invalid_state', m);
}

class ValidationException extends IdentviaException {
  ValidationException(String m) : super('validation_error', m);
}

class UnsupportedException extends IdentviaException {
  UnsupportedException(String m) : super('unsupported', m);
}

/// The user closed the browser.
class CancelledException extends IdentviaException {
  CancelledException()
      : super('cancelled', 'The user closed the sign-in window.');
}

/// Identvia returned an OAuth error to the redirect URI (e.g. `access_denied`).
class AuthorizationException extends IdentviaException {
  AuthorizationException(this.error, [this.description])
      : super(error, description == null ? error : '$error: $description');
  final String error;
  final String? description;
}

/// An OAuth endpoint answered with an error.
class TokenException extends IdentviaException {
  TokenException(this.error, this.description, this.status)
      : super(error, description == null ? error : '$error: $description');
  final String error;
  final String? description;
  final int status;
}
