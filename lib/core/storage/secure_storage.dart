import 'dart:developer';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';

class SecureStorage {
  static const _storage = FlutterSecureStorage();
  static const String _privateKeyKey = 'private_key';
  static const String _publicKeyKey = 'public_key';
  static final _auth = LocalAuthentication();

  static Future<bool> _authenticateWithBiometrics() async {
    try {
      return await _auth.authenticate(
        localizedReason: "Authenticate to access your private key",
        options: AuthenticationOptions(
          biometricOnly: true, // Ensure only biometrics are used
          stickyAuth: true, // Keeps session active if user switches apps
        ),
      );
    } catch (e) {
      log("Biometric authentication failed: $e");
      return false;
    }
  }

  static Future<void> clearKeys() async {
    await _storage.delete(key: _privateKeyKey);
    await _storage.delete(key: _publicKeyKey);
  }

  static Future<void> storePrivateKey(String privateKey) async {
    await _storage.write(
      key: _privateKeyKey,
      value: privateKey,
      iOptions: IOSOptions(
        accessibility: KeychainAccessibility.passcode,
      ),
      aOptions: AndroidOptions(
        encryptedSharedPreferences: true,
      ),
    );
  }

  static Future<String?> getPrivateKey() async {
    bool isAuthenticated = await _authenticateWithBiometrics();
    if (!isAuthenticated) return null;

    return await _storage.read(
      key: _privateKeyKey,
      iOptions: IOSOptions(
        accessibility: KeychainAccessibility.passcode,
      ),
      aOptions: AndroidOptions(
        encryptedSharedPreferences: true,
      ),
    );
  }

  static Future<void> storePublicKey(String publicKey) async {
    await _storage.write(key: _publicKeyKey, value: publicKey);
  }

  static Future<String?> getPublicKey() async {
    return await _storage.read(key: _publicKeyKey);
  }
}
