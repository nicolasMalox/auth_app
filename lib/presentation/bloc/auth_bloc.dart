import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_popcorn_app/core/storage/secure_storage.dart';
import 'package:flutter_popcorn_app/data/repositories/auth_repository.dart';
import 'package:flutter_popcorn_app/presentation/bloc/auth_event.dart';
import 'package:flutter_popcorn_app/presentation/bloc/auth_state.dart';
import '../../core/services/key_service.dart';
import 'dart:async';

class AuthBloc extends Bloc<AuthEvent, AuthState> {
  final AuthRepository authRepository = AuthRepository();

  AuthBloc() : super(AuthInitial()) {
    on<InitialEvent>(_onInitialEvent);
    on<SendOtpEvent>(_onSendOtpEvent);
    on<RegisterUserEvent>(_onRegisterUserEvent);
    on<LoginUserEvent>(_onLoginUserEvent);
  }

  /// Handles initial app event (if needed in the future)
  void _onInitialEvent(event, emit) {}

  /// Sends an OTP to the user's email for authentication
  Future<void> _onSendOtpEvent(event, emit) async {
    emit(AuthLoading());
    try {
      final success = await authRepository.sendOtp(event.email);
      if (success) {
        emit(AuthOtpSent());
      } else {
        emit(AuthError('Failed to send OTP.'));
      }
    } catch (e) {
      emit(AuthError(e.toString()));
    }
  }

  /// Handles user registration, generating key pairs and storing the public key
  Future<void> _onRegisterUserEvent(event, emit) async {
    emit(AuthLoading());
    try {
      // Generate key pair and store securely
      await KeyService().generateAndStoreKeys();

      // Retrieve stored public key
      final publicKey = await SecureStorage.getPublicKey();
      if (publicKey == null) {
        emit(AuthError('Failed to generate public key.'));
        return;
      }

      // Register user with the generated passkey
      final success = await authRepository.signUp(event.email, event.pin, publicKey);

      if (success) {
        emit(AuthRegistered());
      } else {
        emit(AuthError('User registration failed.'));
      }
    } catch (e) {
      emit(AuthError(e.toString()));
    }
  }

  /// Handles user login using passkey authentication
  Future<void> _onLoginUserEvent(event, emit) async {
    emit(AuthLoading());
    try {
      // Retrieve stored public key
      final publicKey = await SecureStorage.getPublicKey();

      if (publicKey == null) {
        emit(AuthError("No stored public key found."));
        return;
      }

      // 1️ Request a challenge from the backend
      final challenge = await authRepository.generatePasskeyChallenge(event.email, publicKey);
      if (challenge == null) {
        emit(AuthError("Failed to retrieve challenge from the backend."));
        return;
      }

      // Retrieve stored private key
      final privateKeyPem = await SecureStorage.getPrivateKey();

      if (privateKeyPem == null) {
        emit(AuthError("No stored private key found."));
        return;
      }

      // 2️ Sign the challenge using the private key
      final signature = await KeyService().signChallenge(challenge, privateKeyPem);
      if (signature == null) {
        emit(AuthError("Failed to sign the challenge."));
        return;
      }

      // 3️ Send the signed challenge to the backend for authentication
      final token = await authRepository.signIn(event.email, signature);
      if (token != null) {
        emit(AuthLoggedIn(token));
      } else {
        emit(AuthError("Failed to log in."));
      }
    } catch (e) {
      emit(AuthError(e.toString()));
    }
  }
}
