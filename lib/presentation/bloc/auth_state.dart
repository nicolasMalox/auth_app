import 'package:equatable/equatable.dart';

abstract class AuthState extends Equatable {
  @override
  List<Object> get props => [];
}

class AuthInitial extends AuthState {}

class AuthLoading extends AuthState {}

class AuthOtpSent extends AuthState {}

class AuthRegistered extends AuthState {}

class AuthLoggedIn extends AuthState {
  final String token;

  AuthLoggedIn(this.token);

  @override
  List<Object> get props => [token];
}

class AuthError extends AuthState {
  final String message;

  AuthError(this.message);

  @override
  List<Object> get props => [message];
}
