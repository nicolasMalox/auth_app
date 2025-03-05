import 'package:equatable/equatable.dart';

abstract class AuthEvent extends Equatable {
  @override
  List<Object> get props => [];
}

class InitialEvent extends AuthEvent {}

class SendOtpEvent extends AuthEvent {
  final String email;

  SendOtpEvent(this.email);

  @override
  List<Object> get props => [email];
}

class RegisterUserEvent extends AuthEvent {
  final String email;
  final String pin;

  RegisterUserEvent(this.email, this.pin);

  @override
  List<Object> get props => [email, pin];
}

class LoginUserEvent extends AuthEvent {
  final String email;

  LoginUserEvent(this.email);

  @override
  List<Object> get props => [email];
}
