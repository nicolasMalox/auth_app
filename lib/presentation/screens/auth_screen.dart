import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_popcorn_app/presentation/widgets/auth_button_widget.dart';
import '../bloc/auth_bloc.dart';
import '../bloc/auth_event.dart';
import '../bloc/auth_state.dart';

class AuthScreen extends StatelessWidget {
  final TextEditingController emailController = TextEditingController();
  final TextEditingController pinController = TextEditingController();

  static Widget builder(BuildContext context) {
    return BlocProvider<AuthBloc>(
      create: (context) => AuthBloc()..add(InitialEvent()),
      child: AuthScreen(),
    );
  }

  AuthScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("Authentication")),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          children: [
            TextField(
              controller: emailController,
              decoration: const InputDecoration(labelText: "Email"),
            ),
            TextField(
              controller: pinController,
              decoration: const InputDecoration(labelText: "PIN"),
              obscureText: true,
              keyboardType: TextInputType.number,
            ),
            const SizedBox(height: 20),
            BlocConsumer<AuthBloc, AuthState>(
              listener: (context, state) {
                if (state is AuthOtpSent) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text("OTP sent successfully!")),
                  );
                } else if (state is AuthRegistered) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text("Registration successful!")),
                  );
                } else if (state is AuthLoggedIn) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text("Login successful! Token: ${state.token}")),
                  );
                } else if (state is AuthError) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text(state.message)),
                  );
                }
              },
              builder: (context, state) {
                if (state is AuthLoading) {
                  return const CircularProgressIndicator();
                }
                return Column(
                  children: [
                    AuthButton(
                      label: "Send OTP",
                      onPressed: () {
                        final email = emailController.text.trim();
                        if (email.isNotEmpty) {
                          context.read<AuthBloc>().add(SendOtpEvent(email));
                        } else {
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text("Please enter an email")),
                          );
                        }
                      },
                    ),
                    AuthButton(
                      label: "Sign Up",
                      onPressed: () {
                        final email = emailController.text.trim();
                        final pin = pinController.text.trim();
                        if (email.isNotEmpty && pin.length == 4) {
                          context.read<AuthBloc>().add(RegisterUserEvent(email, pin));
                        } else {
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text("Enter a valid email and 4-digit PIN")),
                          );
                        }
                      },
                    ),
                    AuthButton(
                      label: "Login",
                      onPressed: () {
                        final email = emailController.text.trim();
                        if (email.isNotEmpty) {
                          context.read<AuthBloc>().add(LoginUserEvent(email));
                        } else {
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text("Please enter an email")),
                          );
                        }
                      },
                    ),
                  ],
                );
              },
            ),
          ],
        ),
      ),
    );
  }
}
