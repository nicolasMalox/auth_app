import 'dart:developer';
import 'package:flutter_popcorn_app/core/storage/secure_storage.dart';
import 'package:graphql_flutter/graphql_flutter.dart';

class AuthRepository {
  /// GraphQL client to interact with the authentication server.
  final GraphQLClient client = GraphQLClient(
    link: HttpLink("https://api-staging.popcorn.space/graphql"),
    cache: GraphQLCache(),
  );

  /// Sends an OTP (One-Time Password) for user verification.
  Future<bool> sendOtp(String email) async {
    final MutationOptions options = MutationOptions(
      document: gql("""
        mutation sendOtpSignUp {
          sendOtpEmailSignUp(email: "$email") {
            succeeded
          }
        }
      """),
    );

    final result = await client.mutate(options);
    return result.data?['sendOtpEmailSignUp']['succeeded'] ?? false;
  }

  /// SignUp a new user by signing up and associating a passkey.
  Future<bool> signUp(String email, String pin, String publicKey) async {
    final MutationOptions signUpOptions = MutationOptions(
      document: gql("""
      mutation signUp {
        signUpWithOtp(email: "$email", code: "111111", userInputDto: {
          email: "$email",
          firstName: "John",
          lastName: "Doe",
          addressLine1: "123 Main St",
          addressLine2: "Apt 4B",
          city: "New York",
          country: "USA",
          state: "NY",
          zip: "10001"
        }) {
          succeeded
          userErrors {
            code
            message
          }
        }
      }
    """),
    );

    final signUpResult = await client.mutate(signUpOptions);

    log("GraphQL Response (signUp): ${signUpResult.data}");
    log("GraphQL Errors (signUp): ${signUpResult.exception?.graphqlErrors}");

    if (signUpResult.hasException || signUpResult.data?['signUpWithOtp']['succeeded'] == false) {
      log("Error in signUpWithOtp");
      return false;
    }

    final MutationOptions resetPasskeyOptions = MutationOptions(
      document: gql("""
      mutation resetPasskey {
        resetPasskeyWithOtpByUsername(
          username: "$email",
          code: "111111",
          pin: "$pin",
          newPublicKey: "$publicKey"
        ) {
          succeeded
          token
          userErrors {
            code
            message
          }
        }
      }
    """),
    );

    final resetPasskeyResult = await client.mutate(resetPasskeyOptions);

    log("GraphQL Response (resetPasskey): ${resetPasskeyResult.data}");
    log("GraphQL Errors (resetPasskey): ${resetPasskeyResult.exception?.graphqlErrors}");

    if (resetPasskeyResult.hasException ||
        resetPasskeyResult.data?['resetPasskeyWithOtpByUsername']['succeeded'] == false) {
      log("Error in resetPasskeyWithOtpByUsername");
      return false;
    }

    return true;
  }

  /// Requests a challenge for passkey authentication.
  Future<String?> generatePasskeyChallenge(String email, publicKey) async {
    if (publicKey.isEmpty) {
      log("Error: No stored public key found.");
      return null;
    }

    final MutationOptions options = MutationOptions(
      document: gql("""
      mutation generatePasskeyChallenge {
        generatePasskeyChallengeByUsername(username: "$email", publicKey: "$publicKey") {
          succeeded
          challenge
          userErrors {
            code
            message
          }
        }
      }
    """),
    );

    final result = await client.mutate(options);

    log("GraphQL Response (generatePasskeyChallenge): ${result.data}");
    log("GraphQL Errors (generatePasskeyChallenge): ${result.exception?.graphqlErrors}");

    if (result.hasException) {
      log("Error in generatePasskeyChallenge: ${result.exception.toString()}");
      return null;
    }

    if (result.data?['generatePasskeyChallengeByUsername']['succeeded'] == true) {
      return result.data?['generatePasskeyChallengeByUsername']['challenge'];
    }

    final List<dynamic>? errors = result.data?['generatePasskeyChallengeByUsername']['userErrors'];
    if (errors != null && errors.isNotEmpty) {
      final errorMessage = errors.map((e) => e['message']).join(", ");
      log("Error in generatePasskeyChallenge: $errorMessage");
    }

    return null;
  }

  /// Attempts to sign in the user using a passkey signature.
  Future<String?> signIn(String email, String signature) async {
    final publicKey = await SecureStorage.getPublicKey();
    if (publicKey == null) {
      log("Error: No stored public key found.");
      return null;
    }

    final MutationOptions options = MutationOptions(
      document: gql("""
      mutation signIn {
        signInByUsername(username: "$email", signature: "$signature", publicKey: "$publicKey") {
          succeeded
          token
          userErrors {
            code
            message
          }
        }
      }
    """),
    );

    final result = await client.mutate(options);

    log("GraphQL Response (signIn): ${result.data}");
    log("GraphQL Errors (signIn): ${result.exception?.graphqlErrors}");

    if (result.hasException) {
      log("Error in signIn: ${result.exception.toString()}");
      return null;
    }

    final data = result.data?['signInByUsername'];
    if (data?['succeeded'] == true) {
      return data['token'];
    }

    final List<dynamic>? errors = data?['userErrors'];
    if (errors != null && errors.isNotEmpty) {
      final errorMessage = errors.map((e) => e['message']).join(", ");
      log("Error in signIn: $errorMessage");
    }

    return null;
  }
}
