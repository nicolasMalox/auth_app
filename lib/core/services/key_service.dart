import 'dart:convert';
import 'dart:typed_data';
import 'dart:math' as math;
import 'dart:developer';
import 'package:pointycastle/export.dart';
import 'package:asn1lib/asn1lib.dart';
import '../storage/secure_storage.dart';

class KeyService {
  ///  MAIN METHODS (Key Handling)

  /// Generates an EC P-256 key pair and securely stores them.
  Future<void> generateAndStoreKeys() async {
    await SecureStorage.clearKeys();

    final keyPair = _generateEcKeyPair();
    final ecPrivateKey = keyPair.privateKey as ECPrivateKey;
    final ecPublicKey = keyPair.publicKey as ECPublicKey;

    final privatePem = _encodeEcPrivateKeyToPemPKCS8(ecPrivateKey);
    final publicPem = _encodeEcPublicKeyToPemSPKI(ecPublicKey);

    await SecureStorage.storePrivateKey(privatePem);
    await SecureStorage.storePublicKey(base64Encode(utf8.encode(publicPem)));
  }

  /// Retrieves the stored private key, signs the given challenge, and returns the signature in Base64.
  Future<String?> signChallenge(String challenge, privateKeyPem) async {
    if (privateKeyPem == null) {
      log("Error: Private key not found in SecureStorage.");
      return null;
    }

    try {
      // Convert PEM to DER format
      final ecPrivateKey = _decodePemToECPrivateKey(privateKeyPem);
      log("Private key converted to DER format: $ecPrivateKey");

      return _signData(challenge, ecPrivateKey);
    } catch (e) {
      log("Error signing the challenge: $e");
      return null;
    }
  }

  /// Signs the given data using ECDSA with SHA-256 and returns a Base64 DER-encoded signature.
  String _signData(String data, ECPrivateKey privateKey) {
    // ECDSA with SHA-256
    final signer = Signer('SHA-256/ECDSA');
    final privateKeyParams = PrivateKeyParameter<ECPrivateKey>(privateKey);

    // Reuse a FortunaRandom seed for ECDSA ephemeral k
    signer.init(true, ParametersWithRandom(privateKeyParams, _createFortunaRandom()));

    // 1) Generate raw signature (r, s)
    final ecSignature = signer.generateSignature(utf8.encode(data)) as ECSignature;

    // 2) Convert raw (r, s) into a 64-byte sequence
    final rBytes = _bigIntToUint8List(ecSignature.r);
    final sBytes = _bigIntToUint8List(ecSignature.s);
    final rawSignature = Uint8List.fromList(rBytes + sBytes);

    // 3) Convert that raw 64-byte signature to DER
    final derSignature = _rawSignatureToDer(rawSignature);

    // 4) Return it in base64
    return base64Encode(derSignature);
  }

  ///  AUXILIARY METHODS

  /// Converts a raw (r, s) ECDSA signature into a DER-encoded format.
  static Uint8List _rawSignatureToDer(Uint8List rawSignature) {
    final seq = ASN1Sequence()
      ..add(ASN1Integer(_bytesToBigInt(rawSignature.sublist(0, 32))))
      ..add(ASN1Integer(_bytesToBigInt(rawSignature.sublist(32))));
    return seq.encodedBytes;
  }

  /// Generates an EC P-256 key pair.
  AsymmetricKeyPair<PublicKey, PrivateKey> _generateEcKeyPair() {
    final domainParams = ECDomainParameters('secp256r1');
    final keyParams = ECKeyGeneratorParameters(domainParams);

    // Create a Fortuna RNG and seed it with secure random bytes
    final secureRandom = FortunaRandom();
    final random = math.Random.secure();
    final seeds = List<int>.generate(32, (_) => random.nextInt(256));
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));

    // Generate the keypair
    final generator = ECKeyGenerator();
    generator.init(ParametersWithRandom(keyParams, secureRandom));
    final pair = generator.generateKeyPair();
    return pair;
  }

  /// Encodes the EC private key in PKCS#8 PEM format.
  String _encodeEcPrivateKeyToPemPKCS8(ECPrivateKey ecPrivateKey) {
    // version = 0
    final version = ASN1Integer(BigInt.zero);

    // Private key OCTET STRING (force unwrapped with `d!`)
    final privateKeyOctet = ASN1OctetString(_bigIntToUint8List(ecPrivateKey.d!));

    // domain parameters (ecPublicKey + prime256v1)
    final domainParameterSequence = ASN1Sequence();
    final oidEC = ASN1ObjectIdentifier([1, 2, 840, 10045, 2, 1]); // ecPublicKey
    final oidPrime256v1 = ASN1ObjectIdentifier([1, 2, 840, 10045, 3, 1, 7]); // prime256v1/secp256r1
    domainParameterSequence.add(oidEC);
    domainParameterSequence.add(oidPrime256v1);

    // Build inner private key sequence
    final privateKeySequence = ASN1Sequence();
    privateKeySequence.add(version);
    privateKeySequence.add(privateKeyOctet);

    // [0] EXPLICIT tagging for domain params
    final publicKeyOptional = ASN1Sequence(tag: 0xA0);
    publicKeyOptional.add(domainParameterSequence);
    privateKeySequence.add(publicKeyOptional);

    // AlgorithmIdentifier sequence
    final algorithmSequence = ASN1Sequence();
    algorithmSequence.add(oidEC);
    algorithmSequence.add(oidPrime256v1);

    // PKCS#8 top-level
    final topLevelSequence = ASN1Sequence();
    topLevelSequence.add(algorithmSequence);

    // Wrap our EC private key sequence in an OCTET STRING
    final privateKeySequenceOctet = ASN1OctetString(privateKeySequence.encodedBytes);

    topLevelSequence.add(privateKeySequenceOctet);

    // Encode top-level ASN.1 sequence as DER, then Base64, then wrap as PEM
    final base64Text = base64Encode(topLevelSequence.encodedBytes);

    return '-----BEGIN PRIVATE KEY-----\r\n'
        '${_chunkEncoded(base64Text)}'
        '-----END PRIVATE KEY-----';
  }

  /// Decodes the PKCS#8 PEM private key in EC format.
  ECPrivateKey _decodePemToECPrivateKey(String pem) {
    // 1. Remove headers and decode Base64
    final base64String = pem
        .replaceAll('-----BEGIN PRIVATE KEY-----', '')
        .replaceAll('-----END PRIVATE KEY-----', '')
        .replaceAll('\r', '')
        .replaceAll('\n', '');

    final derBytes = base64Decode(base64String);

    // 2. Parse ASN.1
    final asn1Parser = ASN1Parser(derBytes);
    final topLevelSequence = asn1Parser.nextObject() as ASN1Sequence;

    // 3. Extract the actual content of the private key
    final privateKeyOctetString = topLevelSequence.elements[1] as ASN1OctetString;

    // 4. Parse the real private key
    final privateKeyParser = ASN1Parser(privateKeyOctetString.valueBytes());
    final privateKeySequence = privateKeyParser.nextObject() as ASN1Sequence;

    final dOctetString = privateKeySequence.elements[1] as ASN1OctetString;
    final d = _uint8ListToBigInt(dOctetString.valueBytes());

    return ECPrivateKey(d, ECDomainParameters('prime256v1'));
  }

  BigInt _uint8ListToBigInt(Uint8List bytes) {
    return bytes.fold<BigInt>(BigInt.zero, (BigInt v, int byte) => (v << 8) | BigInt.from(byte));
  }

  /// Encodes the EC public key in SPKI PEM format.
  String _encodeEcPublicKeyToPemSPKI(ECPublicKey publicKey) {
    final point = publicKey.Q!;
    final encodedBytes = _encodeEcPoint(point);

    // AlgorithmIdentifier
    final algorithmSequence = ASN1Sequence();
    final oidEC = ASN1ObjectIdentifier([1, 2, 840, 10045, 2, 1]);
    final oidPrime256v1 = ASN1ObjectIdentifier([1, 2, 840, 10045, 3, 1, 7]);
    algorithmSequence.add(oidEC);
    algorithmSequence.add(oidPrime256v1);

    // SubjectPublicKey BIT STRING
    final subjectPublicKey = ASN1BitString(encodedBytes);

    // SPKI top-level
    final topLevelSequence = ASN1Sequence();
    topLevelSequence.add(algorithmSequence);
    topLevelSequence.add(subjectPublicKey);

    // DER-encode, then Base64, then wrap as PEM
    final base64Text = base64Encode(topLevelSequence.encodedBytes);

    return '-----BEGIN PUBLIC KEY-----\r\n'
        '${_chunkEncoded(base64Text)}'
        '-----END PUBLIC KEY-----';
  }

  Uint8List _encodeEcPoint(ECPoint point) {
    final x = point.x!.toBigInteger()!;
    final y = point.y!.toBigInteger()!;
    final byteLen = (point.curve.fieldSize + 7) >> 3;

    final xBytes = _bigIntToUint8List(x);
    final yBytes = _bigIntToUint8List(y);

    // Pad X/Y so they are exactly [byteLen] bytes
    final paddedX = Uint8List(byteLen - xBytes.length) + xBytes;
    final paddedY = Uint8List(byteLen - yBytes.length) + yBytes;

    return Uint8List.fromList([0x04, ...paddedX, ...paddedY]);
  }

  /// Converts a BigInt to Uint8List.
  Uint8List _bigIntToUint8List(BigInt v) {
    final bytes = <int>[];
    var temp = v;
    while (temp > BigInt.zero) {
      bytes.add((temp & BigInt.from(0xff)).toInt());
      temp >>= 8;
    }
    return Uint8List.fromList(bytes.reversed.toList());
  }

  /// Converts a Uint8List to BigInt.
  static BigInt _bytesToBigInt(Uint8List bytes) =>
      bytes.fold(BigInt.zero, (acc, byte) => (acc << 8) | BigInt.from(byte));

  /// Generates a secure random number generator using Fortuna.
  FortunaRandom _createFortunaRandom() {
    final secureRandom = FortunaRandom();
    final random = math.Random.secure();
    final seeds = List<int>.generate(32, (_) => random.nextInt(256));
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
    return secureRandom;
  }

  /// Formats Base64 text into lines of 64 characters (PEM format).
  String _chunkEncoded(String b64Text) {
    const chunkSize = 64;
    final buffer = StringBuffer();
    for (var i = 0; i < b64Text.length; i += chunkSize) {
      buffer.writeln(b64Text.substring(
        i,
        (i + chunkSize > b64Text.length) ? b64Text.length : i + chunkSize,
      ));
    }
    return buffer.toString();
  }
}
