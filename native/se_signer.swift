// Shockwave Secure Enclave signer (§17 key custody).
// The private key is generated inside the Apple Secure Enclave and never leaves it: the file on
// disk is an opaque blob that only this device's Secure Enclave can use. Signatures are
// ECDSA P-256 over SHA-256 of the message (the Secure Enclave does not support Ed25519).
//
//   shockwave-se available          -> "yes" / "no"
//   shockwave-se create <blob>      -> base64 DER SubjectPublicKeyInfo of the new key
//   shockwave-se public <blob>      -> base64 DER SubjectPublicKeyInfo
//   shockwave-se sign   <blob>      -> base64 DER ECDSA signature of stdin bytes
//   shockwave-se kem-create <blob>  -> base64 DER public key of a new enclave key-agreement key
//   shockwave-se kem-derive <blob>  -> base64 ECDH shared secret with the base64 DER public key on stdin
//                                      (used to seal the Ed25519 key file; HKDF and AES-GCM run in Python)
import CryptoKit
import Foundation

func fail(_ message: String) -> Never {
    FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
    exit(2)
}

func load(_ path: String) throws -> SecureEnclave.P256.Signing.PrivateKey {
    try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Data(contentsOf: URL(fileURLWithPath: path)))
}

let args = CommandLine.arguments
guard args.count >= 2 else { fail("usage: shockwave-se available|create|public|sign [blob]") }

do {
    switch args[1] {
    case "available":
        print(SecureEnclave.isAvailable ? "yes" : "no")
    case "create":
        guard args.count == 3 else { fail("create needs a blob path") }
        guard SecureEnclave.isAvailable else { fail("Secure Enclave unavailable on this device") }
        let key = try SecureEnclave.P256.Signing.PrivateKey()
        try key.dataRepresentation.write(to: URL(fileURLWithPath: args[2]), options: [.atomic])
        print(key.publicKey.derRepresentation.base64EncodedString())
    case "public":
        guard args.count == 3 else { fail("public needs a blob path") }
        print(try load(args[2]).publicKey.derRepresentation.base64EncodedString())
    case "sign":
        guard args.count == 3 else { fail("sign needs a blob path") }
        let message = FileHandle.standardInput.readDataToEndOfFile()
        guard !message.isEmpty, message.count <= 1 << 20 else { fail("message must be 1 B to 1 MiB") }
        print(try load(args[2]).signature(for: message).derRepresentation.base64EncodedString())
    case "kem-create":
        guard args.count == 3 else { fail("kem-create needs a blob path") }
        guard SecureEnclave.isAvailable else { fail("Secure Enclave unavailable on this device") }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        try key.dataRepresentation.write(to: URL(fileURLWithPath: args[2]), options: [.atomic])
        print(key.publicKey.derRepresentation.base64EncodedString())
    case "kem-derive":
        guard args.count == 3 else { fail("kem-derive needs a blob path") }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: Data(contentsOf: URL(fileURLWithPath: args[2])))
        let input = String(decoding: FileHandle.standardInput.readDataToEndOfFile(), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard let der = Data(base64Encoded: input) else { fail("expected a base64 DER public key on stdin") }
        let secret = try key.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(derRepresentation: der))
        print(secret.withUnsafeBytes { Data($0) }.base64EncodedString())
    default:
        fail("unknown command")
    }
} catch {
    fail("Secure Enclave error: \(error)")
}
