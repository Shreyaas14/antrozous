// antrozous-helper — the entitled sliver that can hold a Secure Enclave key.
//
// The enclave will happily generate a key for anyone, but only a process signed
// with a keychain-access-groups entitlement may PERSIST one. Plain python3 has no
// entitlement, so mcp_gate gets errSecMissingEntitlement (-34018). This binary
// exists purely to be that signed process. It does one thing:
//
//     derive a 32-byte secret that only this Mac can reproduce
//
// The gate uses that secret to unwrap ~/.antrozous/key.enc. The enclave key itself
// never leaves the chip, so a copy of the key file is inert on any other machine.
//
// Why ECDH against a stored public point rather than signing: Secure Enclave keys
// are ECDSA P-256, and ECDSA signatures are randomised — you would get different
// bytes every call and could never decrypt anything twice. Key agreement is
// deterministic for a fixed pair, which is what wrapping requires.
//
//   helper init            -> print a fresh peer public key (base64). Store it.
//   helper derive <peer>   -> print the 32-byte secret (base64). Prompts Touch ID
//                             when built with biometry required.

import Foundation
import Security

let KEY_TAG = "com.antrozous.wrap.v1".data(using: .utf8)!

// Touch ID on every gate start is opt-in: ANTROZOUS_ENCLAVE_BIOMETRY=1. Without it
// the key is still enclave-bound and non-exportable, which already defeats disk
// theft — it just does not demand a fingerprint to use.
let REQUIRE_BIOMETRY = ProcessInfo.processInfo.environment["ANTROZOUS_ENCLAVE_BIOMETRY"] == "1"

struct HelperError: Error, CustomStringConvertible {
    let description: String
    init(_ message: String) { self.description = message }
}

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(("antrozous-helper: " + message + "\n").data(using: .utf8)!)
    exit(1)
}

func cfError(_ error: Unmanaged<CFError>?) -> String {
    guard let error = error?.takeRetainedValue() else { return "unknown error" }
    return CFErrorCopyDescription(error) as String? ?? "unknown error"
}

/// The enclave key's usage policy. `.privateKeyUsage` alone means "enclave-bound";
/// adding `.biometryCurrentSet` also demands a fingerprint match, and invalidates
/// the key if the enrolled set changes — so adding a finger later cannot silently
/// widen who is able to unwrap.
func accessControl() throws -> SecAccessControl {
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if REQUIRE_BIOMETRY { flags.insert(.biometryCurrentSet) }
    var error: Unmanaged<CFError>?
    guard let control = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        flags,
        &error
    ) else {
        throw HelperError("could not build an access policy: \(cfError(error))")
    }
    return control
}

func findKey() -> SecKey? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: KEY_TAG,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecReturnRef as String: true,
    ]
    var out: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess else { return nil }
    return (out as! SecKey?)
}

func createKey() throws -> SecKey {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: KEY_TAG,
            kSecAttrAccessControl as String: try accessControl(),
        ],
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw HelperError("enclave refused to create a key: \(cfError(error))")
    }
    return key
}

func enclaveKey() throws -> SecKey {
    if let existing = findKey() { return existing }
    return try createKey()
}

/// A throwaway P-256 public key to agree against. The private half is generated in
/// software and dropped immediately — it is a fixed point, never a secret, so
/// storing the public half next to the wrapped blob gives an attacker nothing.
func makePeerPublic() throws -> Data {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
    ]
    var error: Unmanaged<CFError>?
    guard let priv = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw HelperError("could not generate a peer keypair: \(cfError(error))")
    }
    guard let pub = SecKeyCopyPublicKey(priv) else {
        throw HelperError("could not read the peer public key")
    }
    guard let raw = SecKeyCopyExternalRepresentation(pub, &error) as Data? else {
        throw HelperError("could not export the peer public key: \(cfError(error))")
    }
    return raw
}

func derive(peerPublic: Data) throws -> Data {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
    ]
    var error: Unmanaged<CFError>?
    guard let peer = SecKeyCreateWithData(peerPublic as CFData, attributes as CFDictionary, &error)
    else {
        throw HelperError("stored peer public key is unusable: \(cfError(error))")
    }
    let priv = try enclaveKey()
    guard let shared = SecKeyCopyKeyExchangeResult(
        priv,
        .ecdhKeyExchangeStandard,
        peer,
        [:] as CFDictionary,
        &error
    ) as Data? else {
        throw HelperError(
            "key exchange refused: \(cfError(error)) "
            + "(cancelled Touch ID, or the key was invalidated)")
    }
    guard shared.count >= 32 else {
        throw HelperError("key exchange returned \(shared.count) bytes")
    }
    return shared.prefix(32)
}

let args = CommandLine.arguments
guard args.count >= 2 else {
    fail("usage: antrozous-helper init | derive <peer-public-base64>")
}

do {
    switch args[1] {
    case "init":
        print(try makePeerPublic().base64EncodedString())
    case "derive":
        guard args.count >= 3, let peer = Data(base64Encoded: args[2]) else {
            fail("derive needs a base64 peer public key")
        }
        print(try derive(peerPublic: peer).base64EncodedString())
    case "check":
        // Proves the entitlement works without touching the wrapped file.
        _ = try enclaveKey()
        print("ok biometry=\(REQUIRE_BIOMETRY)")
    default:
        fail("unknown command \(args[1])")
    }
} catch {
    fail("\(error)")
}
