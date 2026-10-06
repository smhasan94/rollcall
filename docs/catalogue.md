# Algorithm catalogue

`rollcall assay` describes each cryptographic algorithm it finds with the CycloneDX 1.6
`algorithmProperties` of a crypto asset: its primitive, parameter set, mode, functions, and its
classical and post-quantum security levels. Those facts do not depend on the build, so they are
kept once, in a catalogue, instead of in each detector.

## What the catalogue is

[`crates/rollcall-assay/db/algorithms.yaml`](../crates/rollcall-assay/db/algorithms.yaml) is
data, not code. It is built into `rollcall-assay` and loaded with `Catalogue::builtin()`. It is
the single source of truth for the algorithm data rollcall and cbom-infra share: changes are made
here first, and cbom-infra copies the file (see
[Export contract and sync with cbom-infra](#export-contract-and-sync-with-cbom-infra)).

It covers RSA (PSS and PKCS #1 v1.5 signatures, OAEP encryption), DSA, finite-field DH, ECDSA, ECDH,
Ed25519, X25519, AES in ECB, CBC, CTR, GCM and CCM with 128-, 192- and 256-bit keys,
ChaCha20-Poly1305, the SHA-2 and SHA-3 hash families, SHAKE, HMAC, HKDF, PBKDF2, ML-KEM, ML-DSA,
SLH-DSA, LMS, HSS, XMSS and XMSS^MT.

## Schema

```yaml
format: rollcall-algorithms/1
algorithms:
  - name: AES-GCM
    family: AES
    primitive: ae
    mode: gcm
    crypto_functions: [decrypt, encrypt, tag]
    quantum_risk: grover-weakened
    standards: [FIPS 197, SP 800-38D]
    parameter_sets:
      - id: "128"
        classical_security_level: 128
        nist_quantum_security_level: 1
        oid: 2.16.840.1.101.3.4.1.6
        source: "SP 800-57 Pt 1 Rev 5 Table 2: AES-128 → 128 bits; NIST PQC CfP §4.A.5: category 1 is key search on AES-128"
```

| Field | Required | Meaning |
|-------|----------|---------|
| `format` | yes | `rollcall-algorithms/1` |
| `name` | yes | The lookup key: one entry per family, primitive and mode or padding (`AES-GCM`, `RSA-PSS`). `[A-Za-z0-9][A-Za-z0-9+/.-]*`, unique ignoring case; entries are in name order (ASCII, ignoring case) |
| `family` | yes | The algorithm family (`AES`, `RSA`, `SHA2`) |
| `primitive` | yes | A CycloneDX 1.6 `primitive` word |
| `mode` | no | A CycloneDX 1.6 `mode` word |
| `padding` | no | `oaep`, `pss` or `pkcs1v15`; only on a `signature` or `pke` primitive |
| `crypto_functions` | no | CycloneDX 1.6 `cryptoFunctions` words, in ASCII order, without duplicates |
| `quantum_risk` | yes | `shor-broken`, `grover-weakened` or `pq-safe` ([Risk classes](#risk-classes)) |
| `standards` | yes | The documents that specify the algorithm; at least one |
| `parameter_sets` | yes | At least one; ids unique within the entry |
| `id` | yes | The CycloneDX `parameterSetIdentifier`, always a quoted string (`"128"`) |
| `classical_security_level` | yes | Bits |
| `nist_quantum_security_level` | yes | The NIST category, `0` to `6` (`0`: none) |
| `curve` | no | The elliptic curve |
| `oid` | no | The object identifier, dotted decimal; left out where there is no single OID for the entry. Quote an OID with only two arcs (`"1.3"`), which YAML would otherwise read as a number |
| `source` | yes | Where the two levels come from, in words |

Unknown keys are an error. The same shape as a JSON Schema (draft 2020-12) is
[`algorithms.schema.json`](../crates/rollcall-assay/db/algorithms.schema.json), whose `required`
lists are the loader's (a test keeps them in step). Loading also runs a lint for what a schema
cannot say: names unique and in order, the risk class agreeing with the levels (below), padding
only on signatures and encryption, `crypto_functions` in order.

## Risk classes

Every entry has one `quantum_risk`:

| Class | Meaning | NIST level | Entries |
|-------|---------|------------|---------|
| `shor-broken` | A large quantum computer running Shor's algorithm solves the factoring or discrete-logarithm problem the algorithm rests on and recovers the key. No key size helps. | `0` for every parameter set (the lint enforces it) | RSA, DSA, DH, ECDSA, ECDH, Ed25519, X25519 |
| `grover-weakened` | Grover's search (or a quantum collision search) speeds up brute force, but a larger key or digest restores the margin. | Per parameter set | AES, ChaCha20-Poly1305, SHA-2, SHA-3, SHAKE, HMAC, HKDF, PBKDF2 |
| `pq-safe` | Designed to resist a quantum computer. | `1` or more for every parameter set (the lint enforces it) | ML-KEM, ML-DSA, SLH-DSA, LMS, HSS, XMSS, XMSS^MT |

The class says what to do: a `shor-broken` algorithm must be replaced before a quantum computer
arrives; a `grover-weakened` one needs the larger parameter set; a `pq-safe` one is the
replacement.

## Where the numbers come from

Every parameter set's `source` says where its two numbers come from. The rules:

**Classical security levels** come from NIST SP 800-57 Part 1 Rev. 5, Table 2 (comparable
strengths) and Table 3 (hash functions):

| Family | Classical level |
|--------|-----------------|
| AES | The key size: AES-128 → 128, AES-192 → 192, AES-256 → 256 (Table 2) |
| ChaCha20-Poly1305 | 256: a 256-bit key, rated by key size as Table 2 rates AES-256 |
| RSA | Table 2, IFC modulus k: 2048 → 112, 3072 → 128, 7680 → 192, 15360 → 256. A size between two rows takes the lower: 4096 → 128 |
| DSA | Table 2, FFC (L, N): (2048, 224) and (2048, 256) → 112, (3072, 256) → 128 |
| DH | Table 2, FFC modulus L, for the RFC 7919 groups: ffdhe2048 → 112, ffdhe3072, ffdhe4096 and ffdhe6144 → 128, ffdhe8192 → 192 (between rows, the lower) |
| ECDSA, ECDH | Table 2, ECC order size f (half of it): P-256 → 128, P-384 → 192, P-521 → 256 |
| Ed25519, X25519 | 128, as SP 800-186 and RFC 7748 rate Curve25519 and Edwards25519 (subgroup order ≈ 2^252) |
| SHA2, SHA3 | Table 3, the collision-resistance column (half the digest): SHA-224, SHA-512/224, SHA3-224 → 112; SHA-256, SHA-512/256, SHA3-256 → 128; SHA-384, SHA3-384 → 192; SHA-512, SHA3-512 → 256 |
| SHAKE (family SHA3) | FIPS 202 Table 4, the collision strength: SHAKE128 → 128 (output ≥ 256 bits), SHAKE256 → 256 (output ≥ 512 bits) |
| HMAC | Table 3, the HMAC column: SHA-224, SHA-512/224, SHA3-224 → 192; the others "≥ 256", recorded as 256. HMAC is no stronger than its key |
| HKDF, PBKDF2 | Table 3, the key-derivation column: SHA-256, SHA-384, SHA-512 → "≥ 256", recorded as 256. For PBKDF2 this is an upper bound: the real strength is the password's (SP 800-132) |
| ML-KEM, ML-DSA, SLH-DSA | The reference of the NIST category the standard claims: category 1 or 2 → 128, 3 → 192, 5 → 256 |
| LMS, HSS, XMSS, XMSS^MT (families LMS and XMSS) | 8 × n, for the hash output size n in bytes: n = 32 → 256, n = 24 → 192 |

**NIST quantum security levels** are the security categories of the NIST PQC Call for Proposals
(*Submission Requirements and Evaluation Criteria*, §4.A.5): category 1 is as hard to break as
key search on AES-128, 2 as collision search on SHA-256, 3 as key search on AES-192, 4 as
collision search on SHA-384, 5 as key search on AES-256. `0` means no quantum security.

| Family | NIST level |
|--------|------------|
| RSA, DSA, DH, ECDSA, ECDH, Ed25519, X25519 | 0: Shor's algorithm breaks them |
| AES | The matching key-search category: AES-128 → 1, AES-192 → 3, AES-256 → 5 |
| ChaCha20-Poly1305 | 5: key search on a 256-bit key, as AES-256 |
| ML-KEM | FIPS 203 §8: ML-KEM-512 → 1, ML-KEM-768 → 3, ML-KEM-1024 → 5 |
| ML-DSA | FIPS 204 Table 1: ML-DSA-44 → 2, ML-DSA-65 → 3, ML-DSA-87 → 5 |
| SLH-DSA | FIPS 205 Table 2: the 128s and 128f sets → 1, 192s and 192f → 3, 256s and 256f → 5, for SHA2 and SHAKE alike |
| LMS, HSS, XMSS, XMSS^MT | SP 800-208 (§4 for LMS and HSS, §5 for XMSS and XMSS^MT) approves the parameter sets but assigns no category; rollcall rates them by n as FIPS 205 Table 2 rates SLH-DSA with the same n: n = 32 → 5, n = 24 → 3 |
| SHA2, SHA3, SHAKE | The hash rule below |
| HMAC, HKDF, PBKDF2 | The category of the underlying hash, by the hash rule |

**The hash rule.** NIST gives categories for two hashes only (category 2 is collision search on
SHA-256, category 4 on SHA-384). rollcall rates every hash, MAC and KDF the same way: halve the
digest length (the collision strength, as in Table 3) and take the category of the matching
NIST example, capped at 5:

| Collision strength (digest ÷ 2) | Category | Hashes |
|---------------------------------|----------|--------|
| ≥ 256 | 5 (key search on AES-256; categories stop at 5) | SHA-512, SHA3-512, SHAKE256 |
| 192 | 4 (collision search on SHA-384) | SHA-384, SHA3-384 |
| 128 | 2 (collision search on SHA-256) | SHA-256, SHA-512/256, SHA3-256, SHAKE128 |
| 112 | 0: below category 1 (key search on AES-128) | SHA-224, SHA-512/224, SHA3-224 |

An XOF is rated as a digest twice its collision strength (SHAKE128 as 256 bits, SHAKE256 as 512).
HMAC, HKDF and PBKDF2 inherit the category of their hash, so HMAC-SHA-256 is category 2 even
though HMAC does not rely on collision resistance. This is deliberately conservative: a
construction never reports more quantum security than the hash inside it.

A NIST level of `0` on a `grover-weakened` entry (SHA-224, SHA-512/224 and SHA3-224, and HMAC
over them) means *below category 1 under this collision-based rule*, not *broken*: unlike the
`0` of a `shor-broken` entry, no quantum attack breaks it. For a MAC or KDF, which does not rely
on collision resistance, the classical level (the HMAC and key-derivation columns of Table 3) is
the better indicator of its strength.

Each entry's `standards` field names the documents that specify it; the catalogue's list is
authoritative. Together they are FIPS 197 and SP 800-38A, C and D for AES; RFC 8439; FIPS 186-4
(DSA) and FIPS 186-5; RFC 8017; SP 800-56A Rev. 3, SP 800-56B Rev. 2 and SP 800-56C Rev. 2
(HKDF); RFC 7919; SP 800-186; RFC 8032; RFC 7748; FIPS 180-4; FIPS 202; FIPS 198-1 and RFC 2104
(HMAC); RFC 5869; RFC 8018 and SP 800-132; FIPS 203, 204 and 205; RFC 8554; RFC 8391;
SP 800-208.

## CycloneDX mapping

`Catalogue::lookup(name, id)` returns an entry whose `algorithm_properties()` is the
`algorithmProperties` block E1.1 writes:

| Catalogue | CycloneDX 1.6 |
|-----------|---------------|
| `primitive` | `algorithmProperties.primitive` |
| `id` | `algorithmProperties.parameterSetIdentifier` |
| `mode` | `algorithmProperties.mode` |
| `crypto_functions` | `algorithmProperties.cryptoFunctions` |
| `classical_security_level` | `algorithmProperties.classicalSecurityLevel` |
| `nist_quantum_security_level` | `algorithmProperties.nistQuantumSecurityLevel` (`0` is written) |
| `oid` | `cryptoProperties.oid` (`Entry::oid()`) |
| `curve` | `algorithmProperties.curve` (`Entry::curve()`; not modelled by rollcall-core yet) |
| `padding` | `algorithmProperties.padding` (`Entry::padding()`, `Padding::as_cyclonedx()`; not modelled by rollcall-core yet) |

`executionEnvironment` and `implementationPlatform` describe a build, not an algorithm; the
detector fills them in.

Conventions:

- `parameterSetIdentifier` is the key or digest size where there is one (`"128"`, `"256"`,
  `"512/224"`, `"3072"`), the standard's own set name where there is one (`"SHA2-128s"`,
  `"LMS_SHA256_M32_H10"`, `"XMSS-SHA2_10_256"`, `"XMSSMT-SHA2_20/2_256"`), the number in the
  standard's name for ML-KEM and ML-DSA (`"768"`, `"65"`), the curve for ECDSA and ECDH
  (`"secp256r1"`), the RFC 7919 group for DH (`"ffdhe2048"`), `"L-N"` for DSA (`"2048-224"`), and
  the hash for HMAC, HKDF and PBKDF2 (`"SHA-256"`, `"HMAC-SHA-256"`).
- Curves are named as the curve database CycloneDX recommends names them (`neuromancer.sk/std`):
  `secp256r1`, `secp384r1`, `secp521r1`, `Ed25519`, `Curve25519`.
- CycloneDX 1.6 has no padding word for PSS, so `pss` is written as `other`; `oaep` and
  `pkcs1v15` are written as themselves.
- An HSS signature uses LMS trees at every level; its parameter set is the LMS set used.
- ECDSA and ECDH have no `oid`: their OIDs name either the signature together with its hash
  (`ecdsa-with-SHA256`) or the key type and curve, never the algorithm and parameter set the
  catalogue keys on, so the curve is given in `curve` instead.

## Lookup API

```rust
use rollcall_assay::catalogue::Catalogue;

let catalogue = Catalogue::builtin()?;
let entry = catalogue.lookup("AES-GCM", "128")?;
let properties = entry.algorithm_properties(); // primitive ae, 128, gcm, NIST 1, ...
let oid = entry.oid();                          // Some("2.16.840.1.101.3.4.1.6")
```

The name is matched ignoring ASCII case, the parameter-set id exactly. An unknown algorithm is
`LookupError::UnknownAlgorithm`; a known algorithm with an unknown id is
`LookupError::UnknownParameterSet`, which lists the ids there are. There is never a default.

## Export contract and sync with cbom-infra

rollcall's `algorithms.yaml` is the single source of truth; cbom-infra (not built yet) will keep
a copy. The contract:

- **Same file format.** cbom-infra's copy is a `format: rollcall-algorithms/1` file that passes
  [`algorithms.schema.json`](../crates/rollcall-assay/db/algorithms.schema.json) and rollcall's
  lint. A new format version means a new `format` string.
- **Shared entries agree.** An entry is shared when its name (ignoring ASCII case) and
  parameter-set id are in both files. Every field of a shared entry must be equal, except the
  prose `source`, which is not normative.
- **One-sided entries are allowed.** An entry in only one file is reported but does not fail the
  check: cbom-infra may carry algorithms rollcall does not detect, and the reverse.

The check is `scripts/check-catalogue-sync.sh THEIRS [OURS]` (OURS defaults to rollcall's file).
It prints the shared count, the entries in one file only and every disagreement, such as
`AES-GCM/128 nist_quantum_security_level: ours 1, theirs 3`, and exits 0 when the shared entries
agree, 1 when they do not, 64 on a usage error, 65 when a file does not load and 66 when a file
cannot be read. Until cbom-infra exists it is tested against two hand-written stand-ins in
`crates/rollcall-assay/tests/data/cbom-infra-standin/`.

The process:

1. A change to a shared entry lands in rollcall first, in `algorithms.yaml`, with the sources
   that justify it, and ships in a rollcall release.
2. cbom-infra copies `algorithms.yaml` from that rollcall tag and records the tag and commit it
   copied.
3. cbom-infra's CI checks out rollcall at the recorded tag and runs
   `scripts/check-catalogue-sync.sh` against its copy; a disagreement fails its build. If
   cbom-infra needs a different value, it is changed in rollcall first.
