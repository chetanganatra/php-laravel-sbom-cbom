# PHP-Laravel-sbom-cbom

Two small, dependency-free PHP scripts that generate **CycloneDX v1.6** Bills of Materials for PHP / Laravel applications:

- **`generate-sbom.php`** — a **Software** Bill of Materials (SBOM) built from your `composer.lock` and `package-lock.json`.
- **`generate-cbom.php`** — a **Cryptographic** Bill of Materials (CBOM) built by statically scanning your source code for cryptographic usage (hash functions, encryption, signatures, random generation, key derivation — including Laravel's `Hash::`, `Crypt::` and `Str::` facades and libsodium).

Both scripts are single files with no dependencies beyond PHP itself — copy them into a project or run them from anywhere against a project path.

## Why

- **SBOMs** are increasingly required for supply-chain compliance (e.g. vulnerability management with OWASP Dependency-Track, regulatory requirements such as the EU Cyber Resilience Act).
- **CBOMs** give you an inventory of the cryptography your application actually uses — useful for crypto-agility planning, post-quantum migration assessments, and spotting deprecated algorithms (MD5, SHA-1, DES, mcrypt) in your codebase.

## Requirements

- PHP **8.0+** (CLI)
- No Composer packages, no extensions beyond the PHP defaults

## Usage

### SBOM

```console
$ php generate-sbom.php /path/to/laravel/app
SBOM generated: sbom.json (214 components)
```

Options:

| Option | Description |
|---|---|
| `-o, --output FILE` | Output file path (default: `sbom.json`) |
| `[path]` | Project directory to read lock files from (default: current directory) |

The script reads `composer.lock` (`packages` and `packages-dev`) and `package-lock.json` (lockfile versions 1, 2 and 3). Dev dependencies are included with `"scope": "optional"`; runtime dependencies get `"scope": "required"`. Components are de-duplicated by package URL (purl), and license information is carried over from the lock files when present.

Example component:

```json
{
    "type": "library",
    "name": "laravel/framework",
    "scope": "required",
    "bom-ref": "pkg:composer/laravel/framework@v11.9.2",
    "version": "v11.9.2",
    "purl": "pkg:composer/laravel/framework@v11.9.2",
    "licenses": [{ "license": { "name": "MIT" } }]
}
```

### CBOM

```console
$ php generate-cbom.php /path/to/laravel/app
Analyzing PHP files for cryptographic usage...
Scanned 182 PHP files; found 6 cryptographic components and 3 named algorithms.
CBOM generated successfully: cbom.json
```

Options:

| Option | Description |
|---|---|
| `-o, --output FILE` | Output file path (default: `cbom.json` / `cbom.txt`) |
| `-f, --format FORMAT` | `json` (CycloneDX v1.6) or `text` (human-readable report) |
| `[path]` | Project directory to scan (default: current directory) |

The scanner walks `app/`, `routes/`, `config/`, `database/`, `resources/`, `bootstrap/` and `src/` (or the whole project, excluding `vendor/` and `node_modules/`, if none of those exist) and detects:

- PHP crypto functions: `md5`, `sha1`, `hash`, `hash_hmac`, `password_hash`, `openssl_encrypt`, `openssl_sign`, `hash_pbkdf2`, `random_bytes`, `sodium_crypto_*`, and more
- Laravel facades: `Hash::make/check`, `Crypt::encrypt/decrypt`, `Str::random/uuid`
- Algorithm string literals: `'aes-256-gcm'`, `'sha256'`, `'des-ede3-cbc'`, … (case-insensitive)

Findings are emitted as CycloneDX **`cryptographic-asset`** components with `cryptoProperties` (primitive, crypto functions, cipher mode/key size where known) and `evidence.occurrences` pointing at the files where each item was found. Tool-specific details that have no standard CycloneDX field — category, security rating, occurrence counts — are carried in namespaced `properties` (`cbom:*`).

Example component:

```json
{
    "type": "cryptographic-asset",
    "bom-ref": "crypto/algorithm/aes-256-gcm",
    "name": "AES-256-GCM",
    "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
            "primitive": "ae",
            "parameterSetIdentifier": "256",
            "mode": "gcm",
            "executionEnvironment": "software-plain-ram",
            "cryptoFunctions": ["encrypt", "decrypt"]
        }
    },
    "evidence": { "occurrences": [{ "location": "config/app.php" }] },
    "properties": [
        { "name": "cbom:category", "value": "Cipher" },
        { "name": "cbom:security-rating", "value": "strong" },
        { "name": "cbom:occurrence-count", "value": "1" }
    ]
}
```

## Validating the output

Both outputs can be validated against the official CycloneDX 1.6 schema, e.g. with the [cyclonedx-cli](https://github.com/CycloneDX/cyclonedx-cli) tool:

```console
$ cyclonedx validate --input-file sbom.json --input-version v1_6
$ cyclonedx validate --input-file cbom.json --input-version v1_6
```

## Known limitations

Please read these before relying on the output:

- **The SBOM only reflects your lock files.** Packages installed by other means, platform extensions, or transitive dependencies not present in the lock files won't appear. Hashes, dependency graphs and package pedigree are not emitted.
- **The CBOM is regex-based static analysis, not a parser.** It can produce **false positives** (matches inside comments, doc-blocks, string literals, or unrelated methods that happen to be named e.g. `hash()`) and **false negatives** (dynamically built calls like `call_user_func('md5', …)`, crypto hidden inside `vendor/` packages — which are deliberately not scanned — or algorithms chosen at runtime from config).
- **Security ratings are informational.** "strong" / "weak" / "deprecated" labels reflect broad consensus about algorithms, not the correctness of your usage — strong algorithms used incorrectly (static IVs, ECB mode, hard-coded keys) are still insecure.
- **Neither tool is a security audit.** Use the output as an inventory and a starting point, not as evidence of security or compliance.

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied. The authors and contributors accept no liability for any claim, damages or other liability arising from its use, including decisions made on the basis of generated SBOM/CBOM documents. See [LICENSE](LICENSE) for the full terms.

## Contributing

Issues and pull requests are welcome. Useful contributions include: additional crypto function mappings (e.g. more libsodium, phpseclib, web-token detection), CycloneDX XML output, unit tests, and validation fixes against the official schema.

## License

[MIT](LICENSE) — © 2026 Chetan Ganatra and contributors.
