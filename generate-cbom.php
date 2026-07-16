<?php
/**
 * Laravel/PHP Cryptographic Bill of Materials (CBOM) Generator
 *
 * Statically scans PHP/Laravel source code for cryptographic usage and emits
 * a CycloneDX v1.6 CBOM (components of type "cryptographic-asset"), or a
 * human-readable text report. Requires only PHP itself — no dependencies.
 *
 * Usage:
 *   php generate-cbom.php [-o cbom.json] [-f json|text] [path/to/project]
 *
 * Options:
 *   -o, --output FILE     Output file path (default: cbom.json / cbom.txt)
 *   -f, --format FORMAT   Output format: json (CycloneDX) or text (default: json)
 *   -h, --help            Show help
 *
 * Part of the php-laravel-sbom-cbom project.
 * Copyright (c) 2026 Chetan Ganatra and contributors
 * Licensed under the MIT License. See the LICENSE file for details.
 *
 * DISCLAIMER: This tool is provided "as is", without warranty of any kind.
 * Detection is based on static analysis of the PHP token stream: comments and
 * docblocks are ignored, and function-call detection only matches real calls,
 * but it can still miss usage that is constructed dynamically (variable
 * functions, call_user_func, string concatenation) or lives in vendor
 * packages. The security ratings are informational only. This is not a
 * substitute for a professional cryptographic or security audit. See
 * README.md for details.
 */

class CryptographicBOMGenerator
{
    const TOOL_NAME = 'ais-php-laravel-cbom-generator';
    const TOOL_VERSION = '2.1.0';

    private $projectPath;
    private $usedCrypto = [];
    private $detectedAlgorithms = [];
    private $filesScanned = 0;

    /**
     * PHP crypto functions mapped to algorithm details and their CycloneDX
     * algorithmProperties (primitive, cryptoFunctions).
     */
    private $cryptoFunctions = [
        // Hash functions
        'md5' => ['algorithm' => 'MD5', 'category' => 'Hash', 'security' => 'deprecated', 'primitive' => 'hash', 'cryptoFunctions' => ['digest']],
        'sha1' => ['algorithm' => 'SHA-1', 'category' => 'Hash', 'security' => 'weak', 'primitive' => 'hash', 'cryptoFunctions' => ['digest']],
        'hash' => ['algorithm' => 'hash() [algorithm passed as argument]', 'category' => 'Hash', 'security' => 'depends', 'primitive' => 'hash', 'cryptoFunctions' => ['digest']],
        'hash_hmac' => ['algorithm' => 'HMAC', 'category' => 'MAC', 'security' => 'strong', 'primitive' => 'mac', 'cryptoFunctions' => ['tag']],
        'password_hash' => ['algorithm' => 'bcrypt/argon2', 'category' => 'Password Hashing', 'security' => 'strong', 'primitive' => 'kdf', 'cryptoFunctions' => ['keyderive']],
        'password_verify' => ['algorithm' => 'bcrypt/argon2', 'category' => 'Password Hashing', 'security' => 'strong', 'primitive' => 'kdf', 'cryptoFunctions' => ['keyderive', 'verify']],

        // Encryption
        'openssl_encrypt' => ['algorithm' => 'OpenSSL cipher [from arguments]', 'category' => 'Encryption', 'security' => 'depends', 'primitive' => 'block-cipher', 'cryptoFunctions' => ['encrypt']],
        'openssl_decrypt' => ['algorithm' => 'OpenSSL cipher [from arguments]', 'category' => 'Encryption', 'security' => 'depends', 'primitive' => 'block-cipher', 'cryptoFunctions' => ['decrypt']],
        'mcrypt_encrypt' => ['algorithm' => 'mcrypt [removed in PHP 7.2]', 'category' => 'Encryption', 'security' => 'deprecated', 'primitive' => 'block-cipher', 'cryptoFunctions' => ['encrypt']],
        'mcrypt_decrypt' => ['algorithm' => 'mcrypt [removed in PHP 7.2]', 'category' => 'Encryption', 'security' => 'deprecated', 'primitive' => 'block-cipher', 'cryptoFunctions' => ['decrypt']],

        // Sodium (libsodium)
        'sodium_crypto_secretbox' => ['algorithm' => 'XSalsa20-Poly1305', 'category' => 'Encryption', 'security' => 'strong', 'library' => 'libsodium', 'primitive' => 'ae', 'cryptoFunctions' => ['encrypt']],
        'sodium_crypto_secretbox_open' => ['algorithm' => 'XSalsa20-Poly1305', 'category' => 'Encryption', 'security' => 'strong', 'library' => 'libsodium', 'primitive' => 'ae', 'cryptoFunctions' => ['decrypt']],
        'sodium_crypto_box' => ['algorithm' => 'X25519-XSalsa20-Poly1305', 'category' => 'Encryption', 'security' => 'strong', 'library' => 'libsodium', 'primitive' => 'ae', 'cryptoFunctions' => ['encrypt']],
        'sodium_crypto_box_open' => ['algorithm' => 'X25519-XSalsa20-Poly1305', 'category' => 'Encryption', 'security' => 'strong', 'library' => 'libsodium', 'primitive' => 'ae', 'cryptoFunctions' => ['decrypt']],
        'sodium_crypto_sign' => ['algorithm' => 'Ed25519', 'category' => 'Digital Signature', 'security' => 'strong', 'library' => 'libsodium', 'primitive' => 'signature', 'cryptoFunctions' => ['sign']],
        'sodium_crypto_sign_detached' => ['algorithm' => 'Ed25519', 'category' => 'Digital Signature', 'security' => 'strong', 'library' => 'libsodium', 'primitive' => 'signature', 'cryptoFunctions' => ['sign']],
        'sodium_crypto_sign_verify_detached' => ['algorithm' => 'Ed25519', 'category' => 'Digital Signature', 'security' => 'strong', 'library' => 'libsodium', 'primitive' => 'signature', 'cryptoFunctions' => ['verify']],
        'sodium_crypto_generichash' => ['algorithm' => 'BLAKE2b', 'category' => 'Hash', 'security' => 'strong', 'library' => 'libsodium', 'primitive' => 'hash', 'cryptoFunctions' => ['digest']],
        'sodium_crypto_pwhash' => ['algorithm' => 'Argon2id', 'category' => 'Password Hashing', 'security' => 'strong', 'library' => 'libsodium', 'primitive' => 'kdf', 'cryptoFunctions' => ['keyderive']],

        // Random generation
        'random_bytes' => ['algorithm' => 'CSPRNG', 'category' => 'Random Generation', 'security' => 'strong', 'primitive' => 'drbg', 'cryptoFunctions' => ['generate']],
        'random_int' => ['algorithm' => 'CSPRNG', 'category' => 'Random Generation', 'security' => 'strong', 'primitive' => 'drbg', 'cryptoFunctions' => ['generate']],
        'openssl_random_pseudo_bytes' => ['algorithm' => 'OpenSSL PRNG', 'category' => 'Random Generation', 'security' => 'strong', 'primitive' => 'drbg', 'cryptoFunctions' => ['generate']],
        'mt_rand' => ['algorithm' => 'Mersenne Twister', 'category' => 'Random Generation', 'security' => 'weak', 'primitive' => 'drbg', 'cryptoFunctions' => ['generate']],
        'rand' => ['algorithm' => 'OS-dependent PRNG', 'category' => 'Random Generation', 'security' => 'weak', 'primitive' => 'drbg', 'cryptoFunctions' => ['generate']],

        // Signatures
        'openssl_sign' => ['algorithm' => 'RSA/ECDSA', 'category' => 'Digital Signature', 'security' => 'strong', 'primitive' => 'signature', 'cryptoFunctions' => ['sign']],
        'openssl_verify' => ['algorithm' => 'RSA/ECDSA', 'category' => 'Digital Signature', 'security' => 'strong', 'primitive' => 'signature', 'cryptoFunctions' => ['verify']],

        // Key derivation
        'hash_pbkdf2' => ['algorithm' => 'PBKDF2', 'category' => 'Key Derivation', 'security' => 'strong', 'primitive' => 'kdf', 'cryptoFunctions' => ['keyderive']],
    ];

    /**
     * Laravel facade crypto usage patterns.
     */
    private $laravelCryptoPatterns = [
        'Hash::make' => ['algorithm' => 'bcrypt/argon2', 'category' => 'Password Hashing', 'security' => 'strong', 'library' => 'Laravel', 'primitive' => 'kdf', 'cryptoFunctions' => ['keyderive']],
        'Hash::check' => ['algorithm' => 'bcrypt/argon2', 'category' => 'Password Hashing', 'security' => 'strong', 'library' => 'Laravel', 'primitive' => 'kdf', 'cryptoFunctions' => ['keyderive', 'verify']],
        'Crypt::encrypt' => ['algorithm' => 'AES-CBC/AES-GCM [per app config]', 'category' => 'Encryption', 'security' => 'strong', 'library' => 'Laravel', 'primitive' => 'ae', 'cryptoFunctions' => ['encrypt']],
        'Crypt::decrypt' => ['algorithm' => 'AES-CBC/AES-GCM [per app config]', 'category' => 'Encryption', 'security' => 'strong', 'library' => 'Laravel', 'primitive' => 'ae', 'cryptoFunctions' => ['decrypt']],
        'Crypt::encryptString' => ['algorithm' => 'AES-CBC/AES-GCM [per app config]', 'category' => 'Encryption', 'security' => 'strong', 'library' => 'Laravel', 'primitive' => 'ae', 'cryptoFunctions' => ['encrypt']],
        'Crypt::decryptString' => ['algorithm' => 'AES-CBC/AES-GCM [per app config]', 'category' => 'Encryption', 'security' => 'strong', 'library' => 'Laravel', 'primitive' => 'ae', 'cryptoFunctions' => ['decrypt']],
        'Str::random' => ['algorithm' => 'CSPRNG', 'category' => 'Random Generation', 'security' => 'strong', 'library' => 'Laravel', 'primitive' => 'drbg', 'cryptoFunctions' => ['generate']],
        'Str::uuid' => ['algorithm' => 'UUID v4 (CSPRNG)', 'category' => 'Random Generation', 'security' => 'strong', 'library' => 'Laravel', 'primitive' => 'drbg', 'cryptoFunctions' => ['generate']],
    ];

    /**
     * Quoted hash-algorithm names (as passed to hash(), hash_hmac(), etc.).
     */
    private $hashAlgorithmStrings = [
        'md5' => ['name' => 'MD5', 'security' => 'deprecated'],
        'sha1' => ['name' => 'SHA-1', 'security' => 'weak'],
        'sha256' => ['name' => 'SHA-256', 'security' => 'strong'],
        'sha384' => ['name' => 'SHA-384', 'security' => 'strong'],
        'sha512' => ['name' => 'SHA-512', 'security' => 'strong'],
        'sha3-256' => ['name' => 'SHA3-256', 'security' => 'strong'],
        'sha3-512' => ['name' => 'SHA3-512', 'security' => 'strong'],
        'blake2b' => ['name' => 'BLAKE2b', 'security' => 'strong'],
        'blake2s' => ['name' => 'BLAKE2s', 'security' => 'strong'],
    ];

    public function __construct($projectPath = '.')
    {
        $this->projectPath = rtrim($projectPath, '/\\');
        if ($this->projectPath === '') {
            $this->projectPath = '.';
        }
    }

    /**
     * Run the analysis over the project's source directories.
     */
    public function analyze()
    {
        echo "Analyzing PHP files for cryptographic usage...\n";

        $directories = ['app', 'routes', 'config', 'database', 'resources', 'bootstrap', 'src'];
        $scannedAny = false;

        foreach ($directories as $dir) {
            $fullPath = $this->projectPath . '/' . $dir;
            if (is_dir($fullPath)) {
                $this->scanDirectory($fullPath);
                $scannedAny = true;
            }
        }

        // Not a Laravel-style layout: scan the whole project, skipping
        // dependency and VCS directories.
        if (!$scannedAny) {
            $this->scanDirectory($this->projectPath, ['vendor', 'node_modules', 'storage', '.git']);
        }

        echo "Scanned {$this->filesScanned} PHP files; found "
            . count($this->usedCrypto) . ' cryptographic components and '
            . count($this->detectedAlgorithms) . " named algorithms.\n";

        return $this;
    }

    /**
     * Recursively scan a directory for PHP files.
     */
    private function scanDirectory($dir, array $excludeDirs = [])
    {
        try {
            $inner = new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS);
            $filtered = new RecursiveCallbackFilterIterator($inner, function ($current) use ($excludeDirs) {
                return !($current->isDir() && in_array($current->getFilename(), $excludeDirs, true));
            });
            $files = new RecursiveIteratorIterator($filtered);
        } catch (UnexpectedValueException $e) {
            fwrite(STDERR, "Warning: cannot read directory {$dir}: {$e->getMessage()}\n");
            return;
        }

        foreach ($files as $file) {
            if ($file->isFile() && strtolower($file->getExtension()) === 'php') {
                $this->parsePhpFile($file->getPathname());
            }
        }
    }

    /**
     * Parse a single PHP file for cryptographic usage.
     */
    private function parsePhpFile($filePath)
    {
        $content = @file_get_contents($filePath);
        if ($content === false) {
            fwrite(STDERR, "Warning: cannot read file {$filePath}\n");
            return;
        }

        $location = $this->relativePath($filePath);

        try {
            $tokens = token_get_all($content, TOKEN_PARSE);
        } catch (Throwable $e) {
            fwrite(STDERR, "Warning: skipping {$location}: cannot tokenize ({$e->getMessage()})\n");
            return;
        }

        $this->filesScanned++;
        $this->scanTokens($tokens, $location);
    }

    /**
     * Walk the token stream of one file. Comments and docblocks are ignored
     * entirely; function calls are matched only as real T_STRING calls (bare
     * or fully qualified, never ->/:: methods); facade usage is matched as
     * Class::method( via T_DOUBLE_COLON; algorithm names are matched only
     * against whole string-literal tokens.
     */
    private function scanTokens(array $tokens, $location)
    {
        $count = count($tokens);

        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];
            if (!is_array($token)) {
                continue;
            }

            list($id, $text, $line) = $token;

            if ($id === T_COMMENT || $id === T_DOC_COMMENT) {
                continue;
            }

            // Algorithm names live inside string literals ('sha256', 'aes-256-cbc').
            if ($id === T_CONSTANT_ENCAPSED_STRING) {
                $this->matchAlgorithmString(substr($text, 1, -1), $location, $line);
                continue;
            }

            $isName = $id === T_STRING
                || (defined('T_NAME_FULLY_QUALIFIED') && $id === T_NAME_FULLY_QUALIFIED)
                || (defined('T_NAME_QUALIFIED') && $id === T_NAME_QUALIFIED);
            if (!$isName) {
                continue;
            }

            $nextIdx = $this->significantIndex($tokens, $i, 1);
            if ($nextIdx === null) {
                continue;
            }

            // Laravel facade static call: Class::method( — also matches
            // \Hash::make( and Illuminate\...\Hash::make( by class basename.
            if (is_array($tokens[$nextIdx]) && $tokens[$nextIdx][0] === T_DOUBLE_COLON) {
                $methodIdx = $this->significantIndex($tokens, $nextIdx, 1);
                if ($methodIdx !== null && is_array($tokens[$methodIdx]) && $tokens[$methodIdx][0] === T_STRING) {
                    $parenIdx = $this->significantIndex($tokens, $methodIdx, 1);
                    if ($parenIdx !== null && $tokens[$parenIdx] === '(') {
                        $pos = strrpos($text, '\\');
                        $class = $pos === false ? $text : substr($text, $pos + 1);
                        $key = $class . '::' . $tokens[$methodIdx][1];
                        if (isset($this->laravelCryptoPatterns[$key])) {
                            $this->recordCrypto($key, $this->laravelCryptoPatterns[$key], $location, $line);
                        }
                    }
                }
                continue;
            }

            // Bare (or fully qualified) function call: name must be directly
            // followed by "(". Namespaced functions (Foo\hash) are a different
            // function and are not counted.
            if ($tokens[$nextIdx] !== '(') {
                continue;
            }

            $name = strtolower(ltrim($text, '\\'));
            if (strpos($name, '\\') !== false || !isset($this->cryptoFunctions[$name])) {
                continue;
            }

            $prevIdx = $this->significantIndex($tokens, $i, -1);
            if ($prevIdx !== null) {
                $prev = $tokens[$prevIdx];
                $prevId = is_array($prev) ? $prev[0] : null;
                if ($prevId === T_OBJECT_OPERATOR
                    || $prevId === T_DOUBLE_COLON
                    || $prevId === T_FUNCTION
                    || $prevId === T_NEW
                    || (defined('T_NULLSAFE_OBJECT_OPERATOR') && $prevId === T_NULLSAFE_OBJECT_OPERATOR)) {
                    continue;
                }
            }

            $this->recordCrypto($name . '()', $this->cryptoFunctions[$name], $location, $line);
        }
    }

    /**
     * Index of the nearest non-whitespace, non-comment token from $index in
     * $direction (1 or -1), or null if none.
     */
    private function significantIndex(array $tokens, $index, $direction)
    {
        $count = count($tokens);

        for ($i = $index + $direction; $i >= 0 && $i < $count; $i += $direction) {
            $token = $tokens[$i];
            if (is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            return $i;
        }

        return null;
    }

    private function relativePath($filePath)
    {
        $path = $filePath;
        $prefix = $this->projectPath . DIRECTORY_SEPARATOR;
        if (strpos($path, $prefix) === 0) {
            $path = substr($path, strlen($prefix));
        }

        return str_replace('\\', '/', $path);
    }

    /**
     * Match one string-literal value against the known cipher specifications
     * ('aes-256-gcm', 'des-ede3-cbc', ...) and hash-algorithm names. The whole
     * literal must be the algorithm name, matching case-insensitively.
     */
    private function matchAlgorithmString($value, $location, $line)
    {
        if (preg_match('/^aes-(?:128|192|256)-(?:cbc|gcm|ecb|ctr|cfb|ofb)$/i', $value)) {
            $cipher = strtoupper($value);
            $mode = substr($cipher, strrpos($cipher, '-') + 1);
            $security = $mode === 'ECB' ? 'weak' : ($mode === 'GCM' ? 'strong' : 'standard');
            $this->recordAlgorithm($cipher, 'Cipher', $security, $location, $line);
            return;
        }

        // DES / 3DES (deprecated)
        if (preg_match('/^(?:des-ede3(?:-cbc|-ecb)?|des-(?:cbc|ecb))$/i', $value)) {
            $this->recordAlgorithm(strtoupper($value), 'Cipher', 'deprecated', $location, $line);
            return;
        }

        $lower = strtolower($value);
        if (isset($this->hashAlgorithmStrings[$lower])) {
            $details = $this->hashAlgorithmStrings[$lower];
            $this->recordAlgorithm($details['name'], 'Hash Algorithm', $details['security'], $location, $line);
        }
    }

    /**
     * Record one detected usage of a crypto function or facade call.
     */
    private function recordCrypto($name, $details, $location, $line)
    {
        $key = $details['algorithm'] . ' (' . $details['category'] . ')';

        if (!isset($this->usedCrypto[$key])) {
            $this->usedCrypto[$key] = [
                'functions' => [],
                'algorithm' => $details['algorithm'],
                'category' => $details['category'],
                'security' => isset($details['security']) ? $details['security'] : 'standard',
                'library' => isset($details['library']) ? $details['library'] : 'PHP Built-in',
                'primitive' => $details['primitive'],
                'cryptoFunctions' => [],
                'occurrences' => 0,
                'sites' => [],
            ];
        }

        $entry = &$this->usedCrypto[$key];
        $entry['functions'][$name] = true;
        $entry['cryptoFunctions'] = array_values(array_unique(array_merge($entry['cryptoFunctions'], $details['cryptoFunctions'])));
        $entry['occurrences']++;
        $entry['sites'][$location . ':' . $line] = ['location' => $location, 'line' => $line];
        unset($entry);
    }

    /**
     * Record one detected occurrence of a named algorithm string literal.
     */
    private function recordAlgorithm($name, $type, $security, $location, $line)
    {
        if (!isset($this->detectedAlgorithms[$name])) {
            $this->detectedAlgorithms[$name] = [
                'type' => $type,
                'security' => $security,
                'count' => 0,
                'sites' => [],
            ];
        }

        $entry = &$this->detectedAlgorithms[$name];
        $entry['count']++;
        $entry['sites'][$location . ':' . $line] = ['location' => $location, 'line' => $line];
        unset($entry);
    }

    /**
     * CycloneDX algorithmProperties for a string-detected algorithm.
     */
    private function algorithmProperties($name, $type)
    {
        if ($type === 'Cipher') {
            if (preg_match('/^AES-(\d+)-([A-Z]+)$/', $name, $m)) {
                $mode = strtolower($m[2]);

                return [
                    'primitive' => $mode === 'gcm' ? 'ae' : 'block-cipher',
                    'parameterSetIdentifier' => $m[1],
                    'mode' => in_array($mode, ['cbc', 'ecb', 'ccm', 'gcm', 'cfb', 'ofb', 'ctr'], true) ? $mode : 'other',
                    'executionEnvironment' => 'software-plain-ram',
                    'cryptoFunctions' => ['encrypt', 'decrypt'],
                ];
            }

            return [
                'primitive' => 'block-cipher',
                'executionEnvironment' => 'software-plain-ram',
                'cryptoFunctions' => ['encrypt', 'decrypt'],
            ];
        }

        return [
            'primitive' => 'hash',
            'executionEnvironment' => 'software-plain-ram',
            'cryptoFunctions' => ['digest'],
        ];
    }

    private function slugRef($prefix, $value)
    {
        $slug = strtolower(preg_replace('/[^a-zA-Z0-9]+/', '-', $value));

        return 'crypto/' . $prefix . '/' . trim($slug, '-');
    }

    private function occurrenceEvidence(array $sites)
    {
        $occurrences = [];
        foreach ($sites as $site) {
            $occurrences[] = ['location' => $site['location'], 'line' => $site['line']];
        }

        return ['occurrences' => $occurrences];
    }

    /**
     * Unique file paths from a list of detection sites.
     */
    private function siteFiles(array $sites)
    {
        $files = [];
        foreach ($sites as $site) {
            $files[$site['location']] = true;
        }

        return array_keys($files);
    }

    /**
     * RFC 4122 version 4 UUID, as required by the CycloneDX serialNumber schema.
     */
    private function uuidv4()
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }

    /**
     * Generate the CBOM as a CycloneDX v1.6 document (array, ready for
     * json_encode). Cryptographic usage is expressed as components of type
     * "cryptographic-asset"; non-standard details (category, security rating,
     * occurrence counts) are carried in namespaced properties.
     */
    public function toCycloneDX()
    {
        $components = [];

        foreach ($this->usedCrypto as $key => $details) {
            $components[] = [
                'type' => 'cryptographic-asset',
                'bom-ref' => $this->slugRef('function', $key),
                'name' => $details['algorithm'],
                'description' => $details['category'] . ' — detected via ' . implode(', ', array_keys($details['functions'])),
                'cryptoProperties' => [
                    'assetType' => 'algorithm',
                    'algorithmProperties' => [
                        'primitive' => $details['primitive'],
                        'executionEnvironment' => 'software-plain-ram',
                        'cryptoFunctions' => $details['cryptoFunctions'],
                    ],
                ],
                'evidence' => $this->occurrenceEvidence($details['sites']),
                'properties' => [
                    ['name' => 'cbom:category', 'value' => $details['category']],
                    ['name' => 'cbom:security-rating', 'value' => $details['security']],
                    ['name' => 'cbom:library', 'value' => $details['library']],
                    ['name' => 'cbom:occurrence-count', 'value' => (string) $details['occurrences']],
                ],
            ];
        }

        foreach ($this->detectedAlgorithms as $name => $details) {
            $components[] = [
                'type' => 'cryptographic-asset',
                'bom-ref' => $this->slugRef('algorithm', $name),
                'name' => $name,
                'description' => $details['type'] . ' — detected as a string literal',
                'cryptoProperties' => [
                    'assetType' => 'algorithm',
                    'algorithmProperties' => $this->algorithmProperties($name, $details['type']),
                ],
                'evidence' => $this->occurrenceEvidence($details['sites']),
                'properties' => [
                    ['name' => 'cbom:category', 'value' => $details['type']],
                    ['name' => 'cbom:security-rating', 'value' => $details['security']],
                    ['name' => 'cbom:occurrence-count', 'value' => (string) $details['count']],
                ],
            ];
        }

        return [
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'serialNumber' => 'urn:uuid:' . $this->uuidv4(),
            'version' => 1,
            'metadata' => [
                'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
                'tools' => [
                    'components' => [
                        [
                            'type' => 'application',
                            'name' => self::TOOL_NAME,
                            'version' => self::TOOL_VERSION,
                        ],
                    ],
                ],
                'component' => [
                    'type' => 'application',
                    'bom-ref' => 'root-application',
                    'name' => basename(realpath($this->projectPath) ?: $this->projectPath),
                ],
                'properties' => [
                    ['name' => 'cbom:files-scanned', 'value' => (string) $this->filesScanned],
                    ['name' => 'cbom:deprecated-usage', 'value' => (string) $this->countBySecurity('deprecated')],
                    ['name' => 'cbom:weak-usage', 'value' => (string) $this->countBySecurity('weak')],
                    ['name' => 'cbom:strong-usage', 'value' => (string) $this->countBySecurity('strong')],
                ],
            ],
            'components' => $components,
        ];
    }

    /**
     * Generate the CBOM as a human-readable text report.
     */
    public function toText()
    {
        $output = "=== CRYPTOGRAPHIC BILL OF MATERIALS (CBOM) ===\n";
        $output .= 'Project: ' . basename(realpath($this->projectPath) ?: $this->projectPath) . "\n";
        $output .= 'Generated: ' . gmdate('Y-m-d H:i:s') . " UTC\n";
        $output .= str_repeat('=', 50) . "\n\n";

        $output .= "CRYPTOGRAPHIC COMPONENTS\n";
        $output .= str_repeat('-', 50) . "\n";

        if (empty($this->usedCrypto)) {
            $output .= "No cryptographic usage detected.\n";
        } else {
            foreach ($this->usedCrypto as $comp => $details) {
                $output .= "\n[{$details['category']}] {$comp}\n";
                $output .= '  Detected via: ' . implode(', ', array_keys($details['functions'])) . "\n";
                $output .= "  Library: {$details['library']}\n";
                $output .= "  Security: {$details['security']}\n";
                $output .= "  Occurrences: {$details['occurrences']}\n";
                $output .= '  Files: ' . implode(', ', $this->siteFiles($details['sites'])) . "\n";
            }
        }

        $output .= "\n\nDETECTED ALGORITHMS\n";
        $output .= str_repeat('-', 50) . "\n";

        if (empty($this->detectedAlgorithms)) {
            $output .= "No specific algorithms detected.\n";
        } else {
            foreach ($this->detectedAlgorithms as $algo => $details) {
                $output .= "\n{$algo} ({$details['type']})\n";
                $output .= "  Security: {$details['security']}\n";
                $output .= "  Usage Count: {$details['count']}\n";
                $output .= '  Files: ' . implode(', ', $this->siteFiles($details['sites'])) . "\n";
            }
        }

        $output .= "\n\nSUMMARY\n";
        $output .= str_repeat('-', 50) . "\n";
        $output .= 'Files Scanned: ' . $this->filesScanned . "\n";
        $output .= 'Total Cryptographic Components: ' . count($this->usedCrypto) . "\n";
        $output .= 'Total Detected Algorithms: ' . count($this->detectedAlgorithms) . "\n";
        $output .= 'Deprecated Usage: ' . $this->countBySecurity('deprecated') . "\n";
        $output .= 'Weak Crypto Usage: ' . $this->countBySecurity('weak') . "\n";
        $output .= 'Strong Crypto Usage: ' . $this->countBySecurity('strong') . "\n";

        return $output;
    }

    private function countBySecurity($rating)
    {
        $total = 0;

        foreach ($this->usedCrypto as $item) {
            if ($item['security'] === $rating) {
                $total += $item['occurrences'];
            }
        }

        foreach ($this->detectedAlgorithms as $item) {
            if ($item['security'] === $rating) {
                $total += $item['count'];
            }
        }

        return $total;
    }
}

// CLI Interface
if (PHP_SAPI === 'cli') {
    $args = ['output' => null, 'format' => 'json', 'path' => '.', 'help' => false];

    for ($i = 1, $n = count($argv); $i < $n; $i++) {
        $arg = $argv[$i];

        if ($arg === '-h' || $arg === '--help') {
            $args['help'] = true;
        } elseif ($arg === '-o' || $arg === '--output') {
            $args['output'] = isset($argv[++$i]) ? $argv[$i] : null;
        } elseif (strpos($arg, '--output=') === 0) {
            $args['output'] = substr($arg, strlen('--output='));
        } elseif ($arg === '-f' || $arg === '--format') {
            $args['format'] = isset($argv[++$i]) ? $argv[$i] : 'json';
        } elseif (strpos($arg, '--format=') === 0) {
            $args['format'] = substr($arg, strlen('--format='));
        } elseif ($arg !== '' && $arg[0] !== '-') {
            $args['path'] = $arg;
        } else {
            fwrite(STDERR, "Unknown option: {$arg}\n");
            exit(1);
        }
    }

    if ($args['help']) {
        echo "Laravel/PHP CBOM Generator (CycloneDX v1.6)\n\n";
        echo "Usage: php generate-cbom.php [OPTIONS] [path/to/project]\n\n";
        echo "Options:\n";
        echo "  -o, --output FILE     Output file path (default: cbom.json / cbom.txt)\n";
        echo "  -f, --format FORMAT   Output format: json (CycloneDX) or text (default: json)\n";
        echo "  -h, --help            Show this help message\n\n";
        echo "Examples:\n";
        echo "  php generate-cbom.php /path/to/laravel/app\n";
        echo "  php generate-cbom.php -f text -o cbom.txt .\n";
        exit(0);
    }

    if (!is_dir($args['path'])) {
        fwrite(STDERR, "Error: not a directory: {$args['path']}\n");
        exit(1);
    }

    if (!in_array($args['format'], ['json', 'text'], true)) {
        fwrite(STDERR, "Error: unsupported format '{$args['format']}' (supported: json, text)\n");
        exit(1);
    }

    if ($args['output'] === null) {
        $args['output'] = $args['format'] === 'json' ? 'cbom.json' : 'cbom.txt';
    }

    $generator = new CryptographicBOMGenerator($args['path']);
    $generator->analyze();

    if ($args['format'] === 'json') {
        $result = json_encode($generator->toCycloneDX(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    } else {
        $result = $generator->toText();
    }

    file_put_contents($args['output'], $result);
    echo "CBOM generated successfully: {$args['output']}\n";
}
