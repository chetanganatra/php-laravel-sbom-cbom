<?php
/**
 * Laravel/PHP Software Bill of Materials (SBOM) Generator
 *
 * Generates a CycloneDX v1.6 SBOM (JSON) from a project's composer.lock and
 * package-lock.json files. Requires only PHP itself — no dependencies.
 *
 * Usage:
 *   php generate-sbom.php [-o sbom.json] [path/to/project]
 *
 * Options:
 *   -o, --output FILE   Output file path (default: sbom.json)
 *   -h, --help          Show help
 *
 * Part of the php-laravel-sbom-cbom project.
 * Copyright (c) 2026 Chetan Ganatra and contributors
 * Licensed under the MIT License. See the LICENSE file for details.
 *
 * DISCLAIMER: This tool is provided "as is", without warranty of any kind.
 * The generated SBOM reflects only what is recorded in the project's lock
 * files and may be incomplete or inaccurate. It is not a substitute for a
 * professional security audit. See README.md for known limitations.
 */

const SBOM_TOOL_NAME = 'php-laravel-sbom-generator';
const SBOM_TOOL_VERSION = '2.0.0';

function readJsonFile(string $path): ?array
{
    if (!is_file($path)) {
        return null;
    }

    $data = json_decode((string) file_get_contents($path), true);

    return is_array($data) ? $data : null;
}

/**
 * RFC 4122 version 4 UUID, as required by the CycloneDX serialNumber schema.
 */
function uuidv4(): string
{
    $bytes = random_bytes(16);
    $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
    $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);

    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
}

/**
 * Percent-encode a package name for use in a purl, preserving the
 * namespace/name separator, e.g. "@vue/compiler-core" => "%40vue/compiler-core".
 */
function purlEncode(string $name): string
{
    return implode('/', array_map('rawurlencode', explode('/', $name)));
}

/**
 * @param string[] $licenses License strings as found in the lock file
 */
function makeComponent(string $ecosystem, string $name, ?string $version, string $scope, array $licenses = []): array
{
    $component = [
        'type' => 'library',
        'name' => $name,
        'scope' => $scope,
    ];

    if ($version !== null && $version !== '') {
        $purl = 'pkg:' . $ecosystem . '/' . purlEncode($name) . '@' . rawurlencode($version);
        $component['bom-ref'] = $purl;
        $component['version'] = $version;
        $component['purl'] = $purl;
    } else {
        // Version unknown (e.g. workspace entries): still emit the component,
        // but without a versioned purl.
        $component['bom-ref'] = 'pkg:' . $ecosystem . '/' . purlEncode($name);
    }

    if ($licenses !== []) {
        // "name" is used instead of "id" so that non-SPDX strings found in
        // lock files never invalidate the document against the schema.
        $component['licenses'] = array_map(
            fn (string $license): array => ['license' => ['name' => $license]],
            $licenses
        );
    }

    return $component;
}

function composerComponents(array $composerLock): array
{
    $components = [];
    $sections = ['packages' => 'required', 'packages-dev' => 'optional'];

    foreach ($sections as $section => $scope) {
        foreach ($composerLock[$section] ?? [] as $pkg) {
            if (!isset($pkg['name'])) {
                continue;
            }

            $licenses = array_values(array_filter((array) ($pkg['license'] ?? []), 'is_string'));
            $components[] = makeComponent('composer', $pkg['name'], $pkg['version'] ?? null, $scope, $licenses);
        }
    }

    return $components;
}

function npmComponents(array $packageLock): array
{
    $components = [];

    if (isset($packageLock['packages'])) {
        // lockfileVersion 2/3: entries are keyed by their install path,
        // e.g. "node_modules/lodash" or "node_modules/a/node_modules/b".
        foreach ($packageLock['packages'] as $path => $pkg) {
            if ($path === '' || !empty($pkg['link'])) {
                continue; // the root project itself, or a symlinked workspace
            }

            $name = $pkg['name'] ?? npmNameFromPath((string) $path);
            if ($name === '') {
                continue;
            }

            $scope = !empty($pkg['dev']) ? 'optional' : 'required';
            $license = isset($pkg['license']) && is_string($pkg['license']) ? [$pkg['license']] : [];
            $components[] = makeComponent('npm', $name, $pkg['version'] ?? null, $scope, $license);
        }
    } elseif (isset($packageLock['dependencies'])) {
        // lockfileVersion 1: nested dependency tree.
        collectNpmV1($packageLock['dependencies'], $components);
    }

    return $components;
}

function npmNameFromPath(string $path): string
{
    $marker = 'node_modules/';
    $pos = strrpos($path, $marker);

    return $pos === false ? $path : substr($path, $pos + strlen($marker));
}

function collectNpmV1(array $dependencies, array &$components): void
{
    foreach ($dependencies as $name => $pkg) {
        if (!is_array($pkg)) {
            continue;
        }

        $scope = !empty($pkg['dev']) ? 'optional' : 'required';
        $components[] = makeComponent('npm', (string) $name, $pkg['version'] ?? null, $scope);

        if (isset($pkg['dependencies']) && is_array($pkg['dependencies'])) {
            collectNpmV1($pkg['dependencies'], $components);
        }
    }
}

/**
 * The same package can appear at multiple node_modules paths; keep one
 * component per purl, preferring "required" scope over "optional".
 */
function dedupeComponents(array $components): array
{
    $unique = [];

    foreach ($components as $component) {
        $ref = $component['bom-ref'];

        if (!isset($unique[$ref]) || ($unique[$ref]['scope'] === 'optional' && $component['scope'] === 'required')) {
            $unique[$ref] = $component;
        }
    }

    return array_values($unique);
}

function parseArgs(array $argv): array
{
    $args = ['output' => 'sbom.json', 'path' => '.', 'help' => false];

    for ($i = 1, $n = count($argv); $i < $n; $i++) {
        $arg = $argv[$i];

        if ($arg === '-h' || $arg === '--help') {
            $args['help'] = true;
        } elseif ($arg === '-o' || $arg === '--output') {
            $args['output'] = $argv[++$i] ?? $args['output'];
        } elseif (str_starts_with($arg, '--output=')) {
            $args['output'] = substr($arg, strlen('--output='));
        } elseif ($arg !== '' && $arg[0] !== '-') {
            $args['path'] = $arg;
        } else {
            fwrite(STDERR, "Unknown option: {$arg}\n");
            exit(1);
        }
    }

    return $args;
}

if (PHP_SAPI !== 'cli') {
    exit(1);
}

$args = parseArgs($argv);

if ($args['help']) {
    echo "Laravel/PHP SBOM Generator (CycloneDX v1.6)\n\n";
    echo "Usage: php generate-sbom.php [OPTIONS] [path/to/project]\n\n";
    echo "Options:\n";
    echo "  -o, --output FILE   Output file path (default: sbom.json)\n";
    echo "  -h, --help          Show this help message\n\n";
    echo "Examples:\n";
    echo "  php generate-sbom.php /path/to/laravel/app\n";
    echo "  php generate-sbom.php -o build/sbom.json .\n";
    exit(0);
}

$projectPath = rtrim($args['path'], '/\\');
if ($projectPath === '') {
    $projectPath = '.';
}

if (!is_dir($projectPath)) {
    fwrite(STDERR, "Error: not a directory: {$projectPath}\n");
    exit(1);
}

$composerLock = readJsonFile($projectPath . '/composer.lock');
$packageLock = readJsonFile($projectPath . '/package-lock.json');

if ($composerLock === null && $packageLock === null) {
    fwrite(STDERR, "Error: no composer.lock or package-lock.json found in {$projectPath}\n");
    exit(1);
}

$composerJson = readJsonFile($projectPath . '/composer.json');
$appName = $composerJson['name'] ?? basename(realpath($projectPath) ?: $projectPath);

$rootComponent = [
    'type' => 'application',
    'bom-ref' => 'root-application',
    'name' => $appName,
];
if (isset($composerJson['version'])) {
    $rootComponent['version'] = $composerJson['version'];
}

$components = dedupeComponents(array_merge(
    $composerLock !== null ? composerComponents($composerLock) : [],
    $packageLock !== null ? npmComponents($packageLock) : []
));

$sbom = [
    'bomFormat' => 'CycloneDX',
    'specVersion' => '1.6',
    'serialNumber' => 'urn:uuid:' . uuidv4(),
    'version' => 1,
    'metadata' => [
        'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
        'tools' => [
            'components' => [
                [
                    'type' => 'application',
                    'name' => SBOM_TOOL_NAME,
                    'version' => SBOM_TOOL_VERSION,
                ],
            ],
        ],
        'component' => $rootComponent,
    ],
    'components' => $components,
];

file_put_contents(
    $args['output'],
    json_encode($sbom, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n"
);

echo 'SBOM generated: ' . $args['output'] . ' (' . count($components) . " components)\n";
