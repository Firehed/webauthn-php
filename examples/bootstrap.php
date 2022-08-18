<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Firehed\WebAuthn\Challenge;
use Firehed\WebAuthn\Credential;
use Firehed\WebAuthn\Codecs\Credential as CredentialCodec;

const INDEX_SESSION_CHALLENGE = 'challenge';
const INDEX_SESSION_CHALLENGE_CREATED = 'challenge_created';

session_start();

function getRequestBodyFromJson(): array
{
    $rawJson = file_get_contents('php://input');
    assert(is_string($rawJson));
    $decoded = json_decode($rawJson, true, flags: JSON_THROW_ON_ERROR);
    return $decoded;
}

function getActiveChallenge(bool $clear = false): Challenge
{
    $generate = function (): Challenge {
        $challenge = Challenge::random(32);
        $_SESSION[INDEX_SESSION_CHALLENGE_CREATED] = time();
        $_SESSION[INDEX_SESSION_CHALLENGE] = $challenge;
        return $challenge;
    };

    try {
        $hasTime = array_key_exists(INDEX_SESSION_CHALLENGE_CREATED, $_SESSION);
        if (!$hasTime) {
            return $generate();
        }

        // If too old, create a new one.
        if ((time() - $_SESSION[INDEX_SESSION_CHALLENGE_CREATED]) > 60) {
            return $generate();
        }

        $exists = array_key_exists(INDEX_SESSION_CHALLENGE, $_SESSION);
        if (!$exists) {
            return $generate();
        }

        return $_SESSION[INDEX_SESSION_CHALLENGE];
    } finally {
        if ($clear) {
            unset($_SESSION[INDEX_SESSION_CHALLENGE]);
            unset($_SESSION[INDEX_SESSION_CHALLENGE_CREATED]);
        }
    }
}

function uuidv4(): string
{
    $bytes = random_bytes(16);
    $hex = bin2hex($bytes);
    $chunks = str_split($hex, 4);
    $chunks[3][0] = '4';
    return sprintf('%s%s-%s-%s-%s-%s%s%s', ...$chunks);
}

function getSqliteConnection(): PDO
{
    $dbFile = __DIR__ . '/app.sqlite3';

    $create = !file_exists($dbFile);

    $pdo = new PDO(sprintf('sqlite:%s', $dbFile));

    if ($create) {
        $pdo->exec(<<<SQL
        CREATE TABLE users (
            id text PRIMARY KEY,
            name text UNIQUE
        );
        SQL);
        $pdo->exec(<<<SQL
        CREATE TABLE user_credentials (
            id text PRIMARY KEY,
            user_id text,
            credential text,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        SQL);
    }

    return $pdo;
}

function getUserByName(PDO $pdo, string $name): ?array
{
    $stmt = $pdo->prepare('SELECT * FROM users WHERE name = ?');
    $stmt->execute([$name]);
    $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
    if ($result !== []) {
        return $result[0];
    } else {
        return null;
    }
}

/**
 * @param array{id: string} $user
 */
function storeCredentialForUser(PDO $pdo, Credential $credential, array $user): bool
{
    $credentialId = $credential->getSafeId();

    $stmt = $pdo->prepare('SELECT * FROM user_credentials WHERE id = ?');
    $stmt->execute([$credentialId]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    if (count($rows) === 1) {
        if ($rows[0]['user_id'] !== $user['id']) {
            error_log('credential attached to a different user (7.1.22)');
            return false;
        }
        // Already stored, do nothing.
        return true;
    } elseif (count($rows) > 1) {
        error_log('UNIQUE KEY VIOLATION???');
        return false;
    }

    $stmt = $pdo->prepare('INSERT INTO user_credentials (id, user_id, credential) VALUES (?, ?, ?)');
    $codec = new CredentialCodec();
    return $stmt->execute([
        $credentialId,
        $user['id'],
        $codec->encode($credential),
    ]);
}

/** @return Credential[] */
function getStoredCredentialsForUser(PDO $pdo, array $user): array
{
    $stmt = $pdo->prepare('SELECT * FROM user_credentials WHERE user_id = ?');
    $stmt->execute([$user['id']]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $codec = new CredentialCodec();
    return array_map(fn ($row) => $codec->decode($row['credential']), $rows);
}
