<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Firehed\WebAuthn\Challenge;
use Firehed\WebAuthn\CredentialContainer;
use Firehed\WebAuthn\CredentialInterface;
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
 * Persists a credential to external storage, associated with the provided
 * user. If it is already stored, update it (this is done to track the
 * monotonically increasing signnature counter)
 *
 * @param array{id: string} $user
 */
function storeCredentialForUser(PDO $pdo, CredentialInterface $credential, array $user): bool
{
    $credentialId = $credential->getSafeId();

    // Check if the credential already exists
    $stmt = $pdo->prepare('SELECT * FROM user_credentials WHERE id = ?');
    $stmt->execute([$credentialId]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // This should be unreachable!
    if (count($rows) > 1) {
        error_log('UNIQUE KEY VIOLATION???');
        return false;
    }

    $codec = new CredentialCodec();

    // The credential is stored.
    if (count($rows) === 1) {
        // This credential is associated with a different user! Error out.
        if ($rows[0]['user_id'] !== $user['id']) {
            error_log('credential attached to a different user (7.1.22)');
            return false;
        }

        // Already stored, update it (track the new sign count)
        $stmt = $pdo->prepare('UPDATE user_credentials SET credential = :encoded WHERE id = :id AND user_id = :user_id');
    } else {
        // Brand new credential = insert it.
        $stmt = $pdo->prepare('INSERT INTO user_credentials (id, user_id, credential) VALUES (:id, :user_id, :encoded)');
    }

    $result = $stmt->execute([
        'id' => $credentialId,
        'user_id' => $user['id'],
        'encoded' => $codec->encode($credential),
    ]);
    if (!$result) {
        return false;
    }

    // If no rows were affected, something went wrong. This is mostly for the
    // UPDATE(user_id) sanity-check.
    return $stmt->rowCount() === 1;
}

/**
 * @param array{id: string} $user
 * @return CredentialContainer
 */
function getStoredCredentialsForUser(PDO $pdo, array $user): CredentialContainer
{
    $stmt = $pdo->prepare('SELECT * FROM user_credentials WHERE user_id = ?');
    $stmt->execute([$user['id']]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $codec = new CredentialCodec();
    $creds = array_map(fn ($row) => $codec->decode($row['credential']), $rows);

    return new CredentialContainer($creds);
}
