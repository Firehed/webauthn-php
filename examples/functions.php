<?php

declare(strict_types=1);

use Firehed\WebAuthn\{
    RelyingParty,
};

/**
 * @return array{id:string,name:string}
 */
function createUser(PDO $pdo, string $username): array
{
    $existingUser = getUserByName($pdo, $username);
    if ($existingUser !== null) {
        $response = $existingUser;
    } else {
        $stmt = $pdo->prepare('INSERT INTO users (id, name) VALUES (?, ?)');
        $id = uuidv4();
        $stmt->execute([$id, $username]);
        $response = [
            'id' => $id,
            'name' => $username,
        ];
    }
    return $response;
}

function getDatabaseConnection(): PDO
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

function getRelyingParty(): RelyingParty
{
    // This would be configured by a env var or something
    return new RelyingParty('http://localhost:8888');
}

/**
 * @return array{id:string, name: string}|null
 */
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

function uuidv4(): string
{
    $bytes = random_bytes(16);
    $hex = bin2hex($bytes);
    $chunks = str_split($hex, 4);
    $chunks[3][0] = '4';
    return sprintf('%s%s-%s-%s-%s-%s%s%s', ...$chunks);
}
