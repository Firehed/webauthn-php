<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

$body = getRequestBodyFromJson();
$username = $body['username'];

/** @var PDO */
$pdo = getSqliteConnection();
$existingUser = getUserByName($pdo, $username);
if ($existingUser) {
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


header('Content-type: application/json');
echo json_encode($response);
