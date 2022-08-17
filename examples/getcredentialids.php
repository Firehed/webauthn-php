<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

$username = $_GET['username'];
$pdo = getSqliteConnection();
$user = getUserByName($pdo, $username);
$creds = getStoredCredentialsForUser($pdo, $user);

// TODO: how to better move this around
$ids = array_map(function ($cred) {
    return base64_encode($cred->id->unwrap());
}, $creds);

header('Content-type: application/json');
echo json_encode($ids);
