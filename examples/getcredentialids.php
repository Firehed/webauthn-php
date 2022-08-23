<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

$username = $_GET['username'];
$pdo = getSqliteConnection();
$user = getUserByName($pdo, $username);
assert($user !== null);
$creds = getStoredCredentialsForUser($pdo, $user);

$ids = $creds->getBase64Ids();

header('Content-type: application/json');
echo json_encode($ids);
