<?php

require __DIR__ . '/vendor/autoload.php';

use Firehed\WebAuthn\{
    Challenge,
    Codecs,
};

session_start();

$pdo = getDatabaseConnection();
$user = getUserByName($pdo, $_POST['username']);
if ($user === null) {
    header('HTTP/1.1 404 Not Found');
    return;
}
$_SESSION['authenticating_user_id'] = $user['id'];

$credentialContainer = getCredentialsForUserId($pdo, $user['id']);

$challenge = Challenge::random();
$_SESSION['webauthn_challenge'] = $challenge;

// Send to user
header('Content-type: application/json');
echo json_encode([
    'challengeB64' => $challenge->getBase64(),
    'credential_ids' => $credentialContainer->getBase64Ids(),
]);
