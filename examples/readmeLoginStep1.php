<?php

require __DIR__ . '/../vendor/autoload.php';

use Firehed\WebAuthn\{
    Challenge,
    Codecs,
    CredentialContainer,
};

session_start();

$userId = $alreadyKnownValue;
$pdo = getDatabaseConnection();

$stmt = $pdo->prepare('SELECT * FROM user_credentials WHERE user_id = ?');
$stmt->execute([$userId]);
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
$codec = new Codecs\Credential();
$credentials = array_map(function ($row) use ($codec) {
    return $codec->decode($row['credential']);
}, $rows);

/**
 * This value will be re-used in a future step.
 */
$credentialContainer = new CredentialContainer($credentials);

$challenge = Challenge::random();
$_SESSION['webauthn_challenge'] = $challenge;

// Send to user
header('Content-type: application/json');
echo json_encode([
    'challenge' => $challenge->getBase64(),
    'credential_ids' => $credentialContainer->getBase64Ids(),
]);
