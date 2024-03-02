<?php

require __DIR__ . '/vendor/autoload.php';

use Firehed\WebAuthn\ExpiringChallenge;

session_start();

// Generate challenge
$challengeManager = getChallengeManager();
$challenge = ExpiringChallenge::withLifetime(300);
$challengeManager->manageChallenge($challenge);

// Send to user
header('Content-type: application/json');
echo json_encode([
    'b64' => $challenge->getBase64(),
]);
