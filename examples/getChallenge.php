<?php

require __DIR__ . '/vendor/autoload.php';

session_start();

// Generate challenge
$challengeManager = getChallengeManager();
$challenge = $challengeManager->createChallenge();

// Send to user
header('Content-type: application/json');
echo json_encode([
    'b64' => $challenge->getBase64(),
]);
