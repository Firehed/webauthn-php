<?php

require __DIR__ . '/vendor/autoload.php';

use Firehed\WebAuthn\{
    Codecs,
    ArrayBufferResponseParser,
};

session_start();

$json = file_get_contents('php://input');
assert($json !== false);
$data = json_decode($json, true);
assert(is_array($data));

$parser = new ArrayBufferResponseParser();
$createResponse = $parser->parseCreateResponse($data);

$rp = getRelyingParty();
$challengeManager = getChallengeManager();

try {
    $credential = $createResponse->verify($challengeManager, $rp);
} catch (Throwable) {
    // Verification failed. Send an error to the user?
    header('HTTP/1.1 403 Unauthorized');
    return;
}

// Store the credential associated with the authenticated user. This is
// incredibly application-specific. Below is a sample table.
/*
CREATE TABLE user_credentials (
    id text PRIMARY KEY,
    user_id text,
    credential text,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
*/

$codec = new Codecs\Credential();
$encodedCredential = $codec->encode($credential);
$pdo = getDatabaseConnection();
$stmt = $pdo->prepare('INSERT INTO user_credentials (id, user_id, credential) VALUES (:id, :user_id, :encoded);');
$result = $stmt->execute([
    'id' => $credential->getStorageId(),
    'user_id' => $_SESSION['user_id'],
    'encoded' => $encodedCredential,
]);

// Continue with normal application flow, error handling, etc.
header('HTTP/1.1 200 OK');
header('Content-type: application/json');
echo json_encode([
    'success' => true,
    'credentialId' => $credential->getStorageId(),
]);
