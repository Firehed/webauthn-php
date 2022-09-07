<?php

require __DIR__ . '/vendor/autoload.php';

use Firehed\WebAuthn\{
    Codecs,
    ResponseParser,
};

session_start();

$pdo = getDatabaseConnection();

$json = file_get_contents('php://input');
assert($json !== false);
$data = json_decode($json, true);
assert(is_array($data));

$parser = new ResponseParser();
$getResponse = $parser->parseGetResponse($data);

$rp = getRelyingParty();
$challenge = $_SESSION['webauthn_challenge'];

$credentialContainer = getCredentialsForUserId($pdo, $_SESSION['authenticating_user_id']);

try {
    $updatedCredential = $getResponse->verify($challenge, $rp, $credentialContainer);
} catch (Throwable) {
    // Verification failed. Send an error to the user?
    header('HTTP/1.1 403 Unauthorized');
    return;
}

// Authenticating has succeeded!

// Update the credential
$codec = new Codecs\Credential();
$encodedCredential = $codec->encode($updatedCredential);
$stmt = $pdo->prepare('UPDATE user_credentials SET credential = :encoded WHERE id = :id AND user_id = :user_id');
$result = $stmt->execute([
    'id' => $updatedCredential->getStorageId(),
    'user_id' => $_SESSION['authenticating_user_id'],
    'encoded' => $encodedCredential,
]);

header('HTTP/1.1 200 OK');
// Send back whatever your webapp needs to finish authentication on the client
// side and update any additional state
header('Content-type: application/json');
echo json_encode([
    'success' => true,
    'user_id' => $_SESSION['authenticating_user_id'],
    'newCredId' => $updatedCredential->getStorageId(),
]);
