<?php

require __DIR__ . '/../vendor/autoload.php';

use Firehed\WebAuthn\{
    Codecs,
    ResponseParser,
};

$json = file_get_contents('php://stdin');
$data = json_decode($json, true);

$parser = new ResponseParser();
$getResponse = $parser->parseGetResponse($data);

$rp = $valueFromSetup; // e.g. $psr11Container->get(RelyingParty::class);
$challenge = $_SESSION['webauthn_challenge'];

$foundCredential = $credentialContainer->findCredentialUsedByResponse($getResponse);
if ($foundCredential === null) {
    // The credentials associated with the authenticating user did not match the
    // one used in the response. If you are using allowCredentials (as above),
    // this should never happen.
    header('HTTP/1.1 403 Unauthorized');
    return;
}

try {
    $updatedCredential = $getResponse->verify($challenge, $rp, $foundCredential);
} catch (Throwable) {
    // Verification failed. Send an error to the user?
    header('HTTP/1.1 403 Unauthorized');
    return;
}
// Update the credential
$codec = new Codecs\Credential();
$encodedCredential = $codec->encode($updatedCredential);
$stmt = $pdo->prepare('UPDATE user_credentials SET credential = :encoded WHERE id = :id AND user_id = :user_id');
$result = $stmt->execute([
    'id' => $updatedCredential->getSafeId(),
    'user_id' => $user->getId(), // $user comes from your authn process
    'encoded' => $encodedCredential,
]);

header('HTTP/1.1 200 OK');
// Send back whatever your webapp needs to finish authentication
