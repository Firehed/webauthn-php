<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

use Firehed\WebAuthn;

$body = getRequestBodyFromJson();
$username = $body['username'];

$pdo = getSqliteConnection();
$user = getUserByName($pdo, $username);
assert($user !== null);

header('Content-type: text/plain');

$parser = new WebAuthn\ResponseParser();
$response = $parser->parseGetResponse($body);

$creds = getStoredCredentialsForUser($pdo, $user);

$idFromRequest = $response->getSafeId();
// wacky array search
$foundCredential = array_reduce($creds, function ($carry, WebAuthn\CredentialInterface $cred) use ($idFromRequest) {
    // if we found from previous pass, short-circuit
    if ($carry) {
        return $carry;
    }
    // if the stored credential id matches the request, yay
    if ($cred->getSafeId() === $idFromRequest) {
        return $cred;
    }
    // not found
    return null;
}, null);

if (!$foundCredential) {
    header('HTTP/1.1 403 Unauthorized');
    error_log("No credential found!");
    return;
}

$challenge = getActiveChallenge(true);
$rp = new WebAuthn\RelyingParty('http://localhost:8888');

$result = $response->verify($challenge, $rp, $foundCredential);
storeCredentialForUser($pdo, $result, $user);

echo <<<OUT
Old sign count: {$foundCredential->getSignCount()}

Updated sign count: {$result->getSignCount()}

If you got here, verify was OK!
OUT;
