<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

use Firehed\WebAuthn;

$input = getRequestBodyFromJson();

$username = $input['username'];
$pdo = getSqliteConnection();
$user = getUserByName($pdo, $username);
if (!$user) {
    header('HTTP/1.1 400 Bad Request');
    return;
}

header('Content-type: text/plain');

$parser = new WebAuthn\ResponseParser();
$response = $parser->parseCreateResponse($input);

$challenge = getActiveChallenge(true);
$rp = new WebAuthn\RelyingParty('http://localhost:8888');

$credential = $response->verify($challenge, $rp);

$saved = storeCredentialForUser($pdo, $credential, $user);

var_dump("saved", $saved);

// $id = $credential->getSafeId();


// if (!file_exists(__DIR__ . "/data/$id.txt")) {
//     file_put_contents(__DIR__ . "/data/$id.txt", serialize($credential));
// }

var_dump($credential);

echo "If you got here, verify was ok!";
