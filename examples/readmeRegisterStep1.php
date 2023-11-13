<?php

require __DIR__ . '/vendor/autoload.php';

session_start();

// Normally this would come from something like a) a user already logged-in
// with a password or b) a user that was just created and wants to set up
// a WebAuthn credential (who may not have a password at all!)
$user = createUser(getDatabaseConnection(), $_POST['username']);
$_SESSION['user_id'] = $user['id'];

// Send to user
header('Content-type: application/json');
echo json_encode([
    'user' => $user,
]);
