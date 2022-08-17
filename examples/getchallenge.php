<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

$challenge = getActiveChallenge();

header('Content-type: application/json');
echo json_encode(base64_encode($challenge->getChallenge()));
