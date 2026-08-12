#!/usr/bin/env php
<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Tools;

use Symfony\Component\Console\Application;

require __DIR__ . '/../vendor/autoload.php';

$command = new GenerateTestVectorsCommand();

$application = new Application('webauthn-php development tools');
$application->add($command);
$application->setDefaultCommand((string) $command->getName(), true);
$application->run();
