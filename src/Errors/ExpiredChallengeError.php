<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Errors;

use RuntimeException;

class ExpiredChallengeError extends RuntimeException implements WebAuthnErrorInterface
{
}
