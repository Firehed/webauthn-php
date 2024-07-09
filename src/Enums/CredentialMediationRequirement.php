<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Enums;

/**
 * Credential Management (Level 1)
 * §2.3.2
 * @link https://w3c.github.io/webappsec-credential-management/#dom-credentialmediationrequirement-conditional
 */
enum CredentialMediationRequirement: string
{
    case Silent = 'silent';
    case Optional = 'optional';
    case Conditional = 'conditional';
    case Required = 'required';
}
