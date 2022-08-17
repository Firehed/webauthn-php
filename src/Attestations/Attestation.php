<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

/**
 * return this from verify/AttStmtI::verify ?
 */
class Attestation
{
    const TYPE_BASIC = 'Basic';
    const TYPE_SELF = 'Self';
    const TYPE_ATTESTATION_CA = 'AttCA';
    const TYPE_ANONYMIZATION_CA = 'AnonCA';
    const TYPE_NONE = 'None';
    // unknown?
    /** @var self::TYPE_* */
    public $type;

    // trust path ~ cert chain?
    // public AttestationCertificate $cert;
    /** @param self::TYPE_* $type */
    public function __construct(string $type)
    {
        $this->type = $type;
    }
}
