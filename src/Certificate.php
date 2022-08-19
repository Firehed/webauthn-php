<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @internal
 */
class Certificate
{
    public function __construct(private BinaryString $binary)
    {
    }

    public function getPemFormatted(): string
    {
        $data = base64_encode($this->binary->unwrap());
        $pem  = "-----BEGIN CERTIFICATE-----\r\n";
        $pem .= chunk_split($data, 64);
        $pem .= "-----END CERTIFICATE-----";
        return $pem;
    }
}
