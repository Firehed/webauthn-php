<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Tools;

/**
 * A single credential test vector from WebAuthn §16: a registration ceremony
 * and, where the spec provides one, the matching authentication ceremony.
 *
 * Values are the raw hex strings exactly as published. Conversion to the
 * on-disk format happens in FixtureWriter.
 *
 * @phpstan-type Ceremony array<string, string>
 */
class Vector
{
    /**
     * @param Ceremony $registration
     * @param ?Ceremony $authentication
     */
    public function __construct(
        public readonly string $slug,
        public readonly array $registration,
        public readonly ?array $authentication,
    ) {
    }
}
