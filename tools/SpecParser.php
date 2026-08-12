<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Tools;

use UnexpectedValueException;

use function array_chunk;
use function array_diff;
use function array_keys;
use function array_shift;
use function implode;
use function preg_match;
use function preg_match_all;
use function preg_quote;
use function preg_split;
use function sprintf;
use function strpos;
use function substr;

/**
 * Extracts the §16 test vectors from the WebAuthn bikeshed source (index.bs).
 *
 * Upstream generates this content with test-vectors/webauthn-test-vectors.py
 * and injects it between marker comments, verifying in CI that the two stay in
 * sync. Both the markers and the `name = h'...'` line format are therefore
 * maintained by machine rather than by hand.
 *
 * @link https://github.com/w3c/webauthn/tree/main/test-vectors
 */
class SpecParser
{
    private const BEGIN = '<!-- GENERATED CONTENT: Use test-vectors/webauthn-test-vectors.py -->';
    private const END = '<!-- END GENERATED CONTENT: Use test-vectors/webauthn-test-vectors.py -->';

    /**
     * §16.1 is the shared attestation trust root. It describes no credential,
     * and the harness does no chain validation, so it has no fixture.
     */
    private const SKIPPED_SLUG = 'attestation-root-cert';

    private const REQUIRED_REGISTRATION = [
        'challenge',
        'credential_id',
        'clientDataJSON',
        'attestationObject',
    ];

    private const REQUIRED_AUTHENTICATION = [
        'challenge',
        'authenticatorData',
        'clientDataJSON',
        'signature',
    ];

    /**
     * @return Vector[]
     */
    public function parse(string $spec): array
    {
        $start = strpos($spec, self::BEGIN);
        $end = strpos($spec, self::END);
        if ($start === false || $end === false) {
            throw new UnexpectedValueException(
                'Could not locate the generated test vector block. Is this a WebAuthn index.bs?'
            );
        }
        $block = substr($spec, $start, $end - $start);

        // Yields [preamble, slug, body, slug, body, ...]
        $sections = preg_split(
            '/^## .+ ## \{#sctn-test-vectors-([A-Za-z0-9-]+)\}$/m',
            $block,
            flags: PREG_SPLIT_DELIM_CAPTURE,
        );
        if ($sections === false) {
            throw new UnexpectedValueException('Could not split the vector block into sections');
        }
        array_shift($sections);

        $vectors = [];
        foreach (array_chunk($sections, 2) as $pair) {
            if (count($pair) !== 2) {
                throw new UnexpectedValueException('Found a vector heading with no body');
            }
            [$slug, $body] = $pair;
            if ($slug === self::SKIPPED_SLUG) {
                continue;
            }

            $registration = self::extractCeremony($body, 'Registration');
            if ($registration === null) {
                throw new UnexpectedValueException(sprintf('%s has no registration ceremony', $slug));
            }
            self::requireFields($registration, self::REQUIRED_REGISTRATION, "$slug registration");

            $authentication = self::extractCeremony($body, 'Authentication');
            if ($authentication !== null) {
                self::requireFields($authentication, self::REQUIRED_AUTHENTICATION, "$slug authentication");
            }

            $vectors[] = new Vector(
                slug: $slug,
                registration: $registration,
                authentication: $authentication,
            );
        }

        if ($vectors === []) {
            throw new UnexpectedValueException('The vector block contained no credential vectors');
        }

        return $vectors;
    }

    /**
     * @return ?array<string, string>
     */
    private static function extractCeremony(string $body, string $label): ?array
    {
        $pattern = sprintf('/%s=\]:\s*<xmp[^>]*>(.*?)<\/xmp>/s', preg_quote($label, '/'));
        if (preg_match($pattern, $body, $matches) !== 1) {
            return null;
        }
        return self::parseAssignments($matches[1]);
    }

    /**
     * Reads `name = h'hex'` lines, ignoring `;` comments and the alternate
     * `= b64'...'` rendering that some values carry.
     *
     * @return array<string, string>
     */
    private static function parseAssignments(string $block): array
    {
        preg_match_all("/^([A-Za-z_][A-Za-z0-9_]*) = h'([0-9a-f]*)'/m", $block, $matches, PREG_SET_ORDER);

        $values = [];
        foreach ($matches as $match) {
            $values[$match[1]] ??= $match[2];
        }
        return $values;
    }

    /**
     * @param array<string, string> $ceremony
     * @param string[] $required
     */
    private static function requireFields(array $ceremony, array $required, string $context): void
    {
        $missing = array_diff($required, array_keys($ceremony));
        if ($missing !== []) {
            throw new UnexpectedValueException(sprintf(
                '%s is missing expected field(s): %s',
                $context,
                implode(', ', $missing),
            ));
        }
    }
}
