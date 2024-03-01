<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @api
 */
interface ChallengeManagerInterface extends ChallengeLoaderInterface
{
    /**
     * Generates a new Challenge, stores it in the backing mechanism, and
     * returns it.
     *
     * @api
     */
    public function manageChallenge(ChallengeInterface $challenge): void;
}
