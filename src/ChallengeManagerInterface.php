<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @api
 */
interface ChallengeManagerInterface extends ChallengeLoaderInterface
{
    /**
     * Takes the provided challenge and stores it in the backing mechanism.
     *
     * @api
     */
    public function manageChallenge(ChallengeInterface $challenge): void;
}
