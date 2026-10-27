<?php

namespace Akcybex\LaravelSaml\Support;

use DateTimeImmutable;

/**
 * Remembers which assertions were used, so a captured sign-in cannot be played back.
 */
interface ReplayStore
{
    /**
     * Records the assertion id until it expires and says whether it is new: false means it was seen before.
     */
    public function remember(string $assertionId, DateTimeImmutable $expiresAt): bool;
}
