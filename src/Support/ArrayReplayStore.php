<?php

namespace Akcybex\LaravelSaml\Support;

use DateTimeImmutable;

/**
 * An in-memory replay store, for tests and single-process tools.
 */
final class ArrayReplayStore implements ReplayStore
{
    /** @var array<string, true> */
    private array $seen = [];

    public function remember(string $assertionId, DateTimeImmutable $expiresAt): bool
    {
        if (isset($this->seen[$assertionId])) {
            return false;
        }

        $this->seen[$assertionId] = true;

        return true;
    }
}
