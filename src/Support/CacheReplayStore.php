<?php

namespace Akcybex\LaravelSaml\Support;

use DateTimeImmutable;
use Illuminate\Contracts\Cache\Repository;

/**
 * The replay store on Laravel's cache. `add` is atomic, so two requests carrying the same assertion cannot both pass.
 */
final class CacheReplayStore implements ReplayStore
{
    public function __construct(private readonly Repository $cache) {}

    public function remember(string $assertionId, DateTimeImmutable $expiresAt): bool
    {
        $ttl = max(60, $expiresAt->getTimestamp() - time() + 300);

        return $this->cache->add('saml.assertion.'.hash('sha256', $assertionId), 1, $ttl);
    }
}
