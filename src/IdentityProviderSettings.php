<?php

namespace Akcybex\LaravelSaml;

/**
 * The identity provider a team or tenant trusts: its entity id, where to send the sign-in request and the certificates its answers
 * are signed with. Only these certificates are ever used to check a signature; a key that arrives inside a message is ignored.
 */
final readonly class IdentityProviderSettings
{
    /**
     * @param  list<string>  $certificates  PEM, the current one first (several during a key rollover)
     */
    public function __construct(
        public string $entityId,
        public string $singleSignOnUrl,
        public array $certificates,
    ) {}
}
