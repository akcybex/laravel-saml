<?php

namespace Akcybex\LaravelSaml;

use Akcybex\LaravelSaml\Metadata\SpMetadata;
use Akcybex\LaravelSaml\Protocol\AuthnRequest;
use Akcybex\LaravelSaml\Protocol\AuthnRequestBuilder;
use Akcybex\LaravelSaml\Protocol\ResponseValidator;
use Akcybex\LaravelSaml\Support\ReplayStore;

/**
 * The entry point. SP-initiated sign-in in three calls:
 *
 *     $request = $saml->authnRequest($sp, $idp, $relayState);   // keep $request->id in the session, redirect to $request->redirectUrl
 *     $assertion = $saml->validate($_POST['SAMLResponse'], $sp, $idp, $pendingRequestId);   // at the assertion consumer service
 *     // sign the person in from $assertion->nameId / $assertion->attributes, and forget $pendingRequestId
 *
 * The service provider and the identity provider are values, not configuration, so one application can serve many tenants,
 * each with its own identity provider.
 */
final class Saml
{
    public function __construct(
        private readonly ReplayStore $replay,
        private readonly int $clockSkewSeconds = 120,
        private readonly bool $allowSha1 = false,
        private readonly bool $allowIdpInitiated = false,
    ) {}

    public function authnRequest(ServiceProviderSettings $sp, IdentityProviderSettings $idp, ?string $relayState = null): AuthnRequest
    {
        return (new AuthnRequestBuilder)->build($sp, $idp, $relayState);
    }

    /**
     * @throws Exceptions\SamlException
     */
    public function validate(string $samlResponse, ServiceProviderSettings $sp, IdentityProviderSettings $idp, ?string $pendingRequestId): Assertion
    {
        return (new ResponseValidator($this->replay, $this->clockSkewSeconds, $this->allowSha1, $this->allowIdpInitiated))
            ->validate($samlResponse, $sp, $idp, $pendingRequestId);
    }

    public function metadata(ServiceProviderSettings $sp): string
    {
        return SpMetadata::xml($sp);
    }
}
