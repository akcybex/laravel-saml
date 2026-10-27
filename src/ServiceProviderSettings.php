<?php

namespace Akcybex\LaravelSaml;

/**
 * This application as a SAML service provider: who it is (entity id), where the identity provider posts the answer (assertion
 * consumer service URL), and optionally a key pair to sign requests with.
 */
final readonly class ServiceProviderSettings
{
    /**
     * @param  string|null  $privateKeyPem  signs the AuthnRequest (HTTP-Redirect signature) when set
     * @param  string|null  $certificatePem  published in the metadata so the identity provider can verify those signatures
     */
    public function __construct(
        public string $entityId,
        public string $assertionConsumerServiceUrl,
        public ?string $privateKeyPem = null,
        public ?string $certificatePem = null,
        public string $nameIdFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    ) {}
}
