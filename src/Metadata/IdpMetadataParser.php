<?php

namespace Akcybex\LaravelSaml\Metadata;

use Akcybex\LaravelSaml\Exceptions\SamlException;
use Akcybex\LaravelSaml\IdentityProviderSettings;
use Akcybex\LaravelSaml\Xml\SafeXml;
use DOMElement;
use DOMXPath;

/**
 * Reads an identity provider's metadata document: its entity id, the sign-in address (HTTP-Redirect binding preferred) and the
 * certificates it signs with. The document is only trusted as far as the person who supplied it: there is no signature check on
 * metadata here, so it must come from a source the caller trusts (an upload by the owner, or an https address they entered).
 */
final class IdpMetadataParser
{
    private const REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

    /**
     * @throws SamlException
     */
    public static function parse(string $xml): IdentityProviderSettings
    {
        $document = SafeXml::load($xml);

        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

        $entity = $xpath->query('/md:EntityDescriptor')->item(0);

        if (! $entity instanceof DOMElement || $entity->getAttribute('entityID') === '') {
            // A federation file lists many providers: pick the entity yourself and pass its XML.
            throw new SamlException('The metadata must be a single EntityDescriptor with an entityID.');
        }

        $sso = null;

        foreach ($xpath->query('md:IDPSSODescriptor/md:SingleSignOnService', $entity) ?: [] as $service) {
            if (! $service instanceof DOMElement) {
                continue;
            }

            // Sign-in requests go by the HTTP-Redirect binding, so that is the only service that is of use.
            if ($service->getAttribute('Binding') === self::REDIRECT) {
                $sso = $service;
            }
        }

        if ($sso === null || $sso->getAttribute('Location') === '') {
            throw new SamlException('The metadata has no SingleSignOnService for the HTTP-Redirect binding.');
        }

        $certificates = [];

        foreach ($xpath->query('md:IDPSSODescriptor/md:KeyDescriptor[not(@use) or @use="signing"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate', $entity) ?: [] as $node) {
            $body = preg_replace('/\s+/', '', $node->textContent);

            if (is_string($body) && $body !== '') {
                $certificates[] = "-----BEGIN CERTIFICATE-----\n".chunk_split($body, 64, "\n").'-----END CERTIFICATE-----';
            }
        }

        if ($certificates === []) {
            throw new SamlException('The metadata has no signing certificate.');
        }

        return new IdentityProviderSettings($entity->getAttribute('entityID'), $sso->getAttribute('Location'), array_values(array_unique($certificates)));
    }
}
