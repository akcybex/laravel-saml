<?php

namespace Akcybex\LaravelSaml\Metadata;

use Akcybex\LaravelSaml\ServiceProviderSettings;
use DOMDocument;

/**
 * The service provider's metadata document, which the identity provider's administrator imports.
 */
final class SpMetadata
{
    public static function xml(ServiceProviderSettings $sp): string
    {
        $document = new DOMDocument('1.0', 'UTF-8');
        $document->formatOutput = true;

        $md = 'urn:oasis:names:tc:SAML:2.0:metadata';

        $entity = $document->createElementNS($md, 'md:EntityDescriptor');
        $entity->setAttribute('entityID', $sp->entityId);
        $document->appendChild($entity);

        $descriptor = $document->createElementNS($md, 'md:SPSSODescriptor');
        $descriptor->setAttribute('protocolSupportEnumeration', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $descriptor->setAttribute('AuthnRequestsSigned', $sp->privateKeyPem !== null ? 'true' : 'false');
        $descriptor->setAttribute('WantAssertionsSigned', 'true');
        $entity->appendChild($descriptor);

        if ($sp->certificatePem !== null) {
            $key = $document->createElementNS($md, 'md:KeyDescriptor');
            $key->setAttribute('use', 'signing');
            $info = $document->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:KeyInfo');
            $data = $document->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:X509Data');
            $certificate = $document->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:X509Certificate');
            $certificate->appendChild($document->createTextNode(self::certificateBody($sp->certificatePem)));
            $data->appendChild($certificate);
            $info->appendChild($data);
            $key->appendChild($info);
            $descriptor->appendChild($key);
        }

        $format = $document->createElementNS($md, 'md:NameIDFormat');
        $format->appendChild($document->createTextNode($sp->nameIdFormat));
        $descriptor->appendChild($format);

        $acs = $document->createElementNS($md, 'md:AssertionConsumerService');
        $acs->setAttribute('Binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');
        $acs->setAttribute('Location', $sp->assertionConsumerServiceUrl);
        $acs->setAttribute('index', '0');
        $acs->setAttribute('isDefault', 'true');
        $descriptor->appendChild($acs);

        return (string) $document->saveXML();
    }

    public static function certificateBody(string $pem): string
    {
        return (string) preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', $pem);
    }
}
