<?php

namespace Akcybex\LaravelSaml\Protocol;

use Akcybex\LaravelSaml\Exceptions\SamlException;
use Akcybex\LaravelSaml\IdentityProviderSettings;
use Akcybex\LaravelSaml\ServiceProviderSettings;
use DateTimeImmutable;
use DateTimeZone;

/**
 * Builds the SP-initiated AuthnRequest and the HTTP-Redirect binding of it: raw deflate, base64, url-encoded; signed over the
 * query string with the service provider's key when it has one.
 */
final class AuthnRequestBuilder
{
    /**
     * @throws SamlException
     */
    public function build(ServiceProviderSettings $sp, IdentityProviderSettings $idp, ?string $relayState = null, ?DateTimeImmutable $now = null): AuthnRequest
    {
        $now ??= new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $id = '_'.bin2hex(random_bytes(20));

        $xml = sprintf(
            '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="%s"><saml:Issuer>%s</saml:Issuer><samlp:NameIDPolicy Format="%s" AllowCreate="true"/></samlp:AuthnRequest>',
            $id,
            $now->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z'),
            self::escape($idp->singleSignOnUrl),
            self::escape($sp->assertionConsumerServiceUrl),
            self::escape($sp->entityId),
            self::escape($sp->nameIdFormat),
        );

        $deflated = gzdeflate($xml);

        if ($deflated === false) {
            throw new SamlException('The request could not be compressed.');
        }

        $query = 'SAMLRequest='.rawurlencode(base64_encode($deflated));

        if ($relayState !== null && $relayState !== '') {
            $query .= '&RelayState='.rawurlencode($relayState);
        }

        if ($sp->privateKeyPem !== null) {
            $key = openssl_pkey_get_private($sp->privateKeyPem);

            if ($key === false) {
                throw new SamlException('The service provider key is not a valid private key.');
            }

            $query .= '&SigAlg='.rawurlencode('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
            $signature = '';

            if (! openssl_sign($query, $signature, $key, OPENSSL_ALGO_SHA256)) {
                throw new SamlException('The request could not be signed with the service provider key.');
            }

            $query .= '&Signature='.rawurlencode(base64_encode($signature));
        }

        $url = $idp->singleSignOnUrl.(str_contains($idp->singleSignOnUrl, '?') ? '&' : '?').$query;

        return new AuthnRequest($id, $url);
    }

    private static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_XML1, 'UTF-8');
    }
}
