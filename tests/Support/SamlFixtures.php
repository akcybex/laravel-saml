<?php

namespace Akcybex\LaravelSaml\Tests\Support;

use Akcybex\LaravelSaml\IdentityProviderSettings;
use Akcybex\LaravelSaml\ServiceProviderSettings;
use DateTimeImmutable;
use DateTimeZone;
use DOMDocument;
use DOMElement;
use DOMNode;
use DOMXPath;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RuntimeException;

/**
 * Builds the things the tests feed to the package: key pairs, settings, and signed SAML Responses.
 *
 * A Response is built as a string from options (every field can be overridden, null drops an attribute or element where that
 * makes sense), loaded into a DOM, signed with xmlseclibs, optionally changed by an `after` callback (to tamper with it or to
 * build a wrapping attack), and returned base64-encoded as the identity provider's browser would post it.
 *
 * Options (defaults in parentheses):
 *   signing                'assertion' | 'response' | 'both' | 'none'  ('assertion')
 *   key, cert              PEM used to sign / embedded when includeCert  (the identity provider's)
 *   includeCert            put the certificate in KeyInfo  (false)
 *   sigAlg, digest, c14n   XMLSecurityKey / XMLSecurityDSig constants  (RSA-SHA256, SHA256, exclusive c14n)
 *   after                  fn (DOMDocument, DOMXPath): void, run after signing
 *   at                     DateTimeImmutable all default times are relative to  (NOW)
 *   responseId, assertionId, destination, responseInResponseTo, scdInResponseTo, responseIssuer, assertionIssuer, status,
 *   nameId, nameIdFormat, recipient, scdNotBefore, scdNotOnOrAfter, conditions (bool), conditionsNotBefore,
 *   conditionsNotOnOrAfter, audienceRestrictions (list of list of audiences), subjectConfirmationMethod,
 *   subjectConfirmationData (bool), sessionIndex, attributes (name => values), responseIssueInstant, assertionIssueInstant,
 *   version, assertionVersion, assertion (bool), conditionsExtra, assertionExtra, responseExtra (raw XML), saml2Prefixes (bool)
 */
final class SamlFixtures
{
    public const SP_ENTITY = 'https://sp.example.com/saml/metadata';

    public const ACS = 'https://sp.example.com/saml/acs';

    public const IDP_ENTITY = 'https://idp.example.com/metadata';

    public const IDP_SSO = 'https://idp.example.com/sso';

    public const REQUEST_ID = '_request123';

    public const NOW = '2026-01-15T12:00:00Z';

    public const NS_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

    public const NS_ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    public const NS_METADATA = 'urn:oasis:names:tc:SAML:2.0:metadata';

    public const NS_DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    public const STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

    public const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';

    public const BINDING_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

    public const BINDING_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

    public const EMAIL_FORMAT = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';

    /** @var array<string, array{key: string, cert: string}> */
    private static array $pairs = [];

    /**
     * An RSA 2048 key and a self-signed certificate, generated once per process. Known names: idp, attacker, sp.
     *
     * @return array{key: string, cert: string}
     */
    public static function pair(string $name = 'idp'): array
    {
        return self::$pairs[$name] ??= self::generate($name);
    }

    public static function key(string $name = 'idp'): string
    {
        return self::pair($name)['key'];
    }

    public static function cert(string $name = 'idp'): string
    {
        return self::pair($name)['cert'];
    }

    /**
     * @return array{key: string, cert: string}
     */
    private static function generate(string $name): array
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);

        if ($key === false) {
            throw new RuntimeException('openssl_pkey_new failed: '.openssl_error_string());
        }

        $csr = openssl_csr_new(['commonName' => $name.'.example.com'], $key, ['digest_alg' => 'sha256']);

        if ($csr === false) {
            throw new RuntimeException('openssl_csr_new failed: '.openssl_error_string());
        }

        $x509 = openssl_csr_sign($csr, null, $key, 3650, ['digest_alg' => 'sha256']);

        if ($x509 === false) {
            throw new RuntimeException('openssl_csr_sign failed: '.openssl_error_string());
        }

        $certPem = '';
        $keyPem = '';

        if (! openssl_x509_export($x509, $certPem) || ! openssl_pkey_export($key, $keyPem)) {
            throw new RuntimeException('Exporting the key pair failed: '.openssl_error_string());
        }

        return ['key' => $keyPem, 'cert' => $certPem];
    }

    public static function now(): DateTimeImmutable
    {
        return new DateTimeImmutable(self::NOW, new DateTimeZone('UTC'));
    }

    /**
     * An xs:dateTime that many seconds from the base time (NOW unless given).
     */
    public static function at(int $seconds, ?DateTimeImmutable $base = null): string
    {
        return ($base ?? self::now())->modify(sprintf('%+d seconds', $seconds))->format('Y-m-d\TH:i:s\Z');
    }

    public static function sp(bool $signRequests = false, string $entityId = self::SP_ENTITY, string $acs = self::ACS): ServiceProviderSettings
    {
        return new ServiceProviderSettings(
            $entityId,
            $acs,
            $signRequests ? self::key('sp') : null,
            $signRequests ? self::cert('sp') : null,
        );
    }

    /**
     * @param  list<string>|null  $certificates  defaults to the identity provider's one certificate
     */
    public static function idp(?array $certificates = null, string $entityId = self::IDP_ENTITY, string $sso = self::IDP_SSO): IdentityProviderSettings
    {
        return new IdentityProviderSettings($entityId, $sso, $certificates ?? [self::cert('idp')]);
    }

    public static function xpath(DOMDocument $document): DOMXPath
    {
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('samlp', self::NS_PROTOCOL);
        $xpath->registerNamespace('saml', self::NS_ASSERTION);
        $xpath->registerNamespace('md', self::NS_METADATA);
        $xpath->registerNamespace('ds', self::NS_DSIG);

        return $xpath;
    }

    /**
     * The first element an expression selects; a missing one is a mistake in the test.
     */
    public static function node(DOMXPath $xpath, string $expression, ?DOMNode $context = null): DOMElement
    {
        $node = $xpath->query($expression, $context)?->item(0);

        if (! $node instanceof DOMElement) {
            throw new RuntimeException('The fixture has no node for '.$expression);
        }

        return $node;
    }

    public static function response(array $options = []): string
    {
        return base64_encode(self::xml($options));
    }

    /**
     * The signed Response as XML text (response() is this, base64-encoded).
     *
     * @param  array<string, mixed>  $options
     */
    public static function xml(array $options = []): string
    {
        $o = array_replace(self::defaults($options['at'] ?? self::now()), $options);

        $xml = self::build($o);

        if ($o['saml2Prefixes']) {
            $xml = (string) preg_replace(
                ['/<(\/?)samlp:/', '/<(\/?)saml:/', '/xmlns:samlp=/', '/xmlns:saml=/'],
                ['<$1saml2p:', '<$1saml2:', 'xmlns:saml2p=', 'xmlns:saml2='],
                $xml,
            );
        }

        $document = new DOMDocument('1.0', 'UTF-8');
        $document->preserveWhiteSpace = true;

        if (! $document->loadXML($xml)) {
            throw new RuntimeException('The fixture XML is not well formed.');
        }

        $response = $document->documentElement;
        $assertion = $document->getElementsByTagNameNS(self::NS_ASSERTION, 'Assertion')->item(0);

        // The Response's digest covers the Assertion's signature, so the Assertion is signed first.
        if (in_array($o['signing'], ['assertion', 'both'], true) && $assertion instanceof DOMElement) {
            self::sign($assertion, $o);
        }

        if (in_array($o['signing'], ['response', 'both'], true) && $response instanceof DOMElement) {
            self::sign($response, $o);
        }

        if ($o['after'] !== null) {
            ($o['after'])($document, self::xpath($document));
        }

        return (string) $document->saveXML();
    }

    /**
     * @param  DateTimeImmutable  $base
     * @return array<string, mixed>
     */
    private static function defaults(DateTimeImmutable $base): array
    {
        return [
            'signing' => 'assertion',
            'key' => self::key('idp'),
            'cert' => self::cert('idp'),
            'includeCert' => false,
            'sigAlg' => XMLSecurityKey::RSA_SHA256,
            'digest' => XMLSecurityDSig::SHA256,
            'c14n' => XMLSecurityDSig::EXC_C14N,
            'after' => null,
            'at' => $base,
            'saml2Prefixes' => false,

            'responseId' => '_response1',
            'assertionId' => '_assertion1',
            'version' => '2.0',
            'assertionVersion' => '2.0',
            'responseIssueInstant' => self::at(0, $base),
            'assertionIssueInstant' => self::at(0, $base),
            'destination' => self::ACS,
            'responseInResponseTo' => self::REQUEST_ID,
            'scdInResponseTo' => self::REQUEST_ID,
            'responseIssuer' => self::IDP_ENTITY,
            'assertionIssuer' => self::IDP_ENTITY,
            'status' => self::STATUS_SUCCESS,

            'assertion' => true,
            'nameId' => 'alice@example.com',
            'nameIdFormat' => self::EMAIL_FORMAT,
            'subjectConfirmationMethod' => self::BEARER,
            'subjectConfirmationData' => true,
            'recipient' => self::ACS,
            'scdNotBefore' => null,
            'scdNotOnOrAfter' => self::at(300, $base),

            'conditions' => true,
            'conditionsNotBefore' => self::at(-60, $base),
            'conditionsNotOnOrAfter' => self::at(300, $base),
            'audienceRestrictions' => [[self::SP_ENTITY]],

            'sessionIndex' => '_session1',
            'attributes' => ['mail' => ['alice@example.com'], 'groups' => ['admins', 'staff']],

            'conditionsExtra' => '',
            'assertionExtra' => '',
            'responseExtra' => '',
        ];
    }

    /**
     * @param  array<string, mixed>  $o
     */
    private static function build(array $o): string
    {
        $assertion = '';

        if ($o['assertion'] !== false) {
            $issuer = $o['assertionIssuer'] === null ? '' : '<saml:Issuer>'.self::esc($o['assertionIssuer']).'</saml:Issuer>';

            $nameId = $o['nameId'] === null ? '' : '<saml:NameID'.self::attr('Format', $o['nameIdFormat']).'>'.self::esc($o['nameId']).'</saml:NameID>';

            $data = $o['subjectConfirmationData']
                ? '<saml:SubjectConfirmationData'.self::attr('NotBefore', $o['scdNotBefore']).self::attr('NotOnOrAfter', $o['scdNotOnOrAfter']).self::attr('Recipient', $o['recipient']).self::attr('InResponseTo', $o['scdInResponseTo']).'/>'
                : '';

            $subject = '<saml:Subject>'.$nameId.'<saml:SubjectConfirmation'.self::attr('Method', $o['subjectConfirmationMethod']).'>'.$data.'</saml:SubjectConfirmation></saml:Subject>';

            $conditions = '';

            if ($o['conditions']) {
                $restrictions = '';

                foreach ($o['audienceRestrictions'] as $audiences) {
                    $restrictions .= '<saml:AudienceRestriction>';

                    foreach ($audiences as $audience) {
                        $restrictions .= '<saml:Audience>'.self::esc($audience).'</saml:Audience>';
                    }

                    $restrictions .= '</saml:AudienceRestriction>';
                }

                $conditions = '<saml:Conditions'.self::attr('NotBefore', $o['conditionsNotBefore']).self::attr('NotOnOrAfter', $o['conditionsNotOnOrAfter']).'>'.$restrictions.$o['conditionsExtra'].'</saml:Conditions>';
            }

            $authn = '<saml:AuthnStatement AuthnInstant="'.self::esc($o['assertionIssueInstant']).'"'.self::attr('SessionIndex', $o['sessionIndex']).'><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>';

            $attributes = '';

            foreach ($o['attributes'] as $name => $values) {
                $attributes .= '<saml:Attribute Name="'.self::esc((string) $name).'">';

                foreach ($values as $value) {
                    $attributes .= '<saml:AttributeValue>'.self::esc($value).'</saml:AttributeValue>';
                }

                $attributes .= '</saml:Attribute>';
            }

            if ($attributes !== '') {
                $attributes = '<saml:AttributeStatement>'.$attributes.'</saml:AttributeStatement>';
            }

            $assertion = '<saml:Assertion'.self::attr('ID', $o['assertionId']).self::attr('Version', $o['assertionVersion']).self::attr('IssueInstant', $o['assertionIssueInstant']).'>'
                .$issuer.$subject.$conditions.$authn.$attributes.$o['assertionExtra']
                .'</saml:Assertion>';
        }

        $responseIssuer = $o['responseIssuer'] === null ? '' : '<saml:Issuer>'.self::esc($o['responseIssuer']).'</saml:Issuer>';

        return '<samlp:Response xmlns:samlp="'.self::NS_PROTOCOL.'" xmlns:saml="'.self::NS_ASSERTION.'"'
            .self::attr('ID', $o['responseId']).self::attr('Version', $o['version']).self::attr('IssueInstant', $o['responseIssueInstant'])
            .self::attr('Destination', $o['destination']).self::attr('InResponseTo', $o['responseInResponseTo']).'>'
            .$responseIssuer
            .'<samlp:Status><samlp:StatusCode'.self::attr('Value', $o['status']).'/></samlp:Status>'
            .$assertion.$o['responseExtra']
            .'</samlp:Response>';
    }

    /**
     * Signs one element with an enveloped signature that references it by its ID, the way identity providers do.
     *
     * @param  array<string, mixed>  $o
     */
    private static function sign(DOMElement $element, array $o): void
    {
        $dsig = new XMLSecurityDSig;
        $dsig->setCanonicalMethod($o['c14n']);
        $dsig->addReference(
            $element,
            $o['digest'],
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N],
            ['id_name' => 'ID', 'overwrite' => false],
        );

        $key = new XMLSecurityKey($o['sigAlg'], ['type' => 'private']);
        $key->loadKey($o['key'], false);

        $dsig->sign($key);

        if ($o['includeCert']) {
            $dsig->add509Cert($o['cert']);
        }

        $dsig->appendSignature($element);
    }

    /**
     * An identity provider's metadata document.
     *
     * Options: entityId, signingCerts (use="signing"), untypedCerts (no use attribute), encryptionCerts, services (list of
     * [binding, location]), extra (raw XML inside IDPSSODescriptor).
     *
     * @param  array<string, mixed>  $options
     */
    public static function idpMetadata(array $options = []): string
    {
        $o = array_replace([
            'entityId' => self::IDP_ENTITY,
            'signingCerts' => [self::cert('idp')],
            'untypedCerts' => [],
            'encryptionCerts' => [],
            'services' => [[self::BINDING_POST, self::IDP_SSO.'/post'], [self::BINDING_REDIRECT, self::IDP_SSO.'/redirect']],
            'extra' => '',
        ], $options);

        $keys = '';

        foreach ([['signing', $o['signingCerts']], ['encryption', $o['encryptionCerts']], [null, $o['untypedCerts']]] as [$use, $certs]) {
            foreach ($certs as $cert) {
                $keys .= '<md:KeyDescriptor'.($use === null ? '' : ' use="'.$use.'"').'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'
                    .self::wrappedBody($cert).'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>';
            }
        }

        $services = '';

        foreach ($o['services'] as [$binding, $location]) {
            $services .= '<md:SingleSignOnService Binding="'.self::esc($binding).'" Location="'.self::esc($location).'"/>';
        }

        return '<?xml version="1.0" encoding="UTF-8"?>'
            .'<md:EntityDescriptor xmlns:md="'.self::NS_METADATA.'" xmlns:ds="'.self::NS_DSIG.'" entityID="'.self::esc($o['entityId']).'">'
            .'<md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="'.self::NS_PROTOCOL.'">'
            .$keys
            .'<md:SingleLogoutService Binding="'.self::BINDING_REDIRECT.'" Location="https://idp.example.com/slo"/>'
            .'<md:NameIDFormat>'.self::EMAIL_FORMAT.'</md:NameIDFormat>'
            .$services.$o['extra']
            .'</md:IDPSSODescriptor></md:EntityDescriptor>';
    }

    /**
     * The base64 body of a PEM certificate, on indented lines the way metadata files carry it.
     */
    public static function wrappedBody(string $pem): string
    {
        $body = (string) preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', $pem);

        return "\n        ".implode("\n        ", str_split($body, 76))."\n      ";
    }

    private static function attr(string $name, ?string $value): string
    {
        return $value === null ? '' : ' '.$name.'="'.self::esc($value).'"';
    }

    private static function esc(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_XML1, 'UTF-8');
    }
}
