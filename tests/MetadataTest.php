<?php

use Akcybex\LaravelSaml\Exceptions\SamlException;
use Akcybex\LaravelSaml\Metadata\IdpMetadataParser;
use Akcybex\LaravelSaml\Metadata\SpMetadata;
use Akcybex\LaravelSaml\Saml;
use Akcybex\LaravelSaml\Tests\Support\SamlFixtures as Fx;
use Akcybex\LaravelSaml\Xml\SafeXml;

// ---------------------------------------------------------------------------------------------------------------------------
// Service provider metadata
// ---------------------------------------------------------------------------------------------------------------------------

it('describes the service provider: entity id, POST assertion consumer service, name id format', function () {
    $document = SafeXml::load(SpMetadata::xml(Fx::sp()));
    $xpath = Fx::xpath($document);

    expect($document->documentElement->localName)->toBe('EntityDescriptor')
        ->and($document->documentElement->getAttribute('entityID'))->toBe(Fx::SP_ENTITY)
        ->and($xpath->query('/md:EntityDescriptor/md:SPSSODescriptor')->length)->toBe(1)
        ->and($xpath->evaluate('string(//md:SPSSODescriptor/@protocolSupportEnumeration)'))->toBe(Fx::NS_PROTOCOL)
        ->and($xpath->evaluate('string(//md:SPSSODescriptor/@WantAssertionsSigned)'))->toBe('true')
        ->and($xpath->evaluate('string(//md:NameIDFormat)'))->toBe(Fx::EMAIL_FORMAT);

    $acs = $xpath->query('//md:AssertionConsumerService');

    expect($acs->length)->toBe(1)
        ->and($acs->item(0)->getAttribute('Binding'))->toBe(Fx::BINDING_POST)
        ->and($acs->item(0)->getAttribute('Location'))->toBe(Fx::ACS)
        ->and($acs->item(0)->getAttribute('index'))->toBe('0');
});

it('says AuthnRequestsSigned is false without a private key', function () {
    $xpath = Fx::xpath(SafeXml::load(SpMetadata::xml(Fx::sp(false))));

    expect($xpath->evaluate('string(//md:SPSSODescriptor/@AuthnRequestsSigned)'))->toBe('false');
});

it('says AuthnRequestsSigned is true with a private key', function () {
    $xpath = Fx::xpath(SafeXml::load(SpMetadata::xml(Fx::sp(true))));

    expect($xpath->evaluate('string(//md:SPSSODescriptor/@AuthnRequestsSigned)'))->toBe('true');
});

it('publishes the certificate body, without the PEM lines and whitespace', function () {
    $xpath = Fx::xpath(SafeXml::load(SpMetadata::xml(Fx::sp(true))));

    $key = $xpath->query('//md:KeyDescriptor');
    $body = $xpath->evaluate('string(//md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate)');

    expect($key->length)->toBe(1)
        ->and($key->item(0)->getAttribute('use'))->toBe('signing')
        ->and($body)->toBe(SpMetadata::certificateBody(Fx::cert('sp')))
        ->and($body)->not->toContain('BEGIN')
        ->and($body)->not->toMatch('/\s/')
        ->and(base64_decode($body, true))->not->toBeFalse();
});

it('has no KeyDescriptor when no certificate is given', function () {
    $xpath = Fx::xpath(SafeXml::load(SpMetadata::xml(Fx::sp(false))));

    expect($xpath->query('//md:KeyDescriptor')->length)->toBe(0);
});

it('reduces a PEM certificate to its base64 body', function () {
    $pem = "-----BEGIN CERTIFICATE-----\nAAAA\nBBBB\n-----END CERTIFICATE-----\n";

    expect(SpMetadata::certificateBody($pem))->toBe('AAAABBBB');
});

it('escapes special characters in the entity id and the assertion consumer service URL', function () {
    $entityId = 'https://sp.example.com/a&b"<c>\'d';
    $acs = 'https://sp.example.com/acs?x=1&y="2"';

    $xpath = Fx::xpath(SafeXml::load(SpMetadata::xml(Fx::sp(false, $entityId, $acs))));

    expect($xpath->evaluate('string(/md:EntityDescriptor/@entityID)'))->toBe($entityId)
        ->and($xpath->evaluate('string(//md:AssertionConsumerService/@Location)'))->toBe($acs);
});

it('is what the Saml entry point returns as metadata', function () {
    $sp = Fx::sp(true);

    expect(app(Saml::class)->metadata($sp))->toBe(SpMetadata::xml($sp));
});

// ---------------------------------------------------------------------------------------------------------------------------
// Identity provider metadata
// ---------------------------------------------------------------------------------------------------------------------------

it('reads a typical single identity provider', function () {
    $idp = IdpMetadataParser::parse(Fx::idpMetadata());

    expect($idp->entityId)->toBe(Fx::IDP_ENTITY)
        ->and($idp->singleSignOnUrl)->toBe(Fx::IDP_SSO.'/redirect')
        ->and($idp->certificates)->toHaveCount(1)
        ->and($idp->certificates[0])->toBe(rtrim(Fx::cert('idp')));
});

it('prefers the Redirect binding whichever order the sign-in services come in', function (array $services) {
    $idp = IdpMetadataParser::parse(Fx::idpMetadata(['services' => $services]));

    expect($idp->singleSignOnUrl)->toBe('https://idp.example.com/sso/redirect');
})->with([
    'post first' => [[[Fx::BINDING_POST, 'https://idp.example.com/sso/post'], [Fx::BINDING_REDIRECT, 'https://idp.example.com/sso/redirect']]],
    'redirect first' => [[[Fx::BINDING_REDIRECT, 'https://idp.example.com/sso/redirect'], [Fx::BINDING_POST, 'https://idp.example.com/sso/post']]],
]);

it('refuses a provider whose only sign-in service is not the Redirect binding', function () {
    expect(fn () => IdpMetadataParser::parse(Fx::idpMetadata(['services' => [[Fx::BINDING_POST, 'https://idp.example.com/sso/post']]])))
        ->toThrow(SamlException::class, 'no SingleSignOnService');
});

it('returns every signing certificate as a PEM with 64-character lines', function () {
    $idp = IdpMetadataParser::parse(Fx::idpMetadata(['signingCerts' => [Fx::cert('idp'), Fx::cert('attacker')]]));

    expect($idp->certificates)->toHaveCount(2);

    foreach ($idp->certificates as $pem) {
        $lines = explode("\n", $pem);

        expect($lines[0])->toBe('-----BEGIN CERTIFICATE-----')
            ->and(end($lines))->toBe('-----END CERTIFICATE-----')
            ->and(openssl_x509_read($pem))->not->toBeFalse();

        $body = array_slice($lines, 1, -1);

        foreach (array_slice($body, 0, -1) as $line) {
            expect(strlen($line))->toBe(64);
        }

        expect(strlen(end($body)))->toBeLessThanOrEqual(64)->toBeGreaterThan(0);
    }

    expect($idp->certificates[0])->toBe(rtrim(Fx::cert('idp')))
        ->and($idp->certificates[1])->toBe(rtrim(Fx::cert('attacker')));
});

it('ignores a KeyDescriptor that is for encryption', function () {
    $idp = IdpMetadataParser::parse(Fx::idpMetadata(['signingCerts' => [Fx::cert('idp')], 'encryptionCerts' => [Fx::cert('attacker')]]));

    expect($idp->certificates)->toBe([rtrim(Fx::cert('idp'))]);
});

it('counts a KeyDescriptor with no use as a signing certificate', function () {
    $idp = IdpMetadataParser::parse(Fx::idpMetadata(['signingCerts' => [], 'untypedCerts' => [Fx::cert('idp')]]));

    expect($idp->certificates)->toBe([rtrim(Fx::cert('idp'))]);
});

it('lists a certificate once even when the metadata repeats it', function () {
    $idp = IdpMetadataParser::parse(Fx::idpMetadata(['signingCerts' => [Fx::cert('idp')], 'untypedCerts' => [Fx::cert('idp')]]));

    expect($idp->certificates)->toHaveCount(1);
});

it('gives settings that verify a real answer', function () {
    $idp = IdpMetadataParser::parse(Fx::idpMetadata());

    $assertion = app(Saml::class)->validate(
        Fx::response(['at' => new DateTimeImmutable('now', new DateTimeZone('UTC'))]),
        Fx::sp(),
        $idp,
        Fx::REQUEST_ID,
    );

    expect($assertion->nameId)->toBe('alice@example.com');
});

it('refuses a federation file that lists many providers', function () {
    $one = Fx::idpMetadata();
    $inner = (string) preg_replace('/^<\?xml[^>]*\?>/', '', $one);

    $federation = '<?xml version="1.0"?><md:EntitiesDescriptor xmlns:md="'.Fx::NS_METADATA.'">'.$inner.$inner.'</md:EntitiesDescriptor>';

    expect(fn () => IdpMetadataParser::parse($federation))->toThrow(SamlException::class, 'single EntityDescriptor');
});

it('refuses metadata without an entityID', function () {
    $xml = str_replace('entityID="'.Fx::IDP_ENTITY.'"', '', Fx::idpMetadata());

    expect(fn () => IdpMetadataParser::parse($xml))->toThrow(SamlException::class, 'single EntityDescriptor');
});

it('refuses a document that is not metadata', function () {
    expect(fn () => IdpMetadataParser::parse('<html/>'))->toThrow(SamlException::class, 'single EntityDescriptor');
});

it('refuses metadata with no sign-in service', function () {
    expect(fn () => IdpMetadataParser::parse(Fx::idpMetadata(['services' => []])))->toThrow(SamlException::class, 'no SingleSignOnService');
});

it('refuses a sign-in service with no location', function () {
    expect(fn () => IdpMetadataParser::parse(Fx::idpMetadata(['services' => [[Fx::BINDING_REDIRECT, '']]])))->toThrow(SamlException::class, 'no SingleSignOnService');
});

it('refuses metadata with no signing certificate', function () {
    expect(fn () => IdpMetadataParser::parse(Fx::idpMetadata(['signingCerts' => []])))->toThrow(SamlException::class, 'no signing certificate');
});

it('refuses metadata whose only certificate is for encryption', function () {
    $xml = Fx::idpMetadata(['signingCerts' => [], 'encryptionCerts' => [Fx::cert('idp')]]);

    expect(fn () => IdpMetadataParser::parse($xml))->toThrow(SamlException::class, 'no signing certificate');
});

it('refuses a certificate element that is empty', function () {
    $xml = Fx::idpMetadata(['signingCerts' => ['  ']]);

    expect(fn () => IdpMetadataParser::parse($xml))->toThrow(SamlException::class, 'no signing certificate');
});

it('refuses metadata with a DOCTYPE', function () {
    $xml = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        .(string) preg_replace('/^<\?xml[^>]*\?>/', '', Fx::idpMetadata());

    expect(fn () => IdpMetadataParser::parse($xml))->toThrow(SamlException::class, 'document type declaration');
});

it('refuses metadata that is not well formed', function () {
    expect(fn () => IdpMetadataParser::parse('<md:EntityDescriptor'))->toThrow(SamlException::class);
});
