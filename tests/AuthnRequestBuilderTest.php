<?php

use Akcybex\LaravelSaml\Protocol\AuthnRequest;
use Akcybex\LaravelSaml\Protocol\AuthnRequestBuilder;
use Akcybex\LaravelSaml\Saml;
use Akcybex\LaravelSaml\Tests\Support\SamlFixtures as Fx;
use Akcybex\LaravelSaml\Xml\SafeXml;

/**
 * Splits a redirect URL into its raw (still url-encoded) query parameters, in order.
 *
 * @return array<string, string>
 */
$rawQuery = function (string $url): array {
    $query = (string) parse_url($url, PHP_URL_QUERY);
    $params = [];

    foreach (explode('&', $query) as $pair) {
        [$name, $value] = array_pad(explode('=', $pair, 2), 2, '');
        $params[$name] = $value;
    }

    return $params;
};

$inflate = function (string $url) use ($rawQuery): string {
    $encoded = $rawQuery($url)['SAMLRequest'];
    $xml = gzinflate((string) base64_decode(urldecode($encoded), true));

    expect($xml)->toBeString();

    return $xml;
};

it('builds a redirect URL on the identity provider\'s sign-in address', function () {
    $request = (new AuthnRequestBuilder)->build(Fx::sp(), Fx::idp());

    expect($request)->toBeInstanceOf(AuthnRequest::class)
        ->and($request->redirectUrl)->toStartWith(Fx::IDP_SSO.'?SAMLRequest=');
});

it('puts a well-formed AuthnRequest in the SAMLRequest parameter, raw-deflated and base64-encoded', function () use ($inflate) {
    $now = Fx::now();
    $request = (new AuthnRequestBuilder)->build(Fx::sp(), Fx::idp(), null, $now);

    $document = SafeXml::load($inflate($request->redirectUrl));
    $xpath = Fx::xpath($document);
    $root = $document->documentElement;

    expect($root->localName)->toBe('AuthnRequest')
        ->and($root->namespaceURI)->toBe(Fx::NS_PROTOCOL)
        ->and($root->getAttribute('Version'))->toBe('2.0')
        ->and($root->getAttribute('ID'))->toBe($request->id)
        ->and($root->getAttribute('IssueInstant'))->toBe('2026-01-15T12:00:00Z')
        ->and($root->getAttribute('Destination'))->toBe(Fx::IDP_SSO)
        ->and($root->getAttribute('AssertionConsumerServiceURL'))->toBe(Fx::ACS)
        ->and($root->getAttribute('ProtocolBinding'))->toBe(Fx::BINDING_POST)
        ->and($xpath->evaluate('string(/samlp:AuthnRequest/saml:Issuer)'))->toBe(Fx::SP_ENTITY)
        ->and($xpath->evaluate('string(/samlp:AuthnRequest/samlp:NameIDPolicy/@Format)'))->toBe(Fx::EMAIL_FORMAT);
});

it('uses the NameID format of the service provider settings', function () use ($inflate) {
    $sp = new Akcybex\LaravelSaml\ServiceProviderSettings(Fx::SP_ENTITY, Fx::ACS, null, null, 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent');

    $request = (new AuthnRequestBuilder)->build($sp, Fx::idp());
    $xpath = Fx::xpath(SafeXml::load($inflate($request->redirectUrl)));

    expect($xpath->evaluate('string(//samlp:NameIDPolicy/@Format)'))->toBe('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent');
});

it('gives each request a new id that is a valid XML name', function () {
    $builder = new AuthnRequestBuilder;
    $first = $builder->build(Fx::sp(), Fx::idp());
    $second = $builder->build(Fx::sp(), Fx::idp());

    expect($first->id)->toMatch('/^_[0-9a-f]{40}$/')
        ->and($second->id)->not->toBe($first->id);
});

it('url-encodes the RelayState', function () use ($rawQuery) {
    $relay = 'https://app.example.com/dashboard?tab=a b&x=1#top';
    $request = (new AuthnRequestBuilder)->build(Fx::sp(), Fx::idp(), $relay);

    $params = $rawQuery($request->redirectUrl);

    expect($params['RelayState'])->toBe(rawurlencode($relay))
        ->and(rawurldecode($params['RelayState']))->toBe($relay);

    parse_str((string) parse_url($request->redirectUrl, PHP_URL_QUERY), $parsed);

    expect($parsed['RelayState'])->toBe($relay);
});

it('leaves the RelayState out when there is none', function (?string $relay) {
    $request = (new AuthnRequestBuilder)->build(Fx::sp(), Fx::idp(), $relay);

    expect($request->redirectUrl)->not->toContain('RelayState');
})->with(['null' => null, 'empty' => '']);

it('continues an existing query string with an ampersand', function () {
    $idp = Fx::idp(null, Fx::IDP_ENTITY, 'https://idp.example.com/sso?tenant=acme');

    $request = (new AuthnRequestBuilder)->build(Fx::sp(), $idp);

    expect($request->redirectUrl)->toStartWith('https://idp.example.com/sso?tenant=acme&SAMLRequest=')
        ->and(substr_count($request->redirectUrl, '?'))->toBe(1);
});

it('starts a query string with a question mark when there is none', function () {
    $request = (new AuthnRequestBuilder)->build(Fx::sp(), Fx::idp());

    expect(substr_count($request->redirectUrl, '?'))->toBe(1)
        ->and($request->redirectUrl)->toContain(Fx::IDP_SSO.'?SAMLRequest=');
});

it('does not sign the request without a private key', function () {
    $request = (new AuthnRequestBuilder)->build(Fx::sp(false), Fx::idp(), 'state');

    expect($request->redirectUrl)->not->toContain('Signature')
        ->and($request->redirectUrl)->not->toContain('SigAlg');
});

it('signs the exact query string with the service provider key', function () use ($rawQuery) {
    $request = (new AuthnRequestBuilder)->build(Fx::sp(true), Fx::idp(), 'state value/1');

    $query = (string) parse_url($request->redirectUrl, PHP_URL_QUERY);
    $params = $rawQuery($request->redirectUrl);

    expect(array_keys($params))->toBe(['SAMLRequest', 'RelayState', 'SigAlg', 'Signature'])
        ->and(urldecode($params['SigAlg']))->toBe('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');

    $signed = substr($query, 0, (int) strrpos($query, '&Signature='));
    $signature = base64_decode(urldecode($params['Signature']), true);

    expect($signature)->toBeString()
        ->and(openssl_verify($signed, $signature, Fx::cert('sp'), OPENSSL_ALGO_SHA256))->toBe(1)
        ->and(openssl_verify($signed.'x', $signature, Fx::cert('sp'), OPENSSL_ALGO_SHA256))->toBe(0)
        ->and(openssl_verify($signed, $signature, Fx::cert('attacker'), OPENSSL_ALGO_SHA256))->toBe(0);
});

it('signs a request that has no RelayState', function () use ($rawQuery) {
    $request = (new AuthnRequestBuilder)->build(Fx::sp(true), Fx::idp());

    $query = (string) parse_url($request->redirectUrl, PHP_URL_QUERY);
    $params = $rawQuery($request->redirectUrl);

    expect(array_keys($params))->toBe(['SAMLRequest', 'SigAlg', 'Signature']);

    $signed = substr($query, 0, (int) strrpos($query, '&Signature='));

    expect(openssl_verify($signed, (string) base64_decode(urldecode($params['Signature']), true), Fx::cert('sp'), OPENSSL_ALGO_SHA256))->toBe(1);
});

it('escapes XML special characters in the URLs and the entity id', function () use ($inflate) {
    $entityId = 'https://sp.example.com/a&b"<c>\'d';
    $acs = 'https://sp.example.com/acs?x=1&y="2"&z=<3>';
    $sso = 'https://idp.example.com/sso?a=1&b=<2>';

    $request = (new AuthnRequestBuilder)->build(Fx::sp(false, $entityId, $acs), Fx::idp(null, Fx::IDP_ENTITY, $sso));

    $document = SafeXml::load($inflate($request->redirectUrl));
    $root = $document->documentElement;
    $xpath = Fx::xpath($document);

    expect($root->getAttribute('Destination'))->toBe($sso)
        ->and($root->getAttribute('AssertionConsumerServiceURL'))->toBe($acs)
        ->and($xpath->evaluate('string(/samlp:AuthnRequest/saml:Issuer)'))->toBe($entityId)
        ->and($root->getElementsByTagNameNS(Fx::NS_ASSERTION, 'Issuer')->length)->toBe(1);
});

it('is the request the Saml entry point returns', function () use ($inflate) {
    $request = app(Saml::class)->authnRequest(Fx::sp(), Fx::idp(), 'state');

    $root = SafeXml::load($inflate($request->redirectUrl))->documentElement;

    expect($root->getAttribute('ID'))->toBe($request->id);
});
