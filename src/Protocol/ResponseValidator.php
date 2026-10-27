<?php

namespace Akcybex\LaravelSaml\Protocol;

use Akcybex\LaravelSaml\Assertion;
use Akcybex\LaravelSaml\Exceptions\SamlException;
use Akcybex\LaravelSaml\IdentityProviderSettings;
use Akcybex\LaravelSaml\ServiceProviderSettings;
use Akcybex\LaravelSaml\Support\ReplayStore;
use Akcybex\LaravelSaml\Xml\SafeXml;
use DateTimeImmutable;
use DateTimeZone;
use DOMDocument;
use DOMElement;
use DOMNode;
use DOMXPath;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Throwable;

/**
 * Validates a SAML Response received at the assertion consumer service (HTTP-POST binding) and returns what it asserts.
 *
 * What this refuses, and why it is shaped the way it is:
 *
 *  - Unsigned answers: the Response, the Assertion or both must carry an enveloped signature that verifies with one of the identity
 *    provider's configured certificates. A certificate inside the message is never used.
 *  - Signature wrapping: exactly one Assertion in the whole document, no duplicate ID values, and each Signature must reference
 *    (by `#ID`, with the enveloped and exclusive-c14n transforms only) the element that contains it. Data is read only from that
 *    Assertion, which is covered by a verified signature, directly or through the signed Response.
 *  - Weak or odd algorithms: only RSA with SHA-256/384/512 (SHA-1 only when allowed) and exclusive c14n without comments.
 *  - Wrong audience, issuer, destination or recipient; an expired or not-yet-valid assertion; an answer to a request the caller does
 *    not know (InResponseTo), or no request at all (IdP-initiated) unless the caller opts in; a replayed assertion.
 *  - Encrypted assertions (not supported: an unsigned-looking answer is refused, not guessed at).
 *  - Anything with a DOCTYPE (SafeXml).
 */
final class ResponseValidator
{
    private const NS_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

    private const NS_ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    private const STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

    private const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';

    private const SIGNATURE_ALGORITHMS = [
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' => XMLSecurityKey::RSA_SHA256,
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384' => XMLSecurityKey::RSA_SHA384,
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' => XMLSecurityKey::RSA_SHA512,
    ];

    private const DIGEST_ALGORITHMS = [
        'http://www.w3.org/2001/04/xmlenc#sha256',
        'http://www.w3.org/2001/04/xmldsig-more#sha384',
        'http://www.w3.org/2001/04/xmlenc#sha512',
    ];

    private const SHA1_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';

    private const SHA1_DIGEST = 'http://www.w3.org/2000/09/xmldsig#sha1';

    private const CANONICALIZATION = ['http://www.w3.org/2001/10/xml-exc-c14n#'];

    private const TRANSFORMS = [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
    ];

    /**
     * @param  int  $clockSkewSeconds  tolerance for clock differences between the two servers
     * @param  bool  $allowSha1  accept RSA-SHA1 signatures and SHA-1 digests (older identity providers); off by default
     * @param  bool  $allowIdpInitiated  accept an answer to no request of ours (IdP-initiated); off by default
     */
    public function __construct(
        private readonly ReplayStore $replay,
        private readonly int $clockSkewSeconds = 120,
        private readonly bool $allowSha1 = false,
        private readonly bool $allowIdpInitiated = false,
    ) {}

    /**
     * @param  string|null  $expectedRequestId  the id of the AuthnRequest this answer must respond to (kept by the caller)
     *
     * @throws SamlException
     */
    public function validate(string $samlResponse, ServiceProviderSettings $sp, IdentityProviderSettings $idp, ?string $expectedRequestId, ?DateTimeImmutable $now = null): Assertion
    {
        $now ??= new DateTimeImmutable('now', new DateTimeZone('UTC'));

        // Bounded before it is decoded: the base64 form is a third larger than the XML it carries.
        if (strlen($samlResponse) > intdiv(SafeXml::MAX_BYTES * 4, 3) + 4) {
            throw new SamlException('The SAMLResponse is too large.');
        }

        $decoded = base64_decode($samlResponse, true);

        if ($decoded === false) {
            throw new SamlException('The SAMLResponse is not valid base64.');
        }

        $document = SafeXml::load($decoded);
        $xpath = $this->xpath($document);

        $response = $document->documentElement;

        if (! $response instanceof DOMElement || $response->localName !== 'Response' || $response->namespaceURI !== self::NS_PROTOCOL) {
            throw new SamlException('The message is not a SAML Response.');
        }

        if ($xpath->query('//saml:EncryptedAssertion')?->length) {
            throw new SamlException('Encrypted assertions are not supported.');
        }

        $this->assertStructure($document, $xpath, $response);

        $assertion = $this->single($xpath, './saml:Assertion', $response);

        if (! $assertion instanceof DOMElement) {
            throw new SamlException('The Response has no Assertion.');
        }

        // Signatures first: nothing below reads a value from a message that is not proven to come from the identity provider. Order matters:
        // the Response's signature is checked before the Assertion's, because checking a signature takes it out of the document, and the
        // Response's digest covers the Assertion's signature.
        $signed = false;

        foreach ([$response, $assertion] as $element) {
            $signature = $this->single($xpath, './ds:Signature', $element);

            if ($signature instanceof DOMElement) {
                $this->verifySignature($signature, $element, $idp);
                $signed = true;
            }
        }

        if (! $signed) {
            throw new SamlException('The Response and its Assertion are not signed.');
        }

        $this->checkResponse($xpath, $response, $sp, $idp, $expectedRequestId);

        return $this->readAssertion($xpath, $assertion, $sp, $idp, $expectedRequestId, $now);
    }

    /**
     * One Assertion in the whole document, one ID per element, and nothing that could carry a second copy of either.
     *
     * @throws SamlException
     */
    private function assertStructure(DOMDocument $document, DOMXPath $xpath, DOMElement $response): void
    {
        $assertions = $xpath->query('//saml:Assertion');

        if ($assertions === false || $assertions->length !== 1) {
            throw new SamlException('The message must contain exactly one Assertion.');
        }

        if ($assertions->item(0)?->parentNode !== $response) {
            throw new SamlException('The Assertion is not a direct child of the Response.');
        }

        $seen = [];

        foreach ($xpath->query('//*[@ID]') ?: [] as $element) {
            if (! $element instanceof DOMElement) {
                continue;
            }

            $id = $element->getAttribute('ID');

            // An ID is an XML name: nothing else is ever looked up by an expression built from it.
            if (preg_match('/^[A-Za-z_][A-Za-z0-9_.-]{0,255}$/', $id) !== 1) {
                throw new SamlException('The message has an ID that is not a valid name.');
            }

            if (isset($seen[$id])) {
                throw new SamlException('The message uses the same ID twice.');
            }

            $seen[$id] = true;
        }
    }

    /**
     * Verifies the enveloped signature inside $signed, which must be a direct child and must sign that very element.
     *
     * @throws SamlException
     */
    private function verifySignature(DOMElement $signature, DOMElement $signed, IdentityProviderSettings $idp): void
    {
        $id = $signed->getAttribute('ID');

        if ($id === '') {
            throw new SamlException('A signed element has no ID.');
        }

        $xpath = $this->xpath($signature->ownerDocument);

        $c14n = $xpath->evaluate('string(./ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm)', $signature);
        $method = $xpath->evaluate('string(./ds:SignedInfo/ds:SignatureMethod/@Algorithm)', $signature);
        $references = $xpath->query('./ds:SignedInfo/ds:Reference', $signature);

        $allowed = self::SIGNATURE_ALGORITHMS;

        if ($this->allowSha1) {
            $allowed[self::SHA1_SIGNATURE] = XMLSecurityKey::RSA_SHA1;
        }

        if (! in_array($c14n, self::CANONICALIZATION, true)) {
            throw new SamlException('The signature uses a canonicalization method that is not accepted.');
        }

        if (! is_string($method) || ! isset($allowed[$method])) {
            throw new SamlException('The signature algorithm is not accepted.');
        }

        if ($references === false || $references->length !== 1) {
            throw new SamlException('A signature must have exactly one Reference.');
        }

        $reference = $references->item(0);
        $digests = self::DIGEST_ALGORITHMS;

        if ($this->allowSha1) {
            $digests[] = self::SHA1_DIGEST;
        }

        if (! $reference instanceof DOMElement || $reference->getAttribute('URI') !== '#'.$id) {
            throw new SamlException('The signature does not reference the element it is in.');
        }

        if (! in_array($xpath->evaluate('string(./ds:DigestMethod/@Algorithm)', $reference), $digests, true)) {
            throw new SamlException('The digest algorithm is not accepted.');
        }

        $enveloped = false;

        foreach ($xpath->query('./ds:Transforms/ds:Transform', $reference) ?: [] as $transform) {
            if (! $transform instanceof DOMElement || ! in_array($transform->getAttribute('Algorithm'), self::TRANSFORMS, true)) {
                throw new SamlException('The signature uses a transform that is not accepted.');
            }

            $enveloped = $enveloped || $transform->getAttribute('Algorithm') === 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
        }

        if (! $enveloped) {
            throw new SamlException('The signature is not an enveloped signature.');
        }

        foreach ($idp->certificates as $certificate) {
            $copy = $this->freshCopy($signature, $signed);

            if ($copy === null) {
                break;
            }

            [$dsig, $parent] = $copy;

            try {
                $dsig->idKeys = ['ID'];
                $dsig->canonicalizeSignedInfo();

                if ($dsig->validateReference() !== true) {
                    throw new SamlException('The digest of the signed element does not match.');
                }

                $validated = $dsig->getValidatedNodes();
                $covers = false;

                foreach ($validated as $node) {
                    if ($node instanceof DOMNode && $node->isSameNode($parent)) {
                        $covers = true;
                    }
                }

                if (! $covers) {
                    throw new SamlException('The signature does not cover the element it is in.');
                }

                $key = $dsig->locateKey();

                if (! $key instanceof XMLSecurityKey) {
                    continue;
                }

                $key->loadKey($certificate, false, true);

                if ($dsig->verify($key) === 1) {
                    // The real document is read afterwards: take the verified signature out of it too, as the check did in its copy.
                    $signature->parentNode?->removeChild($signature);

                    return;
                }
            } catch (SamlException $e) {
                throw $e;
            } catch (Throwable) {
                // This certificate did not verify it (or the digest did not match): try the next, and refuse below if none does.
                continue;
            }
        }

        throw new SamlException('The signature could not be verified with the identity provider\'s certificate.');
    }

    /**
     * Checking a signature takes it out of the document, so each attempt works on its own copy of the document and the real one is
     * left alone until a certificate has verified.
     *
     * @return array{XMLSecurityDSig, DOMElement}|null
     */
    private function freshCopy(DOMElement $signature, DOMElement $signed): ?array
    {
        $copy = new DOMDocument;
        $copy->preserveWhiteSpace = true;

        $root = $signature->ownerDocument->documentElement;

        if ($root === null) {
            return null;
        }

        $copy->appendChild($copy->importNode($root, true));

        $xpath = $this->xpath($copy);

        // The element that carries the signature in the copy: the Response itself, or its one Assertion.
        $parent = $signed->isSameNode($root) ? $copy->documentElement : $this->single($xpath, './saml:Assertion', $copy->documentElement);
        $sigNode = $parent instanceof DOMElement ? $this->single($xpath, './ds:Signature', $parent) : null;

        if (! $parent instanceof DOMElement || ! $sigNode instanceof DOMElement) {
            return null;
        }

        $dsig = new XMLSecurityDSig;
        $dsig->sigNode = $sigNode;

        return [$dsig, $parent];
    }

    /**
     * @throws SamlException
     */
    private function checkResponse(DOMXPath $xpath, DOMElement $response, ServiceProviderSettings $sp, IdentityProviderSettings $idp, ?string $expectedRequestId): void
    {
        if ($response->getAttribute('Version') !== '2.0') {
            throw new SamlException('The Response is not SAML 2.0.');
        }

        if ($response->getAttribute('Destination') !== $sp->assertionConsumerServiceUrl) {
            throw new SamlException('The Response was not addressed to this service.');
        }

        $status = $xpath->evaluate('string(./samlp:Status/samlp:StatusCode/@Value)', $response);

        if ($status !== self::STATUS_SUCCESS) {
            throw new SamlException('The identity provider did not report success.');
        }

        $issuer = $xpath->evaluate('string(./saml:Issuer)', $response);

        if ($issuer !== '' && trim($issuer) !== $idp->entityId) {
            throw new SamlException('The Response comes from a different issuer.');
        }

        $this->checkInResponseTo($response->getAttribute('InResponseTo'), $expectedRequestId, 'Response');
    }

    /**
     * @throws SamlException
     */
    private function checkInResponseTo(string $actual, ?string $expected, string $where): void
    {
        if ($expected === null) {
            if (! $this->allowIdpInitiated) {
                throw new SamlException('There is no pending sign-in request, and answers to no request are not accepted.');
            }

            return;
        }

        if ($actual === '' || ! hash_equals($expected, $actual)) {
            throw new SamlException("The {$where} answers a different request than the one this browser started.");
        }
    }

    /**
     * Reads the Assertion (already covered by a verified signature) and checks every condition it states.
     *
     * @throws SamlException
     */
    private function readAssertion(DOMXPath $xpath, DOMElement $assertion, ServiceProviderSettings $sp, IdentityProviderSettings $idp, ?string $expectedRequestId, DateTimeImmutable $now): Assertion
    {
        $skew = $this->clockSkewSeconds;

        if ($assertion->getAttribute('Version') !== '2.0') {
            throw new SamlException('The Assertion is not SAML 2.0.');
        }

        if (trim($xpath->evaluate('string(./saml:Issuer)', $assertion)) !== $idp->entityId) {
            throw new SamlException('The Assertion comes from a different issuer.');
        }

        $issued = $this->instant($assertion->getAttribute('IssueInstant'), 'IssueInstant');

        if ($issued->getTimestamp() > $now->getTimestamp() + $skew) {
            throw new SamlException('The Assertion was issued in the future.');
        }

        $nameIdNode = $this->single($xpath, './saml:Subject/saml:NameID', $assertion);
        $nameId = $nameIdNode instanceof DOMElement ? trim($nameIdNode->textContent) : '';

        if ($nameId === '' || strlen($nameId) > 512) {
            throw new SamlException('The Assertion has no usable NameID.');
        }

        $notOnOrAfter = $this->confirmSubject($xpath, $assertion, $sp, $expectedRequestId, $now);

        $conditions = $this->single($xpath, './saml:Conditions', $assertion);

        if (! $conditions instanceof DOMElement) {
            throw new SamlException('The Assertion has no Conditions.');
        }

        $this->checkConditions($xpath, $conditions, $sp, $now);

        $id = $assertion->getAttribute('ID');

        // Scoped by issuer: one identity provider cannot use up another's assertion ids.
        if (! $this->replay->remember($idp->entityId.'|'.$id, $notOnOrAfter)) {
            throw new SamlException('This Assertion was already used.');
        }

        // More than one AuthnStatement is legal; the first one's session index is the one kept.
        $authn = $xpath->query('./saml:AuthnStatement', $assertion)?->item(0);
        $sessionIndex = $authn instanceof DOMElement && $authn->getAttribute('SessionIndex') !== '' ? $authn->getAttribute('SessionIndex') : null;

        $attributes = [];

        foreach ($xpath->query('./saml:AttributeStatement/saml:Attribute', $assertion) ?: [] as $attribute) {
            if (! $attribute instanceof DOMElement || $attribute->getAttribute('Name') === '') {
                continue;
            }

            foreach ($xpath->query('./saml:AttributeValue', $attribute) ?: [] as $value) {
                $attributes[$attribute->getAttribute('Name')][] = trim($value->textContent);
            }
        }

        return new Assertion(
            $id,
            $idp->entityId,
            $nameId,
            $nameIdNode->getAttribute('Format') !== '' ? $nameIdNode->getAttribute('Format') : null,
            $sessionIndex,
            $expectedRequestId,
            $notOnOrAfter,
            $attributes,
        );
    }

    /**
     * At least one bearer confirmation that is for this service, this request and still valid. Returns when it stops being valid.
     *
     * @throws SamlException
     */
    private function confirmSubject(DOMXPath $xpath, DOMElement $assertion, ServiceProviderSettings $sp, ?string $expectedRequestId, DateTimeImmutable $now): DateTimeImmutable
    {
        $skew = $this->clockSkewSeconds;

        foreach ($xpath->query('./saml:Subject/saml:SubjectConfirmation', $assertion) ?: [] as $confirmation) {
            if (! $confirmation instanceof DOMElement || $confirmation->getAttribute('Method') !== self::BEARER) {
                continue;
            }

            $data = $this->single($xpath, './saml:SubjectConfirmationData', $confirmation);

            if (! $data instanceof DOMElement || $data->getAttribute('Recipient') !== $sp->assertionConsumerServiceUrl || $data->getAttribute('NotOnOrAfter') === '') {
                continue;
            }

            $until = $this->instant($data->getAttribute('NotOnOrAfter'), 'NotOnOrAfter');

            if ($until->getTimestamp() + $skew <= $now->getTimestamp()) {
                continue;
            }

            if ($data->getAttribute('NotBefore') !== '' && $this->instant($data->getAttribute('NotBefore'), 'NotBefore')->getTimestamp() > $now->getTimestamp() + $skew) {
                continue;
            }

            $this->checkInResponseTo($data->getAttribute('InResponseTo'), $expectedRequestId, 'Assertion');

            return $until;
        }

        throw new SamlException('The Assertion has no valid bearer confirmation for this service.');
    }

    /**
     * @throws SamlException
     */
    private function checkConditions(DOMXPath $xpath, DOMElement $conditions, ServiceProviderSettings $sp, DateTimeImmutable $now): void
    {
        $skew = $this->clockSkewSeconds;

        if ($conditions->getAttribute('NotOnOrAfter') === '') {
            throw new SamlException('The Assertion has no end of validity.');
        }

        if ($this->instant($conditions->getAttribute('NotOnOrAfter'), 'NotOnOrAfter')->getTimestamp() + $skew <= $now->getTimestamp()) {
            throw new SamlException('The Assertion has expired.');
        }

        if ($conditions->getAttribute('NotBefore') !== '' && $this->instant($conditions->getAttribute('NotBefore'), 'NotBefore')->getTimestamp() > $now->getTimestamp() + $skew) {
            throw new SamlException('The Assertion is not valid yet.');
        }

        $restrictions = $xpath->query('./saml:AudienceRestriction', $conditions);

        if ($restrictions === false || $restrictions->length === 0) {
            throw new SamlException('The Assertion names no audience.');
        }

        // Every restriction must include this service: they are ANDed.
        foreach ($restrictions as $restriction) {
            $match = false;

            foreach ($xpath->query('./saml:Audience', $restriction) ?: [] as $audience) {
                if (trim($audience->textContent) === $sp->entityId) {
                    $match = true;
                }
            }

            if (! $match) {
                throw new SamlException('The Assertion is for a different audience.');
            }
        }

        foreach ($xpath->query('./*', $conditions) ?: [] as $condition) {
            if ($condition instanceof DOMElement && ! in_array($condition->localName, ['AudienceRestriction', 'OneTimeUse', 'ProxyRestriction'], true)) {
                throw new SamlException('The Assertion has a condition that is not understood.');
            }
        }
    }

    /**
     * @throws SamlException
     */
    private function instant(string $value, string $name): DateTimeImmutable
    {
        if (preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/', $value) !== 1) {
            throw new SamlException("{$name} is not a valid time.");
        }

        try {
            return new DateTimeImmutable($value);
        } catch (Throwable) {
            throw new SamlException("{$name} is not a valid time.");
        }
    }

    /**
     * The one node an expression selects, null when there is none; more than one is a refusal (an ambiguous message).
     *
     * @throws SamlException
     */
    private function single(DOMXPath $xpath, string $expression, DOMNode $context): ?DOMNode
    {
        $nodes = $xpath->query($expression, $context);

        if ($nodes === false || $nodes->length === 0) {
            return null;
        }

        if ($nodes->length > 1) {
            throw new SamlException('The message has more than one '.$expression.'.');
        }

        return $nodes->item(0);
    }

    private function xpath(DOMDocument $document): DOMXPath
    {
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('samlp', self::NS_PROTOCOL);
        $xpath->registerNamespace('saml', self::NS_ASSERTION);
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

        return $xpath;
    }
}
