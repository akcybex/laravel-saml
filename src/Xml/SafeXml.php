<?php

namespace Akcybex\LaravelSaml\Xml;

use Akcybex\LaravelSaml\Exceptions\SamlException;
use DOMDocument;

/**
 * Loads XML that came from outside. No network, no entities, no DTD: a document type declaration is refused outright (a SAML message
 * never needs one), which closes XXE and entity-expansion attacks before the parser sees them.
 */
final class SafeXml
{
    public const MAX_BYTES = 524_288;

    /**
     * @throws SamlException
     */
    public static function load(string $xml): DOMDocument
    {
        if ($xml === '' || strlen($xml) > self::MAX_BYTES) {
            throw new SamlException('The XML is empty or too large.');
        }

        // Before parsing: any DOCTYPE or ENTITY declaration, in any case or encoding trick the parser would honour.
        if (preg_match('/<!\s*(DOCTYPE|ENTITY)/i', $xml) === 1) {
            throw new SamlException('The XML contains a document type declaration, which is not allowed.');
        }

        $previous = libxml_use_internal_errors(true);

        try {
            $document = new DOMDocument;
            $document->preserveWhiteSpace = true;

            if (! $document->loadXML($xml, LIBXML_NONET | LIBXML_NOWARNING | LIBXML_NOERROR)) {
                throw new SamlException('The XML is not well formed.');
            }
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }

        foreach ($document->childNodes as $child) {
            if ($child->nodeType === XML_DOCUMENT_TYPE_NODE) {
                throw new SamlException('The XML contains a document type declaration, which is not allowed.');
            }
        }

        return $document;
    }
}
