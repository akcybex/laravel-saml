<?php

use Akcybex\LaravelSaml\Exceptions\SamlException;
use Akcybex\LaravelSaml\Xml\SafeXml;

it('loads a well-formed document', function () {
    $document = SafeXml::load('<?xml version="1.0"?><a xmlns="urn:example"><b>text</b></a>');

    expect($document)->toBeInstanceOf(DOMDocument::class)
        ->and($document->documentElement->localName)->toBe('a')
        ->and($document->documentElement->namespaceURI)->toBe('urn:example');
});

it('keeps whitespace, so a signature over it still verifies', function () {
    $document = SafeXml::load("<a> <b/> </a>");

    expect($document->documentElement->childNodes->length)->toBe(3);
});

it('refuses an empty string', function () {
    expect(fn () => SafeXml::load(''))->toThrow(SamlException::class, 'empty or too large');
});

it('accepts a document of exactly the size limit and refuses one byte more', function () {
    $fill = SafeXml::MAX_BYTES - strlen('<a></a>');

    expect(SafeXml::load('<a>'.str_repeat('x', $fill).'</a>')->documentElement->localName)->toBe('a');

    expect(fn () => SafeXml::load('<a>'.str_repeat('x', $fill + 1).'</a>'))->toThrow(SamlException::class, 'too large');
});

it('refuses a document that is not well formed', function (string $xml) {
    expect(fn () => SafeXml::load($xml))->toThrow(SamlException::class, 'not well formed');
})->with([
    'unclosed' => '<a><b></a>',
    'text only' => 'hello',
    'two roots' => '<a/><b/>',
]);

it('refuses any document type declaration or entity declaration', function (string $xml) {
    expect(fn () => SafeXml::load($xml))->toThrow(SamlException::class, 'document type declaration');
})->with([
    'doctype' => '<!DOCTYPE a><a/>',
    'lower case' => '<!doctype a><a/>',
    'mixed case' => '<!DocType a><a/>',
    'external entity' => '<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>',
    'billion laughs' => '<!DOCTYPE a [<!ENTITY l "lol"><!ENTITY l2 "&l;&l;&l;&l;&l;&l;&l;&l;&l;&l;">]><a>&l2;</a>',
    'entity outside a doctype' => '<a><!ENTITY x "y"></a>',
    'space after the bang' => '<! DOCTYPE a><a/>',
]);

it('refuses a DOCTYPE in UTF-16, which the text check cannot see', function () {
    $xml = "\xFF\xFE".mb_convert_encoding('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>', 'UTF-16LE', 'UTF-8');

    // Either the parser reads it and the node check refuses it, or the parser refuses it: never a loaded document.
    expect(fn () => SafeXml::load($xml))->toThrow(SamlException::class);
});

it('decodes the predefined entities and nothing else', function () {
    $document = SafeXml::load('<a>&amp;&lt;</a>');

    expect($document->documentElement->textContent)->toBe('&<');
});

it('leaves the caller\'s libxml error handling as it found it', function (bool $before) {
    libxml_use_internal_errors($before);

    try {
        SafeXml::load('<a><b></a>');
    } catch (SamlException) {
        // expected
    }

    expect(libxml_use_internal_errors())->toBe($before);

    SafeXml::load('<a/>');

    expect(libxml_use_internal_errors())->toBe($before);

    libxml_use_internal_errors(false);
})->with([true, false]);
