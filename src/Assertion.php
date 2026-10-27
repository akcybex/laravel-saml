<?php

namespace Akcybex\LaravelSaml;

use DateTimeImmutable;

/**
 * What a validated sign-in says about the person. Built only from the part of the message the signature covers.
 */
final readonly class Assertion
{
    /**
     * @param  array<string, list<string>>  $attributes  attribute name => its values
     */
    public function __construct(
        public string $id,
        public string $issuer,
        public string $nameId,
        public ?string $nameIdFormat,
        public ?string $sessionIndex,
        public ?string $inResponseTo,
        public DateTimeImmutable $notOnOrAfter,
        public array $attributes,
    ) {}

    /**
     * The first value of an attribute, or null.
     */
    public function attribute(string $name): ?string
    {
        return $this->attributes[$name][0] ?? null;
    }
}
