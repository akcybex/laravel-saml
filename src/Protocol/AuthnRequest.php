<?php

namespace Akcybex\LaravelSaml\Protocol;

/**
 * A sign-in request ready to send: the address to redirect the browser to, and the request id, which the caller keeps (in the
 * session) and hands back when the answer arrives, so only an answer to this very request is accepted.
 */
final readonly class AuthnRequest
{
    public function __construct(
        public string $id,
        public string $redirectUrl,
    ) {}
}
