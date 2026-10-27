<?php

namespace Akcybex\LaravelSaml\Exceptions;

use RuntimeException;

/**
 * A SAML message that is refused. The message says why in words a log reader can use; it never holds the message itself.
 */
final class SamlException extends RuntimeException {}
