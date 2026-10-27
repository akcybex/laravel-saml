<!-- tc:hero -->
<a href="https://github.com/akcybex/laravel-saml#readme"><picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/tailcove/.github/main/profile/assets/packages/saml-dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/tailcove/.github/main/profile/assets/packages/saml-light.svg"><img alt="akcybex/laravel-saml: AKCybex for Laravel SAML. Version, runtime support, size and license." src="https://raw.githubusercontent.com/tailcove/.github/main/profile/assets/packages/saml-dark.svg" width="100%"></picture></a>

<p align="center">
  <a href="https://github.com/akcybex/laravel-saml#readme">Documentation</a> &nbsp;·&nbsp;
  <a href="https://packagist.org/packages/akcybex/laravel-saml">View on Packagist</a> &nbsp;·&nbsp;
  <a href="https://github.com/akcybex/laravel-saml/issues/new/choose">Report a bug</a>
</p>

<h3 align="center">SAML 2.0 sign-in for Laravel, as a service provider. Strict, small and plain.</h3>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/tailcove/.github/main/profile/assets/packages/features-saml-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/tailcove/.github/main/profile/assets/packages/features-saml-light.svg">
  <img alt="akcybex/laravel-saml features" src="https://raw.githubusercontent.com/tailcove/.github/main/profile/assets/packages/features-saml-dark.svg" width="100%">
</picture>

<!-- /tc:hero -->

SAML 2.0 single sign-on for Laravel, as a service provider. It builds the sign-in request, publishes your metadata, and checks the answer your customer's identity provider sends back, strictly. It does one flow and refuses everything else.

The service provider and the identity provider are plain values, not config files, so one application can serve many tenants, each with its own identity provider (Okta, Entra ID, Google Workspace, Keycloak, ADFS, and so on).

## What it does

- Builds an SP-initiated `AuthnRequest` and the HTTP-Redirect URL for it, signed with your key if you have one.
- Publishes your service provider metadata.
- Reads an identity provider's metadata document into settings.
- Validates the `Response` posted to your assertion consumer service and returns the person's NameID, attributes and session index.

## What it deliberately does not do

- No encrypted assertions. The identity provider must send signed, unencrypted assertions (the transport is HTTPS). An `EncryptedAssertion` is refused.
- No single logout.
- No IdP-initiated sign-in, unless you switch it on. An answer to no request of yours is the easiest one to replay or inject, so by default every answer must respond to a request this browser started.
- No Artifact or SOAP bindings. The request goes out over HTTP-Redirect and the answer comes back over HTTP-POST, nothing else.
- No SHA-1 and no weak algorithms, unless you switch SHA-1 on for an old identity provider. Signatures are RSA with SHA-256, SHA-384 or SHA-512.
- No signature check on identity provider metadata. Metadata is trusted as far as whoever supplied it.
- No user provisioning, attribute mapping or login. You decide what a NameID and its attributes mean in your application.

## Requirements

PHP 8.3 or newer, `ext-dom`, `ext-openssl`, Laravel 12 or 13. Signature checking is done with `robrichards/xmlseclibs`.

## Install

```
composer require akcybex/laravel-saml
```

The service provider is registered automatically. To change the defaults, publish the config:

```
php artisan vendor:publish --tag=saml-config
```

## Quick start

Three calls, all on `Akcybex\LaravelSaml\Saml`:

```php
$request   = $saml->authnRequest($sp, $idp, $relayState);   // keep $request->id in the session, redirect to $request->redirectUrl
$assertion = $saml->validate($_POST['SAMLResponse'], $sp, $idp, $pendingRequestId);   // at the assertion consumer service
// sign the person in from $assertion->nameId / $assertion->attributes, and forget $pendingRequestId
```

`$sp` is a `ServiceProviderSettings` (who you are), `$idp` an `IdentityProviderSettings` (who you trust):

```php
use Akcybex\LaravelSaml\IdentityProviderSettings;
use Akcybex\LaravelSaml\ServiceProviderSettings;

$sp = new ServiceProviderSettings(
    entityId: 'https://app.example.com/saml/metadata',
    assertionConsumerServiceUrl: 'https://app.example.com/saml/acs',
);

$idp = new IdentityProviderSettings(
    entityId: 'https://idp.example.com/metadata',
    singleSignOnUrl: 'https://idp.example.com/sso',
    certificates: [$pemCertificate],   // PEM; several during a key rollover
);
```

### In a Laravel controller

```php
use Akcybex\LaravelSaml\Exceptions\SamlException;
use Akcybex\LaravelSaml\Saml;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class SamlController
{
    public function login(Request $request, Saml $saml)
    {
        [$sp, $idp] = $this->settingsFor($request);

        $authn = $saml->authnRequest($sp, $idp, relayState: '/dashboard');

        $request->session()->put('saml.request_id', $authn->id);

        return redirect()->away($authn->redirectUrl);
    }

    public function acs(Request $request, Saml $saml)
    {
        [$sp, $idp] = $this->settingsFor($request);

        // pull() reads the request id and forgets it in one step: an answer can be used once, even a refused one.
        $pending = $request->session()->pull('saml.request_id');

        try {
            $assertion = $saml->validate((string) $request->input('SAMLResponse'), $sp, $idp, $pending);
        } catch (SamlException $e) {
            report($e);   // the message says why, and never contains the response

            return redirect('/login')->withErrors(['sso' => 'Single sign-on failed.']);
        }

        $user = User::where('email', $assertion->nameId)->first();   // your own lookup or provisioning

        abort_if($user === null, 403);

        Auth::login($user);
        $request->session()->regenerate();

        return redirect('/dashboard');
    }

    public function metadata(Request $request, Saml $saml)
    {
        [$sp] = $this->settingsFor($request);

        return response($saml->metadata($sp), 200, ['Content-Type' => 'application/samlmetadata+xml']);
    }
}
```

```php
Route::get('/saml/login', [SamlController::class, 'login']);
Route::post('/saml/acs', [SamlController::class, 'acs']);
Route::get('/saml/metadata', [SamlController::class, 'metadata']);
```

The assertion consumer service receives a cross-site POST from the identity provider, so it cannot carry a CSRF token. Exclude it from CSRF verification (Laravel 11 and later, in `bootstrap/app.php`):

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->validateCsrfTokens(except: ['saml/acs']);
})
```

The identity provider's POST is a cross-site request, and a session cookie with `SameSite=Lax` (Laravel's default) is not sent on it, so the request id would not be found and the answer would be refused. Set `SESSION_SAME_SITE=none` and `SESSION_SECURE_COOKIE=true` for an application that signs in this way, or keep the pending request id somewhere the cookie does not decide (a short-lived cache entry keyed by the `RelayState`, say).

`RelayState` comes back from the identity provider untouched and unchecked. If you redirect to it after sign-in, only redirect to a relative path or an address you allow-list.

### What you get back

`validate()` returns an `Akcybex\LaravelSaml\Assertion`:

```php
$assertion->id;            // the assertion's ID
$assertion->issuer;        // the identity provider's entity id
$assertion->nameId;        // the person
$assertion->nameIdFormat;  // string or null
$assertion->sessionIndex;  // string or null
$assertion->inResponseTo;  // the request id it answered
$assertion->notOnOrAfter;  // DateTimeImmutable
$assertion->attributes;    // ['mail' => ['a@example.com'], 'groups' => ['admins', 'staff']]
$assertion->attribute('mail');   // first value, or null
```

Everything in it is read from the part of the message covered by a verified signature.

## Metadata

Give your identity provider's administrator the output of `$saml->metadata($sp)` (or serve it from a route, as above). It lists your entity id, the assertion consumer service with the POST binding, and, when the settings have a certificate, the signing certificate.

To read the identity provider's metadata into settings:

```php
use Akcybex\LaravelSaml\Metadata\IdpMetadataParser;

$idp = IdpMetadataParser::parse($xml);   // IdentityProviderSettings
```

The parser takes the entity id, the sign-in service (Redirect binding preferred) and every certificate marked for signing (or with no `use`). Encryption certificates are ignored. It refuses a federation file with many entities (pick the one you want and pass its XML), metadata with no sign-in service or no signing certificate, and anything with a DOCTYPE. There is no signature check on the metadata, so only parse metadata from a source you trust: a file the tenant's administrator uploaded, or an https address they entered.

## Signing requests

Set a private key (and the matching certificate, for the metadata) on the service provider settings and the HTTP-Redirect request is signed with RSA-SHA256 over the query string:

```php
$sp = new ServiceProviderSettings(
    entityId: '...',
    assertionConsumerServiceUrl: '...',
    privateKeyPem: $privateKey,
    certificatePem: $certificate,
);
```

The metadata then says `AuthnRequestsSigned="true"` and carries the certificate. Most identity providers do not require signed requests.

## Per-tenant settings

Nothing is global, so a multi-tenant application builds the two settings objects from its own records for each request:

```php
$sp  = new ServiceProviderSettings($tenant->saml_entity_id, route('saml.acs', $tenant));
$idp = IdpMetadataParser::parse($tenant->saml_metadata_xml);
```

Store the tenant's identity provider settings (or its metadata XML) in your database and the pending request id in the session.

## What `validate()` enforces

An answer is refused with a `SamlException` unless all of this holds. The message says which rule failed and never contains the message itself.

- The Response, the Assertion or both carry an enveloped signature that verifies with one of the identity provider's configured certificates. A certificate inside the message is never used.
- There is exactly one Assertion in the whole document, as a direct child of the Response, and no two elements share an ID. IDs must be valid XML names.
- Each signature has exactly one Reference, by `#ID`, to the element that contains it, with only the enveloped-signature and exclusive-c14n transforms. Canonicalization is exclusive c14n without comments. The signature method is RSA-SHA256/384/512 and the digest SHA-256/384/512 (SHA-1 only when allowed).
- The document has no DOCTYPE, is well formed, and is at most 512 KiB.
- The root is a SAML 2.0 `Response` with status Success, a `Destination` equal to your assertion consumer service URL, and, if it names an Issuer, the identity provider's entity id.
- The Assertion is SAML 2.0, issued by the identity provider's entity id, with an `IssueInstant` not in the future.
- The Assertion has a NameID (not empty, at most 512 characters).
- At least one bearer `SubjectConfirmation` has a `Recipient` equal to your assertion consumer service URL, a `NotOnOrAfter` still in the future, a `NotBefore` (if present) not in the future, and an `InResponseTo` equal to the request id you pass.
- The Response's `InResponseTo` equals the request id you pass too. With no pending request id (`null`), the answer is refused unless IdP-initiated sign-in is allowed.
- `Conditions` exist, have a `NotOnOrAfter` still in the future and a `NotBefore` (if present) not in the future, and every `AudienceRestriction` (there must be at least one) lists your entity id. Any condition other than `AudienceRestriction`, `OneTimeUse` and `ProxyRestriction` is refused.
- The assertion id has not been seen before. Ids are remembered until the assertion expires. An assertion that is refused for any other reason is not remembered.
- Times are compared with the clock skew allowance (120 seconds by default).

## Config

`config/saml.php`:

- `clock_skew_seconds` (`SAML_CLOCK_SKEW_SECONDS`, default `120`): how far two servers' clocks may differ.
- `allow_sha1` (`SAML_ALLOW_SHA1`, default `false`): accept RSA-SHA1 signatures and SHA-1 digests, for an identity provider that cannot do better.
- `allow_idp_initiated` (`SAML_ALLOW_IDP_INITIATED`, default `false`): accept an answer when you pass no pending request id.

The two flags are read with `filter_var(..., FILTER_VALIDATE_BOOLEAN)`, never with a plain cast: the string `"false"` is off, and so is anything that is not a recognisable true (`true`, `"1"`, `"true"`, `"on"`, `"yes"`).

Replay protection uses Laravel's default cache store, with an atomic `add`. Use a shared store (Redis, database, Memcached) when you run more than one server. To use something else, bind your own implementation of `Akcybex\LaravelSaml\Support\ReplayStore`; `ArrayReplayStore` is an in-memory one for tests and single-process tools.

Without the container you can construct the pieces yourself: `new Saml($replayStore, clockSkewSeconds: 120, allowSha1: false, allowIdpInitiated: false)`.

## Testing

```
composer install
vendor/bin/pest
```

The tests generate RSA keys and self-signed certificates with OpenSSL and sign real SAML responses with xmlseclibs, so they need `ext-openssl` and nothing else: no identity provider, no network. `tests/Support/SamlFixtures.php` builds a response from options (signing mode, algorithms, any field) and signs it with a throwaway key.

## License

MIT. See `LICENSE`.

<!-- tc:footer -->
<p align="center">
  <a href="https://github.com/akcybex/laravel-saml#readme">Documentation</a> &nbsp;·&nbsp;
  <a href="https://github.com/akcybex/laravel-saml/issues/new/choose">Report a bug</a> &nbsp;·&nbsp;
  <a href="LICENSE">MIT License</a>
</p>

<p align="center">
  <sub>Built by AKCybex.</sub>
</p>
<!-- /tc:footer -->
