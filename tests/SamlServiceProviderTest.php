<?php

use Akcybex\LaravelSaml\Exceptions\SamlException;
use Akcybex\LaravelSaml\Saml;
use Akcybex\LaravelSaml\SamlServiceProvider;
use Akcybex\LaravelSaml\Support\CacheReplayStore;
use Akcybex\LaravelSaml\Support\ReplayStore;
use Akcybex\LaravelSaml\Tests\Support\SamlFixtures as Fx;
use Illuminate\Support\ServiceProvider;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * A response made for "now", since Saml::validate() reads the real clock.
 */
$live = fn (array $options = []): string => Fx::response(array_replace(['at' => new DateTimeImmutable('now', new DateTimeZone('UTC'))], $options));

it('resolves the Saml entry point from the container, as one instance', function () {
    expect(app(Saml::class))->toBeInstanceOf(Saml::class)
        ->and(app(Saml::class))->toBe(app(Saml::class));
});

it('binds the replay store to the cache', function () {
    expect(app(ReplayStore::class))->toBeInstanceOf(CacheReplayStore::class);
});

it('ships config defaults that are strict', function () {
    expect(config('saml.clock_skew_seconds'))->toBe(120)
        ->and(config('saml.allow_sha1'))->toBeFalse()
        ->and(config('saml.allow_idp_initiated'))->toBeFalse();
});

it('offers the config file for publishing', function () {
    $paths = ServiceProvider::pathsToPublish(SamlServiceProvider::class, 'saml-config');

    expect($paths)->toHaveCount(1)
        ->and(array_key_first($paths))->toEndWith('config/saml.php');
});

it('does not accept an answer to no request by default', function () use ($live) {
    $response = $live(['responseInResponseTo' => null, 'scdInResponseTo' => null]);

    expect(fn () => app(Saml::class)->validate($response, Fx::sp(), Fx::idp(), null))
        ->toThrow(SamlException::class, 'no pending sign-in request');
});

it('reads allow_idp_initiated strictly: only a true value turns it on', function (mixed $value, bool $on) use ($live) {
    config(['saml.allow_idp_initiated' => $value]);

    $response = $live(['responseInResponseTo' => null, 'scdInResponseTo' => null]);
    $saml = app(Saml::class);

    if ($on) {
        expect($saml->validate($response, Fx::sp(), Fx::idp(), null)->nameId)->toBe('alice@example.com');

        return;
    }

    expect(fn () => $saml->validate($response, Fx::sp(), Fx::idp(), null))->toThrow(SamlException::class, 'no pending sign-in request');
})->with([
    'true' => [true, true],
    'the string true' => ['true', true],
    'the string 1' => ['1', true],
    'false' => [false, false],
    'the string false' => ['false', false],
    'the string no' => ['no', false],
    'the string 0' => ['0', false],
    'the string off' => ['off', false],
    'an empty string' => ['', false],
    'null' => [null, false],
    'a word' => ['maybe', false],
]);

it('reads allow_sha1 strictly: the string false is off', function (mixed $value, bool $on) use ($live) {
    config(['saml.allow_sha1' => $value]);

    $response = $live(['sigAlg' => XMLSecurityKey::RSA_SHA1]);
    $saml = app(Saml::class);

    if ($on) {
        expect($saml->validate($response, Fx::sp(), Fx::idp(), Fx::REQUEST_ID)->nameId)->toBe('alice@example.com');

        return;
    }

    expect(fn () => $saml->validate($response, Fx::sp(), Fx::idp(), Fx::REQUEST_ID))->toThrow(SamlException::class, 'signature algorithm is not accepted');
})->with([
    'true' => [true, true],
    'the string true' => ['true', true],
    'false' => [false, false],
    'the string false' => ['false', false],
    'the string no' => ['no', false],
]);

it('reads the clock skew from config', function () use ($live) {
    $response = $live(['conditionsNotOnOrAfter' => Fx::at(-60, new DateTimeImmutable('now', new DateTimeZone('UTC')))]);

    expect(app(Saml::class)->validate($response, Fx::sp(), Fx::idp(), Fx::REQUEST_ID)->nameId)->toBe('alice@example.com');

    config(['saml.clock_skew_seconds' => '10']);
    app()->forgetInstance(Saml::class);

    expect(fn () => app(Saml::class)->validate($live(['conditionsNotOnOrAfter' => Fx::at(-60, new DateTimeImmutable('now', new DateTimeZone('UTC'))), 'assertionId' => '_other']), Fx::sp(), Fx::idp(), Fx::REQUEST_ID))
        ->toThrow(SamlException::class, 'has expired');
});

it('refuses a second use of the same assertion through the container', function () use ($live) {
    $response = $live();
    $saml = app(Saml::class);

    expect($saml->validate($response, Fx::sp(), Fx::idp(), Fx::REQUEST_ID)->nameId)->toBe('alice@example.com');

    expect(fn () => $saml->validate($response, Fx::sp(), Fx::idp(), Fx::REQUEST_ID))->toThrow(SamlException::class, 'already used');
});

it('refuses a second remember() of the same id on the cache replay store', function () {
    $store = app(ReplayStore::class);
    $until = new DateTimeImmutable('+10 minutes');

    expect($store->remember('_one', $until))->toBeTrue()
        ->and($store->remember('_one', $until))->toBeFalse()
        ->and($store->remember('_two', $until))->toBeTrue();
});

it('shares the remembered ids between replay store instances on the same cache', function () {
    $until = new DateTimeImmutable('+10 minutes');

    expect(app(ReplayStore::class)->remember('_shared', $until))->toBeTrue()
        ->and(app(ReplayStore::class)->remember('_shared', $until))->toBeFalse();
});

it('keeps an id remembered for at least a minute, even when it expired already', function () {
    $store = app(ReplayStore::class);

    expect($store->remember('_old', new DateTimeImmutable('-1 hour')))->toBeTrue()
        ->and($store->remember('_old', new DateTimeImmutable('-1 hour')))->toBeFalse();
});
