<?php

namespace Akcybex\LaravelSaml\Tests;

use Akcybex\LaravelSaml\Assertion;
use Akcybex\LaravelSaml\Exceptions\SamlException;
use Akcybex\LaravelSaml\Protocol\ResponseValidator;
use Akcybex\LaravelSaml\SamlServiceProvider;
use Akcybex\LaravelSaml\Support\ArrayReplayStore;
use Akcybex\LaravelSaml\Tests\Support\SamlFixtures;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [SamlServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('cache.default', 'array');
    }

    /**
     * Validates a response the way the tests usually want it: fixed clock, the fixture request id, fresh replay store.
     *
     * Options: expected (request id or null), now, store, skew, sha1, idpInitiated, sp, idp.
     *
     * @param  array<string, mixed>  $options
     *
     * @throws SamlException
     */
    protected function validateResponse(string $samlResponse, array $options = []): Assertion
    {
        $expected = array_key_exists('expected', $options) ? $options['expected'] : SamlFixtures::REQUEST_ID;

        $validator = new ResponseValidator(
            $options['store'] ?? new ArrayReplayStore,
            $options['skew'] ?? 120,
            $options['sha1'] ?? false,
            $options['idpInitiated'] ?? false,
        );

        return $validator->validate(
            $samlResponse,
            $options['sp'] ?? SamlFixtures::sp(),
            $options['idp'] ?? SamlFixtures::idp(),
            $expected,
            $options['now'] ?? SamlFixtures::now(),
        );
    }

    /**
     * Asserts the response is refused with a SamlException whose message contains one of the fragments.
     * Any other kind of exception (a PHP warning turned into an error, say) fails the test.
     *
     * @param  string|list<string>  $fragments
     * @param  array<string, mixed>  $options
     */
    protected function assertRefused(string $samlResponse, string|array $fragments, array $options = []): void
    {
        $fragments = (array) $fragments;

        try {
            $this->validateResponse($samlResponse, $options);
        } catch (SamlException $e) {
            foreach ($fragments as $fragment) {
                if (str_contains($e->getMessage(), $fragment)) {
                    $this->addToAssertionCount(1);

                    return;
                }
            }

            $this->fail('Refused for a different reason than expected ('.implode(' | ', $fragments).'): '.$e->getMessage());
        }

        $this->fail('The response was accepted, but it should have been refused ('.implode(' | ', $fragments).').');
    }
}
