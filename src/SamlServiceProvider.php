<?php

namespace Akcybex\LaravelSaml;

use Akcybex\LaravelSaml\Support\CacheReplayStore;
use Akcybex\LaravelSaml\Support\ReplayStore;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\ServiceProvider;

class SamlServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/saml.php', 'saml');

        $this->app->bind(ReplayStore::class, fn ($app): ReplayStore => new CacheReplayStore($app->make(Repository::class)));

        $this->app->singleton(Saml::class, fn ($app): Saml => new Saml(
            $app->make(ReplayStore::class),
            (int) config('saml.clock_skew_seconds', 120),
            self::flag(config('saml.allow_sha1', false)),
            self::flag(config('saml.allow_idp_initiated', false)),
        ));
    }

    /**
     * A switch that lowers security is on only for an unmistakable true: the boolean, 1, '1' or 'true'. Anything else ('on', 'yes',
     * a typo) is off.
     */
    private static function flag(mixed $value): bool
    {
        return $value === true || $value === 1 || $value === '1' || $value === 'true';
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([__DIR__.'/../config/saml.php' => config_path('saml.php')], 'saml-config');
        }
    }
}
