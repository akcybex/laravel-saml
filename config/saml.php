<?php

return [
    /*
     | How far two servers' clocks may differ, in seconds, when checking an assertion's validity window.
     */
    'clock_skew_seconds' => (int) env('SAML_CLOCK_SKEW_SECONDS', 120),

    /*
     | Accept RSA-SHA1 signatures and SHA-1 digests. Off: only SHA-256 and up. Turn it on only for an identity provider that cannot
     | do better, knowing SHA-1 is broken.
     */
    'allow_sha1' => env('SAML_ALLOW_SHA1', false),

    /*
     | Accept an answer to no request of ours (IdP-initiated sign-in). Off, because an answer nobody asked for is the easiest one to
     | replay or inject. Only true, 1, '1' and 'true' turn it on; anything else ('on', 'yes', a typo) is off.
     */
    'allow_idp_initiated' => env('SAML_ALLOW_IDP_INITIATED', false),
];
