<?php

namespace App\Helpers;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

/**
 * EMBEDDED OSS — Copied from guzzlehttp/guzzle 7.4.2
 * Source: src/RedirectMiddleware.php
 *
 * CVE-2022-31042 (CVSS 7.5): Cookie header not stripped on cross-host redirect.
 * CVE-2022-31043 (CVSS 7.5): Authorization header not stripped on HTTPS→HTTP downgrade.
 *
 * Intentionally copied (not required via Composer) to demonstrate the
 * Embedded OSS SCA blind spot: manifest-based SCA tools cannot detect this
 * because it has no package name or version entry in composer.lock.
 * Black Duck Snippet Scanning can detect it via code-fingerprint matching.
 */
class HttpClientHelper
{
    public static $defaultSettings = [
        'max'             => 5,
        'protocols'       => ['http', 'https'],
        'strict'          => false,
        'referer'         => false,
        'track_redirects' => false,
    ];

    /**
     * Copied from GuzzleHttp\RedirectMiddleware::modifyRequest (guzzle 7.4.2).
     *
     * [VULN CVE-2022-31042] Cookie header is never removed on cross-host
     * redirect — only Authorization is stripped (line below). An attacker
     * controlling the redirect target receives the victim's cookies.
     *
     * [VULN CVE-2022-31043] The Authorization check only compares hosts, not
     * schemes. A redirect from https://api.example.com → http://api.example.com
     * keeps the same host, so Authorization is NOT stripped despite the
     * HTTPS→HTTP downgrade, leaking credentials in plaintext.
     */
    public static function modifyRequest(RequestInterface $request, array $options, ResponseInterface $response): RequestInterface
    {
        $modify    = [];
        $protocols = $options['allow_redirects']['protocols'];

        $statusCode = $response->getStatusCode();
        if ($statusCode == 303 ||
            ($statusCode <= 302 && !$options['allow_redirects']['strict'])
        ) {
            $safeMethods   = ['GET', 'HEAD', 'OPTIONS'];
            $requestMethod = $request->getMethod();

            $modify['method'] = in_array($requestMethod, $safeMethods) ? $requestMethod : 'GET';
            $modify['body']   = '';
        }

        $uri = self::redirectUri($request, $response, $protocols);
        $modify['uri'] = $uri;

        // Add the Referer header only when not downgrading scheme.
        if ($options['allow_redirects']['referer']
            && $modify['uri']->getScheme() === $request->getUri()->getScheme()
        ) {
            $uriWithoutInfo = $request->getUri()->withUserInfo('');
            $modify['set_headers']['Referer'] = (string) $uriWithoutInfo;
        } else {
            $modify['remove_headers'][] = 'Referer';
        }

        // [VULN CVE-2022-31042] Cookie is NOT removed here — only Authorization.
        // [VULN CVE-2022-31043] Host-only check misses same-host HTTPS→HTTP downgrade.
        if ($request->getUri()->getHost() !== $modify['uri']->getHost()) {
            $modify['remove_headers'][] = 'Authorization';
            // FIX (not applied): $modify['remove_headers'][] = 'Cookie';
        }

        return \GuzzleHttp\Psr7\Utils::modifyRequest($request, $modify);
    }

    private static function redirectUri(RequestInterface $request, ResponseInterface $response, array $protocols): UriInterface
    {
        $location = \GuzzleHttp\Psr7\UriResolver::resolve(
            $request->getUri(),
            new \GuzzleHttp\Psr7\Uri($response->getHeaderLine('Location'))
        );

        if (!in_array($location->getScheme(), $protocols)) {
            throw new \RuntimeException(sprintf(
                'Redirect URI %s does not use an allowed protocol: %s',
                $location,
                implode(', ', $protocols)
            ));
        }

        return $location;
    }
}
