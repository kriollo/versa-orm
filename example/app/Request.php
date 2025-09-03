<?php

declare(strict_types=1);

namespace App;

use function function_exists;

/**
 * Request simple para el ejemplo (similar a frameworks web).
 */
class Request
{
    private function __construct(
        public array $get,
        public array $post,
        public array $server,
        public array $cookies,
        public array $files,
        public array $headers,
    ) {
    }

    public static function fromGlobals(): self
    {
        return new self(
            $_GET,
            $_POST,
            $_SERVER,
            $_COOKIE,
            $_FILES,
            function_exists('getallheaders') ? getallheaders() : [],
        );
    }

    public function method(): string
    {
        return strtoupper($this->server['REQUEST_METHOD'] ?? 'GET');
    }

    public function path(): string
    {
        $uri = $this->server['REQUEST_URI'] ?? '/';
        $q = strpos($uri, '?');

        return $q === false ? $uri : substr($uri, 0, $q);
    }
}
