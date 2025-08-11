<?php

declare(strict_types=1);

namespace App;

/**
 * Request simple para el ejemplo (similar a frameworks web).
 */
class Request
{
    public array $get;
    public array $post;
    public array $server;
    public array $cookies;
    public array $files;
    public array $headers;

    private function __construct(array $get, array $post, array $server, array $cookies, array $files, array $headers)
    {
        $this->get = $get;
        $this->post = $post;
        $this->server = $server;
        $this->cookies = $cookies;
        $this->files = $files;
        $this->headers = $headers;
    }

    public static function fromGlobals(): self
    {
        return new self(
            $_GET,
            $_POST,
            $_SERVER,
            $_COOKIE,
            $_FILES,
            function_exists('getallheaders') ? (getallheaders() ?: []) : []
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
