<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        // CWE-352: 故意将 /leaderboard 加入 CSRF 豁免列表
        // 正常 Web 路由应受 CSRF 保护，此处明确绕过，演示跨站请求伪造漏洞
        $middleware->validateCsrfTokens(except: [
            '/leaderboard',
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        //
    })->create();
