<?php

use App\Http\Controllers\BetController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

// CWE-352: 该路由已在 bootstrap/app.php exceptFromCsrf 中明确排除 CSRF 校验。
// 正常 Web 路由应携带 _token 字段，此处故意绕过，使跨站请求可直接触发。
Route::post('/leaderboard', [BetController::class, 'leaderboard']);

// ── /safe 对照路由 ──────────────────────────────────────────────────────────
// [SAFE] CWE-352 修复原因：此路由未加入 exceptFromCsrf，Laravel 默认强制验证 CSRF Token
// 对比漏洞版本：/leaderboard 在 bootstrap/app.php 中被明确豁免，跨站 POST 无需 Token
Route::post('/leaderboard/safe', [BetController::class, 'leaderboardSafe']);
