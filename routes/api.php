<?php

use App\Http\Controllers\BetController;
use App\Http\Controllers\ItemController;
use App\Http\Controllers\PlayerController;
use App\Http\Controllers\RechargeController;
use App\Http\Controllers\SaveController;
use App\Http\Controllers\WithdrawController;
use Illuminate\Support\Facades\Route;

// ══════════════════════════════════════════════════════════════════
//  漏洞版路由（预埋缺陷，供 SAST/DAST/人工审计使用）
// ══════════════════════════════════════════════════════════════════

// 模块一：玩家认证
// CWE-256: 明文存储密码；CWE-321: 硬编码弱 JWT 密钥
Route::post('/register', [PlayerController::class, 'register']);
Route::post('/login',    [PlayerController::class, 'login']);

// 模块二：充值支付
// CWE-532: 敏感 API Key/Secret 写入日志；CWE-117: 日志注入（未过滤换行符）
Route::post('/recharge',       [RechargeController::class, 'recharge']);
Route::get('/recharge/export', [RechargeController::class, 'export']);

// 模块三：游戏下注
// CWE-20: 下注金额无业务范围校验；CWE-89: leaderboard name 参数直接拼接 SQL
Route::post('/bet',        [BetController::class, 'bet']);
Route::get('/leaderboard', [BetController::class, 'leaderboard']);

// 模块四：道具兑换
// CWE-639: IDOR — 不校验道具归属；CWE-22: 路径遍历 — 文件路径由用户传入
Route::post('/item/exchange/{id}', [ItemController::class, 'exchange']);
Route::get('/item/image',          [ItemController::class, 'image']);
Route::get('/item/list',           [ItemController::class, 'list']);

// 模块五：提现功能
// CWE-639: 不校验 player_id 归属；CWE-770: 无频率/金额限制；CWE-223: 无安全日志
Route::post('/withdraw',        [WithdrawController::class, 'withdraw']);
// CWE-918: SSRF — callback_url 由用户传入，服务端直接发起请求
Route::post('/withdraw/notify', [WithdrawController::class, 'notify']);

// 模块六：游戏存档上传
// CWE-434: 无文件类型校验；CWE-732: 权限 0777
Route::post('/save/upload', [SaveController::class, 'upload']);
// CWE-502: 直接 unserialize 用户输入，无 allowed_classes 限制
Route::post('/save/parse',  [SaveController::class, 'parse']);
// CWE-611: XXE — 启用 LIBXML_NOENT | LIBXML_DTDLOAD 解析外部实体
Route::post('/save/import', [SaveController::class, 'importXml']);


// ══════════════════════════════════════════════════════════════════
//  安全修复版路由（/safe 后缀，独立分组）
//  每条路由对应上方同名漏洞接口的修复方案；可用于对比演示和误报验证
// ══════════════════════════════════════════════════════════════════
Route::group([], function () {

    // ── 模块一：玩家认证 ──────────────────────────────────────────
    // CWE-256 修复：registerSafe 使用 Hash::make() 存储哈希密码
    // CWE-321 修复：loginSafe 从 env() 读取 JWT_SECRET 并校验强度（≥32 字符）
    Route::post('/register/safe', [PlayerController::class, 'registerSafe']);
    Route::post('/login/safe',    [PlayerController::class, 'loginSafe']);
    // [FALSE-POSITIVE] eval() 字面量 — CWE-95 误报演示
    Route::get('/register/policy/safe', [PlayerController::class, 'passwordPolicy']);

    // ── 模块二：充值支付 ──────────────────────────────────────────
    // CWE-532 修复：rechargeSafe 日志仅记录 player_id + transaction_id，不含密钥
    // CWE-117 修复：exportSafe 过滤 \r\n + 结构化日志（key-value，无字符串拼接）
    Route::post('/recharge/safe',       [RechargeController::class, 'rechargeSafe']);
    Route::get('/recharge/export/safe', [RechargeController::class, 'exportSafe']);
    // [FALSE-POSITIVE] exec() 字面量 — CWE-78 误报演示
    Route::get('/recharge/gateway-ping/safe', [RechargeController::class, 'gatewayStatus']);

    // ── 模块三：游戏下注 ──────────────────────────────────────────
    // CWE-20 修复：betSafe 校验正数金额 + 余额校验 + DB 事务
    // CWE-89 修复：leaderboardSafe 使用 Eloquent ORM 参数绑定，消除拼接 SQL
    Route::post('/bet/safe',        [BetController::class, 'betSafe']);
    Route::get('/leaderboard/safe', [BetController::class, 'leaderboardSafe']);
    // [FALSE-POSITIVE] DB::raw() 字面量 — CWE-89 误报演示
    Route::get('/bet/rtp/safe', [BetController::class, 'returnToPlayer']);

    // ── 模块四：道具兑换 ──────────────────────────────────────────
    // CWE-639 修复：exchangeSafe where 条件加 player_id 归属校验，防止 IDOR
    // CWE-22 修复：imageSafe realpath() + 白名单目录前缀校验，防止路径遍历
    Route::post('/item/exchange/safe/{id}', [ItemController::class, 'exchangeSafe']);
    Route::get('/item/image/safe',          [ItemController::class, 'imageSafe']);
    // [FALSE-POSITIVE] unserialize() 硬编码 — CWE-502 误报演示
    Route::get('/item/catalog-defaults/safe', [ItemController::class, 'itemCatalogDefaults']);

    // ── 模块五：提现功能 ──────────────────────────────────────────
    // CWE-639/770/223 修复：withdrawSafe X-Player-Id 认证 + RateLimiter + 余额校验 + 安全日志
    // CWE-918 修复：notifySafe HTTPS 白名单 + 域名白名单 + DNS Rebinding 防护
    Route::post('/withdraw/safe',        [WithdrawController::class, 'withdrawSafe']);
    Route::post('/withdraw/notify/safe', [WithdrawController::class, 'notifySafe']);
    // [FALSE-POSITIVE] call_user_func() 字面量 — CWE-77 误报演示
    Route::get('/withdraw/fee-table/safe', [WithdrawController::class, 'feeTable']);

    // ── 模块六：游戏存档上传 ──────────────────────────────────────
    // CWE-434/732 修复：uploadSafe mimes 白名单 + 非 Web 目录 + chmod 0644
    // CWE-502 修复：parseSafe unserialize 传入 allowed_classes => false
    // CWE-611 修复：importXmlSafe 前置 DOCTYPE/ENTITY 过滤 + 仅用 LIBXML_NONET
    Route::post('/save/upload/safe', [SaveController::class, 'uploadSafe']);
    Route::post('/save/parse/safe',  [SaveController::class, 'parseSafe']);
    Route::post('/save/xml/safe',    [SaveController::class, 'importXmlSafe']);
    // [FALSE-POSITIVE] system() 字面量 — CWE-78 误报演示
    Route::get('/save/schema/safe', [SaveController::class, 'saveSchema']);
});
