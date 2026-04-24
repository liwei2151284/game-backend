<?php

namespace App\Http\Controllers;

use App\Models\Player;
use App\Models\Withdrawal;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;

class WithdrawController extends Controller
{
    /**
     * POST /api/withdraw
     *
     * 预埋漏洞：
     *   CWE-639 — 不校验 player_id 与当前登录用户是否一致（越权提现）
     *   CWE-770 — 无频率限制、无单笔/日累计金额上限、无余额校验（资源耗尽）
     *   CWE-223 — 提现操作不写任何安全审计日志（安全日志缺失，对应 OWASP A09）
     */
    public function withdraw(Request $request)
    {
        $request->validate([
            'player_id'    => 'required|integer',
            'amount'       => 'required|numeric',  // CWE-770: 仅校验是数字，无上限、无余额核查
            'bank_account' => 'required|string',
            'callback_url' => 'nullable|string',
        ]);

        // CWE-639: 直接信任客户端传入的 player_id，不与 JWT/Session 做比对
        // 攻击者可传入任意玩家的 player_id，将他人余额提现到自己银行账户
        $player = Player::findOrFail($request->player_id);

        $amount = (float) $request->amount;

        // CWE-770: 缺失三项关键校验——
        //   1. 无余额校验：允许余额不足时超额提现（余额变负）
        //   2. 无单笔上限：可一次提现 999,999,999
        //   3. 无频率限制：同一账号可在一秒内发起无数次提现请求
        $balanceBefore  = (float) $player->balance;
        $player->balance -= $amount;
        $player->save();

        $withdrawal = Withdrawal::create([
            'player_id'    => $player->id,
            'amount'       => $amount,
            'bank_account' => $request->bank_account,
            'status'       => 'completed',
            'callback_url' => $request->callback_url,
            'ip_address'   => $request->ip(),
        ]);

        // CWE-223 / OWASP A09: 此处故意不记录任何安全审计日志
        // 生产环境应写入：
        //   Log::channel('security')->warning('withdrawal', [
        //       'operator_id'  => auth()->id(),       // 操作者（应与 player_id 一致）
        //       'player_id'    => $player->id,
        //       'amount'       => $amount,
        //       'bank_account' => $request->bank_account,
        //       'ip'           => $request->ip(),
        //       'user_agent'   => $request->userAgent(),
        //       'timestamp'    => now()->toIso8601String(),
        //   ]);
        // 日志缺失导致：事后无法溯源越权操作，合规审计无据可查

        return response()->json([
            'message'        => 'Withdrawal submitted',
            'withdrawal_id'  => $withdrawal->id,
            'player_id'      => $player->id,
            'amount'         => $amount,
            'balance_before' => $balanceBefore,
            'balance_after'  => $player->balance,
            'bank_account'   => $request->bank_account,
            'status'         => 'completed',
            'security_log'   => null,  // 安全日志为空——漏洞标识
        ]);
    }

    /**
     * POST /api/withdraw/notify
     *
     * 预埋漏洞：
     *   CWE-918 — SSRF：callback_url 完全由用户控制，服务端直接发起 HTTP/FILE 请求
     *             攻击者可借此探测/访问内网服务、云元数据接口、本地文件系统
     *
     * 支持的攻击 URL 示例：
     *   http://169.254.169.254/latest/meta-data/   → 读取 AWS EC2 实例元数据
     *   http://127.0.0.1:9001/admin                → 访问内网管理接口
     *   file:///etc/passwd                         → 读取本地系统文件
     *   http://192.168.1.1/                        → 扫描内网路由器
     */
    public function notify(Request $request)
    {
        $request->validate([
            'withdrawal_id' => 'required|integer',
            'callback_url'  => 'required|string',  // CWE-918: 不限制协议与目标地址
        ]);

        $withdrawal = Withdrawal::findOrFail($request->withdrawal_id);

        $callbackUrl = $request->callback_url;
        $payload = json_encode([
            'withdrawal_id' => $withdrawal->id,
            'player_id'     => $withdrawal->player_id,
            'amount'        => $withdrawal->amount,
            'status'        => $withdrawal->status,
        ]);

        // CWE-918: 使用 cURL 向用户指定的 URL 发起请求
        // cURL 默认支持 http/https/ftp/file/dict/gopher 等多种协议，攻击面极大
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $callbackUrl,         // ← 用户控制的 URL
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_FOLLOWLOCATION => true,                 // 自动跟随重定向（绕过防护）
            CURLOPT_SSL_VERIFYPEER => false,                // 不校验 SSL（方便内网 HTTP）
            CURLOPT_POSTFIELDS     => $payload,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        ]);

        $responseBody = curl_exec($ch);
        $responseCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError    = curl_error($ch);
        curl_close($ch);

        return response()->json([
            'message'           => 'Notification dispatched',
            'callback_url'      => $callbackUrl,            // 请求目标（明文返回）
            'callback_status'   => $responseCode,
            'callback_response' => $responseBody ?: $curlError, // 内网响应直接透传给攻击者
        ]);
    }

    // -------------------------------------------------------------------------
    // 假阳性（安全对照）接口
    // -------------------------------------------------------------------------

    /**
     * POST /api/withdraw/safe
     *
     * 对应真实漏洞：CWE-639 越权提现、CWE-770 无频率/金额限制、CWE-223 安全日志缺失
     * 演示正确做法：认证身份绑定 + RateLimiter 频率限制 + 余额校验 + 安全审计日志
     */
    public function withdrawSafe(Request $request)
    {
        $request->validate([
            'player_id'    => 'required|integer',
            // [SAFE] 原因：min:0.01 强制正数，max:50000 设置单笔上限，防止 CWE-770
            'amount'       => 'required|numeric|min:0.01|max:50000',
            'bank_account' => 'required|string',
        ]);

        // [SAFE] 原因：使用 RateLimiter 限制同一 IP 每分钟最多 5 次提现请求
        // 对比漏洞版本：无任何频率限制（CWE-770）
        $rateLimitKey = 'withdraw_safe:' . $request->ip();
        if (RateLimiter::tooManyAttempts($rateLimitKey, 5)) {
            return response()->json(['message' => 'Too many withdrawal requests, please wait'], 429);
        }
        RateLimiter::hit($rateLimitKey, 60);

        // [SAFE] 原因：从请求头取认证身份（生产环境应为 Auth::id() 或 JWT 解码的 sub）
        // 对比漏洞版本：直接信任客户端传入的 player_id（CWE-639）
        $authPlayerId = (int) $request->header('X-Player-Id', 0);
        if ($authPlayerId !== (int) $request->player_id) {
            // [SAFE] 原因：认证身份与请求 player_id 不一致，拒绝越权操作
            return response()->json(['message' => 'Forbidden: player_id does not match authenticated user'], 403);
        }

        $player = Player::findOrFail($request->player_id);
        $amount = round((float) $request->amount, 2);

        // [SAFE] 原因：校验余额充足性，防止账户透支
        // 对比漏洞版本：直接扣款，余额可变负（CWE-770）
        if ((float) $player->balance < $amount) {
            return response()->json(['message' => 'Insufficient balance'], 422);
        }

        $balanceBefore   = (float) $player->balance;
        $player->balance -= $amount;
        $player->save();

        $withdrawal = Withdrawal::create([
            'player_id'    => $player->id,
            'amount'       => $amount,
            'bank_account' => $request->bank_account,
            'status'       => 'completed',
            'callback_url' => null,
            'ip_address'   => $request->ip(),
        ]);

        // [SAFE] 原因：写入安全审计日志，满足 OWASP A09 合规要求（CWE-223 对照）
        // 对比漏洞版本：security_log => null，无任何审计记录
        Log::info('security.withdrawal', [
            'withdrawal_id' => $withdrawal->id,
            'player_id'     => $player->id,
            'amount'        => $amount,
            // [SAFE] 原因：银行卡号脱敏，仅记录前四位，保护敏感数据
            'bank_account'  => substr($request->bank_account, 0, 4) . str_repeat('*', max(0, strlen($request->bank_account) - 4)),
            'ip'            => $request->ip(),
            'user_agent'    => $request->userAgent(),
            'timestamp'     => now()->toIso8601String(),
        ]);

        return response()->json([
            'message'        => 'Withdrawal submitted (safe)',
            'withdrawal_id'  => $withdrawal->id,
            'player_id'      => $player->id,
            'amount'         => $amount,
            'balance_before' => $balanceBefore,
            'balance_after'  => $player->balance,
            'status'         => 'completed',
            'security_log'   => 'recorded',  // [SAFE] 原因：已写入安全审计日志
        ]);
    }

    /**
     * POST /api/withdraw/notify/safe
     *
     * 对应真实漏洞：CWE-918 SSRF 服务端请求伪造
     * 演示正确做法：协议白名单 + 域名白名单 + DNS Rebinding 防护
     */
    public function notifySafe(Request $request)
    {
        $request->validate([
            'withdrawal_id' => 'required|integer',
            'callback_url'  => 'required|string',
        ]);

        $callbackUrl = $request->callback_url;
        $parsed      = parse_url($callbackUrl);

        // [SAFE] 原因：协议白名单，仅允许 https，拒绝 http/file/gopher/ftp 等危险协议
        // 对比漏洞版本：cURL 支持任意协议（CWE-918）
        if (!$parsed || ($parsed['scheme'] ?? '') !== 'https') {
            return response()->json(['message' => 'Only HTTPS callback URLs are allowed'], 422);
        }

        // [SAFE] 原因：域名白名单，仅允许预先注册的可信回调域名
        // 生产环境应从数据库或配置文件维护白名单
        $allowedHosts = array_filter(
            explode(',', env('CALLBACK_ALLOWED_HOSTS', 'webhook.example.com,notify.partner.com'))
        );
        if (!in_array($parsed['host'] ?? '', $allowedHosts, true)) {
            return response()->json(['message' => 'Callback host not in whitelist'], 422);
        }

        // [SAFE] 原因：DNS 解析后二次 IP 校验，防止 DNS Rebinding 攻击
        // 攻击者可能先将域名指向合法 IP 通过白名单，再改为内网 IP
        $resolvedIp = gethostbyname($parsed['host']);
        if (filter_var(
            $resolvedIp,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false) {
            return response()->json(['message' => 'Callback to private/reserved IP is not allowed'], 422);
        }

        $withdrawal = Withdrawal::findOrFail($request->withdrawal_id);
        $payload    = json_encode([
            'withdrawal_id' => $withdrawal->id,
            'status'        => $withdrawal->status,
        ]);

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $callbackUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_FOLLOWLOCATION => false,   // [SAFE] 原因：禁止跟随重定向，防止绕过域名白名单
            CURLOPT_SSL_VERIFYPEER => true,    // [SAFE] 原因：强制验证 SSL 证书
            CURLOPT_POSTFIELDS     => $payload,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        ]);

        // [SAFE] 原因：正确执行请求后再读取状态码（原有 bug：curl_init() 二次调用导致 exec 未执行）
        curl_exec($ch);
        $responseCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return response()->json([
            'message'         => 'Notification dispatched (safe)',
            'callback_status' => $responseCode,
            // [SAFE] 原因：不返回 callback_response，防止内网信息透传给请求方
        ]);
    }

    /**
     * GET /api/withdraw/fee-table/safe
     *
     * [FALSE-POSITIVE] 触发特征: call_user_func() 调用 | 实际安全: 函数名与参数均为字面量，无用户输入
     * SAST 工具对 call_user_func() / call_user_func_array() 调用标记 CWE-77（命令注入），
     * 担心函数名可能由攻击者控制（如 system、exec）。
     * 此处函数名 'array_values' 和参数数组均为编译期常量，无任何 $request 数据参与。
     */
    public function feeTable()
    {
        // [FALSE-POSITIVE] 触发特征: call_user_func() | 实际安全: 函数名与参数均为字面量，无用户数据流入
        $tiers = call_user_func('array_values', [
            ['min' =>     0, 'max' =>  1000, 'fee_pct' => 1.5, 'desc' => '小额提现'],
            ['min' =>  1001, 'max' => 10000, 'fee_pct' => 1.0, 'desc' => '中额提现'],
            ['min' => 10001, 'max' => 50000, 'fee_pct' => 0.5, 'desc' => '大额提现'],
        ]);

        return response()->json([
            'fee_tiers' => $tiers,
            'currency'  => 'CNY',
            'fp_note'   => 'call_user_func() uses a literal function name; no user data controls the callable',
        ]);
    }
}
