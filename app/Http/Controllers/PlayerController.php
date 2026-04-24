<?php

namespace App\Http\Controllers;

use App\Models\Player;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class PlayerController extends Controller
{
    // CWE-321: 硬编码弱密钥（9字节，可被字典爆破）
    private const JWT_SECRET = 'secret123';

    /**
     * POST /api/register
     *
     * 预埋漏洞：
     *   CWE-256 — 密码明文存储（未哈希）
     *   CWE-310 — 邀请码使用弱随机数（mt_rand）生成
     */
    public function register(Request $request)
    {
        $request->validate([
            'username' => 'required|string|unique:players,username',
            'password' => 'required|string',
            'email'    => 'required|email|unique:players,email',
        ]);

        // CWE-310: 使用 mt_rand（伪随机，可预测）生成邀请码
        // mt_rand 基于 Mersenne Twister，种子空间有限，可通过已知输出推算后续码
        $inviteCode = strtoupper(substr(md5((string) mt_rand(0, 99999)), 0, 8));

        // CWE-256: 密码未经任何哈希，原文直接写入数据库
        $player = Player::create([
            'username'    => $request->username,
            'password'    => $request->password,   // ← 明文存储
            'email'       => $request->email,
            'balance'     => 0.00,
            'invite_code' => $inviteCode,
        ]);

        // created_at 由数据库 DEFAULT CURRENT_TIMESTAMP 自动填充，需 refresh() 回填到模型实例
        $player->refresh();

        return response()->json([
            'message' => 'Registration successful',
            'player'  => [
                'id'          => $player->id,
                'username'    => $player->username,
                'email'       => $player->email,
                'balance'     => $player->balance,
                'invite_code' => $player->invite_code,
                'created_at'  => $player->created_at,
            ],
        ], 201);
    }

    /**
     * POST /api/login
     *
     * 预埋漏洞：
     *   CWE-321 — JWT 使用硬编码弱密钥 secret123
     *   CWE-307 — 登录失败不限频率（无速率限制、无锁定机制）
     *   CWE-601 — 登录成功后重定向地址直接取自客户端参数，不做白名单校验
     */
    public function login(Request $request)
    {
        $request->validate([
            'username' => 'required|string',
            'password' => 'required|string',
        ]);

        // CWE-307: 无任何失败计数、延迟或账号锁定，允许无限次暴力破解
        $player = Player::where('username', $request->username)->first();

        // CWE-256: 明文密码直接比对
        if (!$player || $player->password !== $request->password) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }
        $now     = time();
        $payload = [
            'iss'      => 'game-backend',
            'iat'      => $now,
            'exp'      => $now + 3600,
            'sub'      => $player->id,
            'username' => $player->username,
        ];

        // CWE-321: 使用硬编码弱密钥 secret123 签发 JWT
        $token = $this->jwtEncode($payload, self::JWT_SECRET);

        // CWE-601: redirect 参数来自客户端，未做任何白名单/域名校验
        // 攻击者可构造 ?redirect=https://evil.com 实施钓鱼攻击
        $redirectUrl = $request->query('redirect');

        $response = [
            'message'  => 'Login successful',
            'token'    => $token,
            'player'   => [
                'id'       => $player->id,
                'username' => $player->username,
                'email'    => $player->email,
                'balance'  => $player->balance,
            ],
        ];

        if ($redirectUrl) {
            // 漏洞: 直接将攻击者控制的 URL 返回给前端，前端将执行跳转
            $response['redirect'] = $redirectUrl;
        }

        return response()->json($response);
    }

    /**
     * 自实现 JWT 编码（故意不校验密钥强度，保留弱密钥漏洞）
     */
    private function jwtEncode(array $payload, string $secret): string
    {
        $header  = $this->base64UrlEncode(json_encode(['typ' => 'JWT', 'alg' => 'HS256']));
        $payload = $this->base64UrlEncode(json_encode($payload));
        $sig     = $this->base64UrlEncode(hash_hmac('sha256', "$header.$payload", $secret, true));
        return "$header.$payload.$sig";
    }

    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    // -------------------------------------------------------------------------
    // 假阳性（安全对照）接口
    // -------------------------------------------------------------------------

    /**
     * POST /api/register/safe
     *
     * 对应真实漏洞：CWE-256 明文存储密码
     * 演示正确做法：使用 Hash::make() Bcrypt 哈希存储密码
     */
    public function registerSafe(Request $request)
    {
        $request->validate([
            'username' => 'required|string|unique:players,username',
            // [SAFE] 原因：强制最小密码长度，防止极弱口令
            'password' => 'required|string|min:8',
            'email'    => 'required|email|unique:players,email',
        ]);

        // [SAFE] 原因：使用 Bcrypt 哈希存储密码（cost=12），即使数据库泄露也无法还原明文
        // 对比漏洞版本：'password' => $request->password（CWE-256 明文存储）
        $hashedPassword = Hash::make($request->password);

        // [SAFE] 原因：使用密码学安全随机函数 random_bytes() 生成邀请码
        // 对比漏洞版本：mt_rand(0, 99999)（CWE-310 可预测伪随机数）
        $inviteCode = strtoupper(bin2hex(random_bytes(4)));

        $player = Player::create([
            'username'    => $request->username,
            'password'    => $hashedPassword,   // [SAFE] 原因：Bcrypt 哈希，非明文
            'email'       => $request->email,
            'balance'     => 0.00,
            'invite_code' => $inviteCode,       // [SAFE] 原因：CSPRNG 生成，不可预测
        ]);

        // created_at 由数据库 DEFAULT CURRENT_TIMESTAMP 自动填充，需 refresh() 回填到模型实例
        $player->refresh();

        return response()->json([
            'message' => 'Registration successful (safe)',
            'player'  => [
                'id'          => $player->id,
                'username'    => $player->username,
                'email'       => $player->email,
                'balance'     => $player->balance,
                'invite_code' => $player->invite_code,
                'created_at'  => $player->created_at,
            ],
        ], 201);
    }

    /**
     * POST /api/login/safe
     *
     * 对应真实漏洞：CWE-321 JWT 硬编码弱密钥
     * 演示正确做法：JWT 密钥从环境变量读取，并进行强度校验
     */
    public function loginSafe(Request $request)
    {
        $request->validate([
            'username' => 'required|string',
            'password' => 'required|string',
        ]);

        $player = Player::where('username', $request->username)->first();

        // [SAFE] 原因：Hash::check() 使用恒定时间比对，防止时序攻击
        // 对比漏洞版本：$player->password !== $request->password（明文直接比较）
        if (!$player || !Hash::check($request->password, $player->password)) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        // [SAFE] 原因：JWT 密钥从环境变量读取，不硬编码在源码中
        // 对比漏洞版本：private const JWT_SECRET = 'secret123'（CWE-321）
        $jwtSecret = env('JWT_SECRET', '');

        // [SAFE] 原因：校验密钥强度，少于 32 字符视为未配置，拒绝签发（防止使用默认弱密钥）
        if (strlen($jwtSecret) < 32) {
            return response()->json([
                'message' => 'Server misconfiguration: JWT_SECRET not set or too weak',
            ], 500);
        }

        $now     = time();
        $payload = [
            'iss'      => 'game-backend',
            'iat'      => $now,
            'exp'      => $now + 3600,
            'sub'      => $player->id,
            'username' => $player->username,
        ];

        $token = $this->jwtEncode($payload, $jwtSecret);

        return response()->json([
            'message' => 'Login successful (safe)',
            'token'   => $token,
            'player'  => [
                'id'       => $player->id,
                'username' => $player->username,
                'email'    => $player->email,
                'balance'  => $player->balance,
            ],
            // [SAFE] 原因：不返回 redirect 字段，消除 CWE-601 开放重定向风险
        ]);
    }

    /**
     * GET /api/register/policy/safe
     *
     * [FALSE-POSITIVE] 触发特征: eval() 调用 | 实际安全: 参数为字符串字面量，无任何用户输入流入
     * SAST 工具对任意 eval() 调用标记 CWE-95（代码注入），不区分参数来源。
     * 此处 eval() 的唯一参数是编译期字符串常量，不包含任何来自 $request 的数据。
     */
    public function passwordPolicy()
    {
        // [FALSE-POSITIVE] 触发特征: eval() | 实际安全: 字面量字符串，无用户数据流入，不存在注入路径
        $policy = eval('return [
            "min_length"       => 8,
            "require_upper"    => true,
            "require_digit"    => true,
            "require_special"  => true,
            "max_age_days"     => 90,
            "complexity_score" => 95,
        ];');

        return response()->json([
            'password_policy' => $policy,
            'fp_note'         => 'eval() argument is a compile-time string literal; no user data involved',
        ]);
    }
}
