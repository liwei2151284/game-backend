<?php

namespace App\Http\Controllers;

use App\Models\Player;
use App\Models\RechargeLog;
use Illuminate\Http\Request;

class RechargeController extends Controller
{
    // CWE-798: 硬编码第三方支付 API Key / Secret
    private const PAYMENT_API_KEY    = 'sk_live_paymentGateway_4f8b2c1d9e';
    private const PAYMENT_API_SECRET = 'pay_secret_a3f7e2b84c1d6e9f0a2b';
    private const PAYMENT_API_URL    = 'https://api.payment-gateway.example.com/v1/charge';

    /**
     * POST /api/recharge
     *
     * 预埋漏洞：
     *   CWE-532 — 将支付凭据与用户财务信息明文写入应用日志
     *   CWE-209 — 异常时返回完整堆栈信息（文件路径、框架版本、内部逻辑全暴露）
     *   CWE-798 — 第三方支付 API Key 硬编码在源码中
     */
    public function recharge(Request $request)
    {
        try {
            $request->validate([
                'player_id' => 'required|integer',
                'amount'    => 'required|numeric|min:0.01|max:10000',
                'note'      => 'nullable|string',   // 备注字段，供 CWE-1236 导出演示使用
            ]);
            // findOrFail：player_id 不存在时抛 ModelNotFoundException，触发 CWE-209
            $player = Player::findOrFail($request->player_id);

            $amount = round((float) $request->amount, 2);

            // CWE-798: callPaymentGateway 内部使用硬编码密钥
            $paymentResult = $this->callPaymentGateway($amount);

            if (!$paymentResult['success']) {
                return response()->json([
                    'message' => 'Payment failed',
                    'detail'  => $paymentResult['message'],
                ], 402);
            }

            $player->balance += $amount;
            $player->save();

            // CWE-532: 将支付凭据与用户财务数据明文写入应用日志
            // storage/logs/laravel.log 对运维/开发人员通常可读，密钥进入日志等同于泄露
            \Log::info('Recharge processed', [
                'player_id'      => $player->id,
                'username'       => $player->username,
                'amount'         => $amount,
                'balance_after'  => $player->balance,
                'api_key'        => self::PAYMENT_API_KEY,     // ← 支付密钥明文入日志
                'api_secret'     => self::PAYMENT_API_SECRET,  // ← 支付密钥明文入日志
                'transaction_id' => $paymentResult['transaction_id'],
            ]);

            // 将充值记录写入数据库（note 字段原样存储，为 CWE-1236 导出演示使用）
            RechargeLog::create([
                'player_id'      => $player->id,
                'amount'         => $amount,
                'note'           => $request->note,  // 用户输入，不做任何过滤
                'transaction_id' => $paymentResult['transaction_id'],
            ]);

            return response()->json([
                'message'          => 'Recharge successful',
                'player_id'        => $player->id,
                'amount_recharged' => $amount,
                'balance'          => $player->balance,
                'transaction_id'   => $paymentResult['transaction_id'],
            ]);

        } catch (\Throwable $e) {
            // CWE-209: 将完整异常信息（含文件路径、行号、堆栈跟踪）直接暴露给客户端
            // 攻击者可从中获取：绝对路径、框架版本、数据库表结构、业务逻辑分支
            return response()->json([
                'message'   => 'Internal error',
                'error'     => $e->getMessage(),       // 异常消息
                'exception' => get_class($e),          // 异常类名（泄露框架组件）
                'file'      => $e->getFile(),          // 服务器绝对路径
                'line'      => $e->getLine(),          // 出错行号
                'trace'     => $e->getTraceAsString(), // 完整调用栈
            ], 500);
        }
    }

    /**
     * GET /api/recharge/export
     *
     * 预埋漏洞：
     *   CWE-117 — filter 参数直接拼接进日志字符串，未过滤换行符
     *             攻击者可注入 \n 伪造任意日志条目，干扰安全审计
     */
    public function export(Request $request)
    {
        // CWE-117: filter 参数未过滤换行符，直接拼接进日志
        // 攻击者传入 ?filter=normal%0a[2099-01-01] local.INFO: Admin login successful
        // 日志文件中将出现一条完全伪造的记录，与真实条目格式一致
        $filter = $request->query('filter', '');
        \Log::info('Export requested: ' . $filter);

        $logs = RechargeLog::with('player')->get();

        $filename = 'recharge_export_' . date('Ymd_His') . '.csv';

        $headers = [
            'Content-Type'        => 'text/csv; charset=UTF-8',
            'Content-Disposition' => "attachment; filename=\"{$filename}\"",
            'Cache-Control'       => 'no-cache, no-store',
        ];

        $callback = function () use ($logs) {
            $handle = fopen('php://output', 'w');

            fwrite($handle, "\xEF\xBB\xBF");

            fputcsv($handle, ['ID', 'Player ID', 'Username', 'Amount', 'Note', 'Transaction ID', 'Created At']);

            foreach ($logs as $log) {
                fputcsv($handle, [
                    $log->id,
                    $log->player_id,
                    $log->player->username ?? 'unknown',
                    $log->amount,
                    $log->note,
                    $log->transaction_id,
                    $log->created_at,
                ]);
            }

            fclose($handle);
        };

        return response()->stream($callback, 200, $headers);
    }

    /**
     * GET /api/recharge/export/safe
     *
     * 对应真实漏洞：CWE-117 日志注入
     * 演示正确做法：过滤换行符 + 结构化日志字段，防止日志伪造
     */
    public function exportSafe(Request $request)
    {
        // [SAFE] 原因：str_replace 移除 \r\n，使用结构化数组而非字符串拼接
        // 对比漏洞版本：'Export requested: ' . $filter（CWE-117，换行可伪造日志）
        $filter = str_replace(["\r", "\n"], '', $request->query('filter', ''));
        \Log::info('Export requested', ['filter' => $filter]);

        $logs = RechargeLog::with('player')->get();

        $filename = 'recharge_export_safe_' . date('Ymd_His') . '.csv';

        $headers = [
            'Content-Type'        => 'text/csv; charset=UTF-8',
            'Content-Disposition' => "attachment; filename=\"{$filename}\"",
            'Cache-Control'       => 'no-cache, no-store',
        ];

        $callback = function () use ($logs) {
            $handle = fopen('php://output', 'w');

            fwrite($handle, "\xEF\xBB\xBF");

            fputcsv($handle, ['ID', 'Player ID', 'Username', 'Amount', 'Note', 'Transaction ID', 'Created At']);

            foreach ($logs as $log) {
                fputcsv($handle, [
                    $log->id,
                    $log->player_id,
                    $log->player->username ?? 'unknown',
                    $log->amount,
                    $log->note,
                    $log->transaction_id,
                    $log->created_at,
                ]);
            }

            fclose($handle);
        };

        return response()->stream($callback, 200, $headers);
    }

    // -------------------------------------------------------------------------
    // 假阳性（安全对照）接口
    // -------------------------------------------------------------------------

    /**
     * POST /api/recharge/safe
     *
     * 对应真实漏洞：CWE-532 日志中的明文敏感信息
     * 演示正确做法：日志只记录业务必要字段，绝不记录密钥或用户财务数据
     */
    public function rechargeSafe(Request $request)
    {
        // [SAFE] 原因：catch 块只返回通用错误消息，不泄露异常类、文件路径、堆栈
        // 对比漏洞版本：完整 exception/file/line/trace 全部暴露（CWE-209）
        try {
            $request->validate([
                'player_id' => 'required|integer',
                'amount'    => 'required|numeric|min:0.01|max:10000',
                'note'      => 'nullable|string|max:200',
            ]);

            $player = Player::findOrFail($request->player_id);

            $amount = round((float) $request->amount, 2);

            if ($amount <= 0 || $amount > 10000) {
                return response()->json(['message' => 'Invalid amount range'], 422);
            }

            $player->balance += $amount;
            $player->save();

            $transactionId = 'txn_safe_' . strtoupper(bin2hex(random_bytes(8)));

            // [SAFE] 原因：日志只记录业务必要字段，不含密钥、用户名、余额等敏感数据
            // 对比漏洞版本：api_key/api_secret/username/balance_after 全部明文写入日志（CWE-532）
            \Log::info('Recharge processed', [
                'player_id'      => $player->id,
                'transaction_id' => $transactionId,
            ]);

            RechargeLog::create([
                'player_id'      => $player->id,
                'amount'         => $amount,
                'note'           => $request->note,
                'transaction_id' => $transactionId,
            ]);

            return response()->json([
                'message'          => 'Recharge successful (safe)',
                'player_id'        => $player->id,
                'amount_recharged' => $amount,
                'balance'          => $player->balance,
            ]);

        } catch (\Illuminate\Validation\ValidationException $e) {
            // 校验错误正常返回，不视为内部异常
            throw $e;
        } catch (\Throwable $e) {
            // [SAFE] 原因：仅返回通用消息，绝不暴露 exception 类名、文件路径、行号、调用栈
            // 对比漏洞版本：'error'=>$e->getMessage(), 'file'=>$e->getFile(), 'trace'=>...（CWE-209）
            return response()->json(['message' => 'An internal error occurred'], 500);
        }
    }

    /**
     * 模拟调用第三方支付网关
     * CWE-798: API Key / Secret 硬编码，随源码进入版本仓库
     */
    private function callPaymentGateway(float $amount): array
    {
        // 实际项目中此处发起 HTTPS 请求，密钥通过 Authorization Header 传出
        // 源码一旦泄露，攻击者无需入侵服务器即可直接调用支付接口
        $headers = [
            'Authorization: Bearer ' . self::PAYMENT_API_KEY,    // ← 硬编码密钥
            'X-Api-Secret: '         . self::PAYMENT_API_SECRET,  // ← 硬编码密钥
        ];

        // 演示环境跳过真实请求，直接返回成功
        return [
            'success'        => true,
            'message'        => 'ok',
            'transaction_id' => 'txn_' . strtoupper(bin2hex(random_bytes(8))),
        ];
    }

    /**
     * GET /api/recharge/gateway-ping/safe
     *
     * [FALSE-POSITIVE] 触发特征: exec() 调用 | 实际安全: 命令为字符串字面量，无任何用户输入参与拼接
     * SAST 工具对任意 exec()/system()/shell_exec() 调用标记 CWE-78（OS 命令注入）。
     * 此处 exec() 的参数是 'php -r "echo PHP_VERSION;"'，完全固定，不含 $request 数据。
     */
    public function gatewayStatus()
    {
        // [FALSE-POSITIVE] 触发特征: exec() | 实际安全: 命令字符串字面量，$_GET/$_POST 未参与拼接
        exec('php -r "echo PHP_VERSION;"', $output, $exitCode);

        return response()->json([
            'php_version'    => $output[0] ?? 'unknown',
            'exit_code'      => $exitCode,
            'gateway_compat' => version_compare($output[0] ?? '0', '8.0.0', '>='),
            'fp_note'        => 'exec() argument is a string literal; no user data flows to the command',
        ]);
    }
}
