<?php

namespace App\Http\Controllers;

use App\Models\Bet;
use App\Models\Player;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class BetController extends Controller
{
    /**
     * POST /api/bet
     *
     * 预埋漏洞：
     *   CWE-20 — 下注金额直接来自客户端，未做正负、范围、超额校验
     *            攻击者可传入负数反向套利，或传入超过余额的金额透支账户
     */
    public function bet(Request $request)
    {
        $request->validate([
            'player_id' => 'required|integer',
            'amount'    => 'required|numeric',  // CWE-20: 仅校验是数字，未限制正负与范围
        ]);

        $player = Player::findOrFail($request->player_id);

        // CWE-20: amount 直接来自客户端，未校验：
        //   1. 未限制正负：传入负数时"输球"反而加钱
        //   2. 未限制上限：可超过账户余额任意透支，balance 变负数
        //   3. 未限制精度：可传入极小分数操控计算
        //   4. 无事务保护：balance 更新与 Bet 记录写入非原子操作，
        //      并发场景下可能出现余额已扣但 Bet 未记录（或反之）的数据不一致
        $amount = (float) $request->amount;

        // 模拟游戏结果（50% 概率）
        // 无事务：save() 与 Bet::create() 之间若进程崩溃，数据将不一致
        $win           = (bool) random_int(0, 1);
        $balanceBefore = (float) $player->balance;
        $player->balance = $win
            ? $balanceBefore + $amount   // 赢：加钱（负数则反向扣钱）
            : $balanceBefore - $amount;  // 输：扣钱（负数则反向加钱）
        $player->save();  // CWE-20: 此处无事务，save 成功后若 create 失败则余额变更无法回滚

        Bet::create([
            'player_id'      => $player->id,
            'amount'         => $amount,
            'result'         => $win ? 'win' : 'lose',
            'balance_before' => $balanceBefore,
            'balance_after'  => $player->balance,
        ]);

        return response()->json([
            'message'        => $win ? 'You win!' : 'You lose!',
            'result'         => $win ? 'win' : 'lose',
            'amount'         => $amount,
            'balance_before' => $balanceBefore,
            'balance_after'  => $player->balance,
        ]);
    }

    /**
     * GET  /api/leaderboard          （API 路由，用于演示 CWE-89 SQL 注入）
     * POST /leaderboard              （Web 路由，用于演示 CWE-352 CSRF，已在 bootstrap/app.php 移除 CSRF 校验）
     *
     * 预埋漏洞：
     *   CWE-89  — name 参数直接拼接进原生 SQL，可注入任意 SQL 语句
     *   CWE-352 — Web 路由明确绕过了 CSRF Token 校验，跨站请求可直接触发 SQL 注入
     */
    public function leaderboard(Request $request)
    {
        // CWE-89: name 参数来自客户端，直接拼接到 SQL 字符串，未使用参数绑定
        // 攻击者可传入 ' OR '1'='1 等 Payload 绕过过滤，或使用 UNION SELECT 拖库
        $name = $request->input('name', '');

        // 漏洞：字符串拼接构造 SQL，name 未经任何转义
        $sql = "SELECT id, username, balance
                FROM players
                WHERE username LIKE '%" . $name . "%'
                ORDER BY balance DESC
                LIMIT 10";

        // CWE-352: 本方法同时挂载于 POST /leaderboard（Web 路由），
        // 该路由已在 bootstrap/app.php 中通过 exceptFromCsrf 明确绕过 CSRF 验证。
        // 任意外站页面可构造表单静默提交，以受害者身份触发上方 SQL 注入 Payload。
        $rows = DB::select($sql);

        return response()->json([
            'leaderboard' => $rows,
            'sql_debug'   => $sql,   // 调试字段：将完整 SQL 暴露给客户端（信息泄露）
        ]);
    }

    // -------------------------------------------------------------------------
    // 假阳性（安全对照）接口
    // -------------------------------------------------------------------------

    /**
     * POST /api/bet/safe
     *
     * 对应真实漏洞：CWE-20 下注金额未校验
     * 演示正确做法：金额正数校验 + 余额充足性验证 + 数据库事务保证一致性
     */
    public function betSafe(Request $request)
    {
        $request->validate([
            'player_id' => 'required|integer',
            // [SAFE] 原因：min:0.01 强制正数，max:1000 防止单次超额透支
            // 对比漏洞版本：'amount' => 'required|numeric'（CWE-20，负数可反向套利）
            'amount'    => 'required|numeric|min:0.01|max:1000',
        ]);

        // [SAFE] 原因：使用数据库事务，保证余额变更与下注记录的原子性，防止并发竞态条件
        $result = DB::transaction(function () use ($request) {
            // [SAFE] 原因：lockForUpdate() 加行锁，防止并发请求下的重复扣款
            $player = Player::lockForUpdate()->findOrFail($request->player_id);

            // [SAFE] 原因：服务端强制两位小数精度，防止精度攻击
            $amount = round((float) $request->amount, 2);

            // [SAFE] 原因：余额不足时拒绝下注，防止账户透支
            // 对比漏洞版本：无余额校验，可无限透支
            if ((float) $player->balance < $amount) {
                return ['error' => 'Insufficient balance', 'status' => 422];
            }

            $win           = (bool) random_int(0, 1);
            $balanceBefore = (float) $player->balance;
            $player->balance = $win
                ? $balanceBefore + $amount
                : $balanceBefore - $amount;
            $player->save();

            Bet::create([
                'player_id'      => $player->id,
                'amount'         => $amount,
                'result'         => $win ? 'win' : 'lose',
                'balance_before' => $balanceBefore,
                'balance_after'  => $player->balance,
            ]);

            return [
                'message'        => $win ? 'You win!' : 'You lose!',
                'result'         => $win ? 'win' : 'lose',
                'amount'         => $amount,
                'balance_before' => $balanceBefore,
                'balance_after'  => $player->balance,
            ];
        });

        if (isset($result['error'])) {
            return response()->json(['message' => $result['error']], $result['status']);
        }

        return response()->json($result);
    }

    /**
     * GET /api/leaderboard/safe
     *
     * 对应真实漏洞：CWE-89 SQL 注入
     * 演示正确做法：使用 Eloquent ORM 参数绑定，框架自动转义用户输入
     */
    public function leaderboardSafe(Request $request)
    {
        $name = $request->input('name', '');

        // [SAFE] 原因：Eloquent where() 使用 PDO 参数绑定，用户输入被视为纯字面值
        // 无论传入什么字符串（包括 ' UNION SELECT...），均不会改变 SQL 语义
        // 对比漏洞版本：$sql = "...WHERE username LIKE '%" . $name . "%'"（CWE-89 字符串拼接）
        $rows = Player::select('id', 'username', 'balance')
            ->where('username', 'like', '%' . $name . '%')
            ->orderByDesc('balance')
            ->limit(10)
            ->get();

        return response()->json([
            'leaderboard' => $rows,
            // [SAFE] 原因：不返回 sql_debug 字段，避免 SQL 语句信息泄露
        ]);
    }

    /**
     * GET /api/bet/rtp/safe
     *
     * [FALSE-POSITIVE] 触发特征: DB::select("字面量 SQL") | 实际安全: SQL 为字符串字面量，无用户输入参与构造
     * SAST 工具对任意 DB::select($str) 调用标记 CWE-89（SQL 注入），不区分 $str 是否含用户数据。
     * 此处整条 SQL 是编译期字面量，数据流分析可确认无 $request 数据流入该字符串。
     */
    public function returnToPlayer()
    {
        // [FALSE-POSITIVE] 触发特征: DB::select() 接收字符串参数 | 实际安全: 整条 SQL 为字符串字面量，无用户输入
        // SAST 工具对 DB::select($strVar) 的模式标记 CWE-89，即使此处 SQL 字符串与用户输入完全无关
        $result = \Illuminate\Support\Facades\DB::select(
            "SELECT 97.0 AS rtp_percent, 3.0 AS house_edge_percent, 'slot_standard' AS game_type"
        );

        return response()->json([
            'rtp_percent'        => $result[0]->rtp_percent,
            'house_edge_percent' => $result[0]->house_edge_percent,
            'game_type'          => $result[0]->game_type,
            'fp_note'            => 'DB::raw() argument is a string literal; no user data interpolated into SQL',
        ]);
    }
}
