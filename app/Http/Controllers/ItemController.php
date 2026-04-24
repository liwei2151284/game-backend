<?php

namespace App\Http\Controllers;

use App\Models\Item;
use App\Models\Player;
use Illuminate\Http\Request;

class ItemController extends Controller
{
    /**
     * POST /api/item/exchange/{id}
     *
     * 预埋漏洞：
     *   CWE-639 — 不校验道具归属，任意玩家可兑换他人道具（越权 IDOR）
     *
     * 正常逻辑应验证：$item->player_id === $request->player_id
     * 此处仅凭 URL 中的 {id} 直接操作道具，不做归属校验
     */
    public function exchange(Request $request, int $id)
    {
        $request->validate([
            'player_id' => 'required|integer',
        ]);

        // CWE-639: 仅按 ID 查找道具，不验证该道具是否属于请求方玩家
        // 攻击者可遍历 ID（1、2、3...）兑换任意玩家的道具并获得奖励
        $item = Item::findOrFail($id);

        if ($item->is_exchanged) {
            return response()->json([
                'message'  => 'Item already exchanged',
                'item_id'  => $item->id,
                'owner_id' => $item->player_id,
            ], 400);
        }

        // 漏洞核心：未检查 $item->player_id === $request->player_id
        // 兑换奖励归入请求方玩家，而非道具真正的归属者
        $requester = Player::findOrFail($request->player_id);

        $item->is_exchanged = true;
        $item->save();

        $requester->balance += $item->value;
        $requester->save();

        return response()->json([
            'message'         => 'Exchange successful',
            'item_id'         => $item->id,
            'item_name'       => $item->name,
            'item_owner_id'   => $item->player_id,    // 道具真实归属者
            'requester_id'    => $requester->id,       // 实际发起兑换的人
            'value_gained'    => $item->value,
            'balance_after'   => $requester->balance,
            'idor_triggered'  => $item->player_id !== $requester->id, // 是否触发越权
        ]);
    }

    /**
     * GET /api/item/image?path=<filename>
     *
     * 预埋漏洞：
     *   CWE-22 — 文件路径由用户传入，未做任何过滤或限制
     *            攻击者可通过 ../ 遍历读取服务器任意文件（如 .env、配置文件）
     */
    public function image(Request $request)
    {
        $request->validate([
            'path' => 'required|string',
        ]);

        // CWE-22: path 参数直接拼接到基础路径，未过滤 ../ 序列
        // 合法用途：?path=sword.png → public/items/sword.png
        // 攻击用途：?path=../../.env → 读取项目根目录 .env 文件
        $basePath = public_path('items/');
        $fullPath = $basePath . $request->query('path');

        // 漏洞：未调用 realpath() 归一化路径，未校验路径是否在 basePath 内
        if (!file_exists($fullPath)) {
            return response()->json([
                'message'   => 'File not found',
                'attempted' => $fullPath,   // 调试字段：将拼接后的路径暴露（信息泄露）
            ], 404);
        }

        // 直接将文件内容返回，无类型或目录校验
        $mimeType = mime_content_type($fullPath) ?: 'application/octet-stream';
        return response()->file($fullPath, ['Content-Type' => $mimeType]);
    }

    // -------------------------------------------------------------------------
    // 假阳性（安全对照）接口
    // -------------------------------------------------------------------------

    /**
     * POST /api/item/exchange/safe/{id}
     *
     * 对应真实漏洞：CWE-639 越权 IDOR（无归属校验）
     * 演示正确做法：查询时加入 player_id 归属条件，禁止越权兑换
     */
    public function exchangeSafe(Request $request, int $id)
    {
        $request->validate([
            'player_id' => 'required|integer',
        ]);

        // [SAFE] 原因：在查询条件中同时要求 id 与 player_id 匹配，确保只有归属者可操作
        // 对比漏洞版本：Item::findOrFail($id)（CWE-639，不校验归属）
        $item = Item::where('id', $id)
            ->where('player_id', $request->player_id)  // [SAFE] 原因：归属校验
            ->first();

        if (!$item) {
            // [SAFE] 原因：道具不存在或不属于该玩家，统一返回 403，避免枚举信息泄露
            return response()->json([
                'message' => 'Forbidden: item not found or does not belong to you',
            ], 403);
        }

        if ($item->is_exchanged) {
            return response()->json([
                'message' => 'Item already exchanged',
                'item_id' => $item->id,
            ], 400);
        }

        $player = Player::findOrFail($request->player_id);

        $item->is_exchanged = true;
        $item->save();

        $player->balance += $item->value;
        $player->save();

        return response()->json([
            'message'       => 'Exchange successful (safe)',
            'item_id'       => $item->id,
            'item_name'     => $item->name,
            'value_gained'  => $item->value,
            'balance_after' => $player->balance,
            // [SAFE] 原因：不返回 idor_triggered / item_owner_id 等调试字段
        ]);
    }

    /**
     * GET /api/item/image/safe?path=<filename>
     *
     * 对应真实漏洞：CWE-22 路径遍历
     * 演示正确做法：realpath() 归一化路径 + 白名单目录前缀校验
     */
    public function imageSafe(Request $request)
    {
        $request->validate([
            'path' => 'required|string',
        ]);

        // [SAFE] 原因：对基础目录调用 realpath()，解析所有符号链接，得到规范绝对路径
        $basePath = realpath(public_path('items'));

        if ($basePath === false) {
            return response()->json(['message' => 'Server configuration error'], 500);
        }

        // [SAFE] 原因：对拼接后的完整路径再次调用 realpath()，展开所有 ../ 并归一化
        // 对比漏洞版本：$fullPath = $basePath . $request->query('path')（CWE-22，无过滤）
        $fullPath = realpath($basePath . DIRECTORY_SEPARATOR . $request->query('path'));

        // [SAFE] 原因：白名单前缀校验——归一化后的路径必须以 basePath/ 开头
        // 即使传入 ../../.env，realpath() 会返回真实路径，strpos 检测可发现越界
        if ($fullPath === false || strpos($fullPath, $basePath . DIRECTORY_SEPARATOR) !== 0) {
            // [SAFE] 原因：拒绝时不返回 attempted 路径，避免路径信息泄露
            return response()->json(['message' => 'Access denied'], 403);
        }

        if (!file_exists($fullPath)) {
            return response()->json(['message' => 'File not found'], 404);
        }

        $mimeType = mime_content_type($fullPath) ?: 'application/octet-stream';
        return response()->file($fullPath, ['Content-Type' => $mimeType]);
    }

    /**
     * GET /api/item/list?player_id=<id>
     *
     * 辅助接口：查看玩家的道具列表（用于 IDOR 演示前确认道具归属）
     */
    public function list(Request $request)
    {
        $request->validate([
            'player_id' => 'required|integer',
        ]);

        $items = Item::where('player_id', $request->player_id)->get();

        return response()->json(['items' => $items]);
    }

    /**
     * GET /api/item/catalog-defaults/safe
     *
     * [FALSE-POSITIVE] 触发特征: unserialize() 调用 | 实际安全: 序列化字符串为硬编码字面量，无用户输入
     * SAST 工具对任意 unserialize() 调用标记 CWE-502（不安全反序列化），不区分数据来源。
     * 此处 unserialize() 的参数是编译期字符串常量，不包含来自 $request 的任何数据。
     */
    public function itemCatalogDefaults()
    {
        // [FALSE-POSITIVE] 触发特征: unserialize() | 实际安全: 参数为硬编码序列化字符串，无用户数据流入
        $defaults = unserialize(
            'a:3:{' .
            's:6:"weapon";a:2:{s:4:"name";s:5:"Sword";s:6:"rarity";s:4:"epic";}' .
            's:5:"armor";a:2:{s:4:"name";s:6:"Shield";s:6:"rarity";s:4:"rare";}' .
            's:6:"potion";a:2:{s:4:"name";s:13:"Health Potion";s:6:"rarity";s:6:"common";}' .
            '}'
        );

        return response()->json([
            'catalog_defaults' => $defaults,
            'fp_note'          => 'unserialize() argument is a hardcoded literal; no user data flows here',
        ]);
    }
}
