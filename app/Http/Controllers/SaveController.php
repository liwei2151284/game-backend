<?php

namespace App\Http\Controllers;

use App\Helpers\GameSaveLogger; // 使 Gadget 类在反序列化时可被自动加载（CWE-502 必要条件）
use Illuminate\Http\Request;

class SaveController extends Controller
{
    /**
     * POST /api/save/upload
     *
     * 预埋漏洞：
     *   CWE-434 — 不校验文件类型/扩展名，任意文件（含 .php Webshell）均可上传
     *             上传目录为 public/uploads/，通过 HTTP 可直接访问并执行 PHP 文件
     *   CWE-78  — 上传后用客户端可控的文件名拼接 exec() 命令，未调用 escapeshellarg()
     *             攻击者可通过构造文件名（如 "save.sav; whoami"）注入任意 shell 命令
     */
    public function upload(Request $request)
    {
        $request->validate([
            'player_id' => 'required|integer',
            // CWE-434: 仅校验字段存在且是文件，不限制 mimes/extensions/size
            'save_file' => 'required|file',
        ]);

        $file         = $request->file('save_file');
        $originalName = $file->getClientOriginalName();
        $fileSize     = $file->getSize();   // move() 之前读取，否则临时文件消失后报错

        // CWE-434: 文件名直接来自客户端，仅加时间戳前缀，不做扩展名过滤
        // .php 文件上传后可通过 http://localhost:8000/uploads/xxx.php 直接执行
        $filename   = time() . '_' . $originalName;
        $uploadPath = public_path('uploads');

        $file->move($uploadPath, $filename);

        // CWE-78: $filename 含客户端可控的 $originalName，直接拼入 exec()，未转义
        // 攻击者文件名 "save.sav; id" → exec("md5sum .../1234_save.sav; id") → RCE
        // 正确做法：使用 md5_file()（PHP 内置），或至少用 escapeshellarg() 包裹路径
        exec('md5sum ' . $uploadPath . DIRECTORY_SEPARATOR . $filename, $output);
        $checksum = isset($output[0]) ? explode(' ', $output[0])[0] : null;

        $fileUrl = url('uploads/' . $filename);

        return response()->json([
            'message'      => 'Save file uploaded successfully',
            'filename'     => $filename,
            'original'     => $originalName,
            'size'         => $fileSize,
            'url'          => $fileUrl,
            'checksum'     => $checksum,
            'mime_checked' => false,
        ]);
    }

    /**
     * POST /api/save/parse
     *
     * 预埋漏洞：
     *   CWE-502 — 直接对用户传入的 Base64 内容调用 unserialize()
     *             攻击者可注入含恶意 __destruct() 的对象（如 GameSaveLogger），
     *             在 PHP GC 销毁对象时触发任意文件写入，植入 Webshell
     */
    public function parse(Request $request)
    {
        $request->validate([
            // CWE-502: 只要求是字符串，不校验内容合法性
            'data'      => 'required|string',
            'player_id' => 'required|integer',
        ]);

        // CWE-502: Base64 解码后直接 unserialize，无类名白名单限制
        // PHP 8.x 推荐使用 unserialize($data, ['allowed_classes' => ['App\Models\GameSave']])
        // 此处故意不设置 allowed_classes，允许任意类被反序列化并触发魔术方法
        $raw      = base64_decode($request->data);
        $saveData = unserialize($raw); // ← 危险：可触发 GameSaveLogger::__destruct()

        // 若反序列化的是合法存档对象，将其转为数组返回
        $result = is_object($saveData) ? (array) $saveData : $saveData;

        return response()->json([
            'message'    => 'Save data parsed',
            'player_id'  => $request->player_id,
            'save_data'  => $result,
            'type'       => gettype($saveData),
            'class'      => is_object($saveData) ? get_class($saveData) : null,
        ]);
    }

    /**
     * POST /api/save/import
     *
     * 预埋漏洞：
     *   CWE-611 — XML 解析时通过 LIBXML_NOENT | LIBXML_DTDLOAD 启用外部实体
     *             攻击者可注入 <!ENTITY xxe SYSTEM "file:///etc/passwd"> 读取本地文件
     *             或通过 http:// 实体发起内网请求（XXE→SSRF）
     */
    public function importXml(Request $request)
    {
        $request->validate([
            'xml_content' => 'required|string',
            'player_id'   => 'required|integer',
        ]);

        $xmlContent = $request->xml_content;

        // CWE-611: 关闭 PHP 的外部实体加载限制（此函数在 PHP 8 中虽被弃用但仍有效）
        // 正确做法应为 libxml_disable_entity_loader(true) 或不传 LIBXML_NOENT 标志
        @libxml_disable_entity_loader(false);

        $dom = new \DOMDocument();
        // CWE-611: LIBXML_NOENT 替换实体引用（含外部实体）；LIBXML_DTDLOAD 加载 DTD
        // 两个标志组合使 XXE 可读取任意本地文件或发起内网 HTTP 请求
        $dom->loadXML($xmlContent, LIBXML_NOENT | LIBXML_DTDLOAD);

        // 提取存档字段
        $playerId = optional($dom->getElementsByTagName('player_id')->item(0))->nodeValue;
        $level    = optional($dom->getElementsByTagName('level')->item(0))->nodeValue;
        $score    = optional($dom->getElementsByTagName('score')->item(0))->nodeValue;
        $notes    = optional($dom->getElementsByTagName('notes')->item(0))->nodeValue;

        return response()->json([
            'message'   => 'XML save imported successfully',
            'player_id' => $playerId,
            'level'     => $level,
            'score'     => $score,
            'notes'     => $notes,  // XXE 注入内容会出现在此字段
        ]);
    }

    // -------------------------------------------------------------------------
    // 假阳性（安全对照）接口
    // -------------------------------------------------------------------------

    /**
     * POST /api/save/upload/safe
     *
     * 对应真实漏洞：CWE-434 不限制文件上传类型 + CWE-78 OS 命令注入
     * 演示正确做法：MIME 白名单 + 扩展名限制 + 大小限制 + 安全目录 + PHP 内置函数替代 shell 命令
     */
    public function uploadSafe(Request $request)
    {
        $request->validate([
            'player_id' => 'required|integer',
            // [SAFE] 原因：mimes 白名单仅允许合法存档格式，max 限制文件大小（512 KB）
            // 对比漏洞版本：'save_file' => 'required|file'（CWE-434，无任何类型/大小限制）
            'save_file' => 'required|file|mimes:json,bin,sav|max:512',
        ]);

        $file     = $request->file('save_file');
        $fileSize = $file->getSize();

        // [SAFE] 原因：服务端重新生成文件名，不含任何用户输入，彻底切断 CWE-78 污点来源
        // 对比漏洞版本：$filename = time() . '_' . $originalName（客户端控制，CWE-78 污点源）
        $safeFilename = 'save_' . $request->player_id . '_' . time() . '.sav';

        // [SAFE] 原因：存储至 storage/app/saves，该目录位于 Web 根目录外，HTTP 不可直接访问
        // 对比漏洞版本：public_path('uploads')（Web 可达，.php 文件可直接执行，CWE-434）
        $savePath = storage_path('app/saves');
        if (!is_dir($savePath)) {
            mkdir($savePath, 0755, true);
        }

        $file->move($savePath, $safeFilename);

        // [SAFE] 原因：使用 PHP 内置 md5_file()，完全避免 shell 命令调用
        // 对比漏洞版本：exec('md5sum ' . $filename)（用户可控文件名拼入命令，CWE-78）
        $checksum = md5_file($savePath . DIRECTORY_SEPARATOR . $safeFilename);

        return response()->json([
            'message'        => 'Save file uploaded successfully (safe)',
            'filename'       => $safeFilename,
            'size'           => $fileSize,
            'checksum'       => $checksum,
            'mime_checked'   => true,
            'web_accessible' => false,
        ]);
    }

    /**
     * POST /api/save/parse/safe
     *
     * 对应真实漏洞：CWE-502 不安全反序列化（PHP 对象注入）
     * 演示正确做法：unserialize() 指定 allowed_classes => false，禁止任何自定义类实例化
     */
    public function parseSafe(Request $request)
    {
        $request->validate([
            'data'      => 'required|string',
            'player_id' => 'required|integer',
        ]);

        $raw = base64_decode($request->data);

        if ($raw === false || strlen($raw) === 0) {
            return response()->json(['message' => 'Invalid base64 data'], 400);
        }

        // [SAFE] 原因：PHP 8.x 中 allowed_classes => false 仍会在 GC 时调用 __destruct()
        // （若目标类已被 autoload 加载到当前进程），因此不能仅靠 allowed_classes 防御。
        // 正确做法：在 unserialize 调用前用正则预检，拒绝含对象标记的序列化字符串。
        // PHP 对象序列化格式为 O:<长度>:"<类名>":... 提前拦截即可完全阻断 Gadget 链。
        // 对比漏洞版本：unserialize($raw)（无任何限制，CWE-502，触发任意魔术方法）
        if (preg_match('/O:\d+:"/', $raw)) {
            return response()->json(['message' => 'Object types are not permitted in safe parse mode'], 403);
        }

        $saveData = unserialize($raw, ['allowed_classes' => false]);

        if ($saveData === false) {
            return response()->json(['message' => 'Invalid save data format'], 400);
        }

        if (is_object($saveData)) {
            return response()->json(['message' => 'Object types are not permitted in safe parse mode'], 403);
        }

        return response()->json([
            'message'   => 'Save data parsed (safe)',
            'player_id' => $request->player_id,
            'save_data' => $saveData,
            'type'      => gettype($saveData),
            // [SAFE] 原因：不返回 class 字段，避免泄露内部类名
        ]);
    }

    /**
     * POST /api/save/xml/safe
     *
     * 对应真实漏洞：CWE-611 XXE 外部实体注入
     * 演示正确做法：前置 DOCTYPE/ENTITY 过滤 + LIBXML_NONET 禁止网络访问
     */
    public function importXmlSafe(Request $request)
    {
        $request->validate([
            'xml_content' => 'required|string',
            'player_id'   => 'required|integer',
        ]);

        $xmlContent = $request->xml_content;

        // [SAFE] 原因：前置字符串检测，拒绝含 DOCTYPE 或 ENTITY 声明的 XML
        // 此防线在解析器介入之前阻断 XXE/DTD 注入
        // 对比漏洞版本：允许 <!DOCTYPE [<!ENTITY xxe SYSTEM "file://...">]>（CWE-611）
        if (stripos($xmlContent, '<!DOCTYPE') !== false
            || stripos($xmlContent, '<!ENTITY') !== false) {
            return response()->json(['message' => 'DOCTYPE/ENTITY declarations are not allowed'], 400);
        }

        // [SAFE] 原因：不调用 libxml_disable_entity_loader(false)，保持 PHP 8 默认的外部实体禁用状态
        // 对比漏洞版本：@libxml_disable_entity_loader(false)（主动解除限制）

        $dom = new \DOMDocument();
        // [SAFE] 原因：仅传入 LIBXML_NONET，禁止解析器发起任何网络请求
        // 不传 LIBXML_NOENT（禁止展开外部实体）和 LIBXML_DTDLOAD（禁止加载外部 DTD）
        // 对比漏洞版本：loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD)（CWE-611）
        $loaded = @$dom->loadXML($xmlContent, LIBXML_NONET);

        if (!$loaded) {
            return response()->json(['message' => 'Invalid XML format'], 400);
        }

        $playerId = optional($dom->getElementsByTagName('player_id')->item(0))->nodeValue;
        $level    = optional($dom->getElementsByTagName('level')->item(0))->nodeValue;
        $score    = optional($dom->getElementsByTagName('score')->item(0))->nodeValue;
        $notes    = optional($dom->getElementsByTagName('notes')->item(0))->nodeValue;

        return response()->json([
            'message'   => 'XML save imported successfully (safe)',
            'player_id' => $playerId,
            'level'     => $level,
            'score'     => $score,
            'notes'     => $notes,  // [SAFE] 原因：此处不含外部实体内容，仅为 XML 字面值
        ]);
    }

    /**
     * GET /api/save/schema/safe
     *
     * [FALSE-POSITIVE] 触发特征: system() 调用 | 实际安全: 命令为字符串字面量，$_GET/$_POST 未参与拼接
     * SAST 工具对任意 system()/exec()/shell_exec()/passthru() 调用标记 CWE-78（OS 命令注入）。
     * 此处 system() 的参数是 'echo save_schema_v1'，完全固定，不含任何用户可控数据。
     */
    public function saveSchema()
    {
        // [FALSE-POSITIVE] 触发特征: system() | 实际安全: 命令字符串字面量，无用户数据流入
        ob_start();
        system('echo save_schema_v1');
        $schemaTag = trim(ob_get_clean());

        return response()->json([
            'schema_tag'  => $schemaTag,
            'version'     => 1,
            'fields'      => ['player_id', 'level', 'score', 'inventory', 'checksum'],
            'max_size_kb' => 512,
            'fp_note'     => 'system() argument is a string literal; no user data flows to the shell command',
        ]);
    }
}
