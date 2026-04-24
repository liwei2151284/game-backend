<?php

namespace App\Helpers;

/**
 * CWE-502 演示用 PHP 反序列化 Gadget 类
 *
 * 此类在正常业务中用于记录存档日志。
 * 由于实现了 __destruct() 魔术方法，当攻击者通过 /api/save/parse 注入
 * 恶意序列化对象时，PHP 在销毁对象时会自动调用 __destruct()，
 * 执行任意文件写入操作，从而植入 Webshell。
 */
class GameSaveLogger
{
    // 攻击者可控字段：写入目标路径
    public string $log_file = '';

    // 攻击者可控字段：写入内容（可为 PHP Webshell 代码）
    public string $log_data = '';

    /**
     * 正常用途：析构时将日志写入文件
     * 漏洞用途：攻击者通过反序列化注入恶意对象，控制 log_file / log_data，
     *           在对象被 GC 销毁时自动触发任意文件写入
     */
    public function __destruct()
    {
        // CWE-502 Gadget 触发点：无任何路径白名单或内容校验
        if (!empty($this->log_file) && !empty($this->log_data)) {
            file_put_contents($this->log_file, $this->log_data);
        }
    }
}
