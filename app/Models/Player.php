<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Player extends Model
{
    // 数据库只有 created_at，无 updated_at，关闭 Laravel 自动时间戳管理
    public $timestamps = false;

    protected $fillable = [
        'username',
        'password',
        'email',
        'balance',
        'invite_code',
    ];

    protected $casts = [
        'balance'    => 'decimal:2',
        'created_at' => 'datetime',
    ];
}
