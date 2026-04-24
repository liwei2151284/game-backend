<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class RechargeLog extends Model
{
    // 数据库只有 created_at，无 updated_at，关闭 Laravel 自动时间戳管理
    public $timestamps = false;

    protected $fillable = [
        'player_id',
        'amount',
        'note',
        'transaction_id',
    ];

    protected $casts = [
        'amount'     => 'decimal:2',
        'created_at' => 'datetime',
    ];

    public function player()
    {
        return $this->belongsTo(Player::class);
    }
}
