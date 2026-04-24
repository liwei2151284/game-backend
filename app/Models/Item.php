<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Item extends Model
{
    // 数据库只有 created_at，无 updated_at，关闭 Laravel 自动时间戳管理
    public $timestamps = false;

    protected $fillable = [
        'player_id',
        'name',
        'description',
        'value',
        'image',
        'is_exchanged',
    ];

    protected $casts = [
        'value'       => 'decimal:2',
        'is_exchanged'=> 'boolean',
        'created_at'  => 'datetime',
    ];

    public function player()
    {
        return $this->belongsTo(Player::class);
    }
}
