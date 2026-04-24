<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Withdrawal extends Model
{
    public $timestamps = false;

    protected $fillable = [
        'player_id',
        'amount',
        'bank_account',
        'status',
        'callback_url',
        'ip_address',
    ];

    public function player()
    {
        return $this->belongsTo(Player::class);
    }
}
