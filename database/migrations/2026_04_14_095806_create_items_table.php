<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('items', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('player_id');       // 道具归属玩家
            $table->string('name');                         // 道具名称
            $table->string('description')->nullable();      // 道具描述
            $table->decimal('value', 10, 2)->default(0);   // 兑换价值（游戏币）
            $table->string('image')->nullable();            // 图片文件名
            $table->boolean('is_exchanged')->default(false); // 是否已兑换
            $table->timestamp('created_at')->useCurrent();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('items');
    }
};
