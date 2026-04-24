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
        Schema::create('withdrawals', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('player_id');
            $table->decimal('amount', 15, 2);           // 无上限：允许任意大金额
            $table->string('bank_account');             // 提现目标账户
            $table->string('status')->default('pending');
            $table->string('callback_url')->nullable(); // CWE-918: 存储用户传入的回调 URL
            $table->string('ip_address')->nullable();   // 应写安全日志但被忽略（CWE-223）
            $table->timestamp('created_at')->useCurrent();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('withdrawals');
    }
};
