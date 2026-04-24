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
        Schema::create('recharge_logs', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('player_id');
            $table->decimal('amount', 10, 2);
            // CWE-1236: note 字段由用户提交，原样存储，导出 CSV 时不做转义
            $table->string('note')->nullable();
            $table->string('transaction_id')->nullable();
            $table->timestamp('created_at')->useCurrent();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('recharge_logs');
    }
};
