<?php

namespace Database\Seeders;

use App\Models\Item;
use App\Models\Player;
use Illuminate\Database\Seeder;

class ItemSeeder extends Seeder
{
    public function run(): void
    {
        $players = Player::orderBy('id')->get();

        if ($players->isEmpty()) {
            $this->command->warn('No players found. Register players first via POST /api/register.');
            return;
        }

        $catalogue = [
            ['name' => '火焰之剑',   'description' => '传说级武器，兑换价值 500 金币', 'value' => 500.00, 'image' => 'sword.png'],
            ['name' => '龙鳞护甲',   'description' => '稀有防具，兑换价值 300 金币',   'value' => 300.00, 'image' => 'armor.png'],
            ['name' => '神秘药水',   'description' => '普通消耗品，兑换价值 50 金币',   'value' =>  50.00, 'image' => 'potion.png'],
            ['name' => '幸运符文',   'description' => '增幅道具，兑换价值 200 金币',    'value' => 200.00, 'image' => 'rune.png'],
            ['name' => '暗影匕首',   'description' => '精英武器，兑换价值 400 金币',    'value' => 400.00, 'image' => 'dagger.png'],
            ['name' => '治愈宝珠',   'description' => '稀有消耗品，兑换价值 150 金币',  'value' => 150.00, 'image' => 'orb.png'],
        ];

        // 按玩家轮流分配道具，每人至少 2 件
        foreach ($catalogue as $index => $data) {
            $owner = $players[$index % $players->count()];
            Item::create([
                'player_id'   => $owner->id,
                'name'        => $data['name'],
                'description' => $data['description'],
                'value'       => $data['value'],
                'image'       => $data['image'],
                'is_exchanged' => false,
            ]);
        }

        $this->command->info('Items seeded: ' . count($catalogue) . ' items distributed among ' . $players->count() . ' players.');
    }
}
