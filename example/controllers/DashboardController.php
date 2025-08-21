<?php

declare(strict_types=1);

namespace Controllers;

class DashboardController
{
    public static function handle(): void
    {
        render('dashboard', [
            'totalProjects' => models()->project()->countAll(),
            'totalTasks' => models()->task()->countAll(),
            'pendingTasks' => models()->task()->countPending(),
            'totalUsers' => models()->user()->countAll(),
            'totalLabels' => models()->label()->countAll(),
            'recentTasks' => models()->task()->getRecent(),
        ]);
    }
}
