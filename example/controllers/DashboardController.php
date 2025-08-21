<?php

declare(strict_types=1);

namespace Controllers;

use App\Models\Label;
use App\Models\Project;
use App\Models\Task;
use App\Models\User;

class DashboardController
{
    public static function handle(): void
    {
        render('dashboard', [
            'totalProjects' => Project::countAll(),
            'totalTasks' => Task::countAll(),
            'pendingTasks' => Task::countPending(),
            'totalUsers' => User::countAll(),
            'totalLabels' => Label::countAll(),
            'recentTasks' => Task::getRecent(),
        ]);
    }
}
