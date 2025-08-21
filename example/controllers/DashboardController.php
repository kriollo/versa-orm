<?php

declare(strict_types=1);

namespace Controllers;

class DashboardController
{
    public static function handle(): void
    {
        $orm = app()->orm();
        $totalProjects = $orm->table('projects')->count();
        $totalTasks = $orm->table('tasks')->count();
        $pendingTasks = $orm->table('tasks')->where('status', '=', 'todo')->count();
        $totalUsers = $orm->table('users')->count();
        $totalLabels = $orm->table('labels')->count();
        $recentTasks = $orm->table('tasks as t')
            ->lazy()
            ->select(['t.*', 'u.name as user_name', 'p.name as project_name'])
            ->leftJoin('users as u', 't.user_id', '=', 'u.id')
            ->leftJoin('projects as p', 't.project_id', '=', 'p.id')
            ->where('t.status', '!=', 'done')
            ->orderBy('t.created_at', 'desc')
            ->limit(5)
            ->collect();
        render('dashboard', [
            'totalProjects' => $totalProjects,
            'totalTasks' => $totalTasks,
            'pendingTasks' => $pendingTasks,
            'totalUsers' => $totalUsers,
            'totalLabels' => $totalLabels,
            'recentTasks' => $recentTasks,
        ]);
    }
}
