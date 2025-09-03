<?php

declare(strict_types=1);

namespace Controllers;

class TaskController
{
    public static function handle(string $action, null|int $id): void
    {
        switch ($action) {
            case 'tasks':
                $page = max(1, (int) ($_GET['page'] ?? 1));
                $perPageParam = $_GET['per_page'] ?? 10;
                $perPage = in_array((int) $perPageParam, [1, 5, 10, 20, 50, 100], true) ? (int) $perPageParam : 10;
                $offset = ($page - 1) * $perPage;
                $statusFilter = $_GET['status'] ?? '';
                $priorityFilter = $_GET['priority'] ?? '';
                $projectFilter = $_GET['project_id'] ?? '';
                $userFilter = $_GET['user_id'] ?? '';
                $orm = app()->orm();
                $queryBuilder = $orm
                    ->table('tasks as t')
                    ->lazy()
                    ->select([
                        't.*',
                        'u.name as user_name',
                        'u.avatar_color',
                        'p.name as project_name',
                        'p.color as project_color',
                    ])
                    ->leftJoin('users as u', 't.user_id', '=', 'u.id')
                    ->leftJoin('projects as p', 't.project_id', '=', 'p.id');
                if ($statusFilter) {
                    $queryBuilder->where('t.status', '=', $statusFilter);
                }
                if ($priorityFilter) {
                    $queryBuilder->where('t.priority', '=', $priorityFilter);
                }
                if ($projectFilter) {
                    $queryBuilder->where('t.project_id', '=', (int) $projectFilter);
                }
                if ($userFilter) {
                    $queryBuilder->where('t.user_id', '=', (int) $userFilter);
                }
                $countQueryBuilder = $orm->table('tasks as t');
                if ($statusFilter) {
                    $countQueryBuilder->where('t.status', '=', $statusFilter);
                }
                if ($priorityFilter) {
                    $countQueryBuilder->where('t.priority', '=', $priorityFilter);
                }
                if ($projectFilter) {
                    $countQueryBuilder->where('t.project_id', '=', (int) $projectFilter);
                }
                if ($userFilter) {
                    $countQueryBuilder->where('t.user_id', '=', (int) $userFilter);
                }
                $totalTasks = $countQueryBuilder->count();
                $totalPages = $perPage > 0 ? ceil($totalTasks / $perPage) : 1;
                $tasks = $queryBuilder->orderBy('t.created_at', 'desc')->limit($perPage)->offset($offset)->collect();
                $taskIds = array_column($tasks, 'id');
                $noteCounts = [];
                if ($taskIds !== []) {
                    $noteCountsData = $orm
                        ->table('task_notes')
                        ->select(['task_id', 'COUNT(*) as count'])
                        ->whereIn('task_id', $taskIds)
                        ->groupBy('task_id')
                        ->getAll();
                    foreach ($noteCountsData as $row) {
                        $noteCounts[$row['task_id']] = $row['count'];
                    }
                }
                foreach ($tasks as &$task) {
                    $task['notes_count'] = $noteCounts[$task['id']] ?? 0;
                }
                unset($task);
                $projects = $orm->table('projects')->select(['id', 'name'])->getAll();
                $users = $orm->table('users')->select(['id', 'name'])->getAll();
                $pagination = [
                    'current_page' => $page,
                    'per_page' => $perPage,
                    'total' => $totalTasks,
                    'total_pages' => $totalPages,
                    'has_prev' => $page > 1,
                    'has_next' => $page < $totalPages,
                    'prev_page' => max(1, $page - 1),
                    'next_page' => min($totalPages, $page + 1),
                    'start' => $totalTasks > 0 ? $offset + 1 : 0,
                    'end' => min($offset + $perPage, $totalTasks),
                    'showing_from' => $totalTasks > 0 ? $offset + 1 : 0,
                    'showing_to' => min($offset + $perPage, $totalTasks),
                ];
                $filters = [
                    'status' => $statusFilter,
                    'priority' => $priorityFilter,
                    'project_id' => $projectFilter,
                    'user_id' => $userFilter,
                ];
                $filterParams = [];
                if ($statusFilter) {
                    $filterParams['status'] = $statusFilter;
                }
                if ($priorityFilter) {
                    $filterParams['priority'] = $priorityFilter;
                }
                if ($projectFilter) {
                    $filterParams['project_id'] = $projectFilter;
                }
                if ($userFilter) {
                    $filterParams['user_id'] = $userFilter;
                }
                $filterQueryString = $filterParams !== [] ? '&' . http_build_query($filterParams) : '';
                render('tasks/index', [
                    'tasks' => $tasks,
                    'projects' => $projects,
                    'users' => $users,
                    'pagination' => $pagination,
                    'filters' => $filters,
                    'filterQueryString' => $filterQueryString,
                ]);
                break;

            // ...otros casos: task_create, task_edit, task_delete, task_change_status
        }
    }
}
