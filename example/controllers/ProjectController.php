<?php

declare(strict_types=1);

namespace Controllers;

use App\Models\Project;
use App\Models\User;
use Exception;

class ProjectController
{
    public static function handle(string $action, ?int $id): void
    {
        switch ($action) {
            case 'projects':
                $projects = models()->project()->all();
                $users = models()->user()->all();
                render('projects/index', ['projects' => $projects, 'users' => $users]);
                break;
            case 'project_show':
                if ($id === null || $id === 0) {
                    flash('error', 'ID de proyecto requerido');
                    redirect('?action=projects');
                }
                $project = models()->project()->find($id);
                if (!$project instanceof Project) {
                    flash('error', 'Proyecto no encontrado');
                    redirect('?action=projects');
                }
                $orm = app()->orm();
                $tasks = $orm->table('tasks as t')
                    ->lazy()
                    ->select(['t.*', 'u.name as user_name', 'u.email as user_email'])
                    ->leftJoin('users as u', 't.user_id', '=', 'u.id')
                    ->where('t.project_id', '=', $id)
                    ->orderBy('t.status')
                    ->orderBy('t.created_at', 'desc')
                    ->collect();
                $taskIds = array_column($tasks, 'id');
                $noteCounts = [];
                if ($taskIds !== []) {
                    $noteCountsData = $orm->table('task_notes')
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
                $members = $project->members();
                $owner = models()->user()->findArray($project->owner_id);
                $allUsers = models()->user()->all();
                $memberIds = array_column($members, 'id');
                $memberIds[] = $project->owner_id;
                $availableUsers = array_filter($allUsers, static fn ($user): bool => !in_array($user->id, $memberIds, true));
                render('projects/show', ['project' => $project, 'tasks' => $tasks, 'members' => $members, 'owner' => $owner, 'availableUsers' => $availableUsers]);
                break;
            case 'project_create':
                if ($_POST !== []) {
                    try {
                        $project = models()->project()->createOne($_POST);
                        flash('success', 'Proyecto creado exitosamente');
                        redirect('?action=project_show&id=' . $project->id);
                    } catch (Exception $e) {
                        flash('error', 'Error al crear proyecto: ' . $e->getMessage());
                    }
                }
                $users = models()->user()->all();
                render('projects/create', ['users' => $users]);
                break;
            case 'project_edit':
                if ($id === null || $id === 0) {
                    flash('error', 'ID de proyecto requerido');
                    redirect('?action=projects');
                }
                $project = models()->project()->find($id);
                if (!$project instanceof Project) {
                    flash('error', 'Proyecto no encontrado');
                    redirect('?action=projects');
                }
                if ($_POST !== []) {
                    try {
                        $project->fill($_POST);
                        $project->store();
                        flash('success', 'Proyecto actualizado exitosamente');
                        redirect('?action=project_show&id=' . $project->id);
                    } catch (Exception $e) {
                        flash('error', 'Error al actualizar proyecto: ' . $e->getMessage());
                    }
                }
                $users = models()->user()->all();
                render('projects/edit', ['project' => $project, 'users' => $users]);
                break;
            case 'project_add_member':
                if ($_POST && isset($_POST['project_id'], $_POST['user_id'])) {
                    try {
                        $project = models()->project()->find((int) $_POST['project_id']);
                        if (!$project instanceof Project) {
                            flash('error', 'Proyecto no encontrado');
                            redirect('?action=projects');
                            break;
                        }
                        $user = models()->user()->find((int) $_POST['user_id']);
                        if (!$user instanceof User) {
                            flash('error', 'Usuario no encontrado');
                            redirect('?action=project_show&id=' . $_POST['project_id']);
                            break;
                        }
                        $exists = app()->orm()->table('project_users')
                            ->where('project_id', '=', (int) $_POST['project_id'])
                            ->where('user_id', '=', (int) $_POST['user_id'])
                            ->exists();
                        if ($exists) {
                            flash('warning', 'El usuario ya es miembro del proyecto');
                        } else {
                            $pivot = $project->dispenseInstance('project_users');
                            $pivot->project_id = (int) $_POST['project_id'];
                            $pivot->user_id = (int) $_POST['user_id'];
                            $pivot->store();
                            flash('success', 'Miembro agregado exitosamente');
                        }
                        redirect('?action=project_show&id=' . $_POST['project_id']);
                    } catch (Exception $e) {
                        flash('error', 'Error al agregar miembro: ' . $e->getMessage());
                        redirect('?action=project_show&id=' . $_POST['project_id']);
                    }
                } else {
                    flash('error', 'Datos inválidos');
                    redirect('?action=projects');
                }
                break;
            case 'project_remove_member':
                if ($_POST && isset($_POST['project_id'], $_POST['user_id'])) {
                    try {
                        $project = models()->project()->find((int) $_POST['project_id']);
                        if (!$project instanceof Project) {
                            flash('error', 'Proyecto no encontrado');
                            redirect('?action=projects');
                            break;
                        }
                        $orm = app()->orm();
                        $rows = app()->orm()->table('project_users')
                            ->select(['id'])
                            ->where('project_id', '=', (int) $_POST['project_id'])
                            ->where('user_id', '=', (int) $_POST['user_id'])
                            ->get();
                        foreach ($rows as $row) {
                            if (!isset($row['id'])) {
                                continue;
                            }
                            $pivot = $project->load('project_users', (int) $row['id']);
                            $pivot?->trash();
                        }
                        flash('success', 'Miembro removido exitosamente');
                        redirect('?action=project_show&id=' . $_POST['project_id']);
                    } catch (Exception $e) {
                        flash('error', 'Error al remover miembro: ' . $e->getMessage());
                        redirect('?action=project_show&id=' . $_POST['project_id']);
                    }
                } else {
                    flash('error', 'Datos inválidos');
                    redirect('?action=projects');
                }
                break;
            case 'project_delete':
                if ($id === null || $id === 0) {
                    flash('error', 'ID de proyecto requerido');
                    redirect('?action=projects');
                }
                $project = models()->project()->find($id);
                if ($project instanceof Project) {
                    $project->trash();
                    flash('success', 'Proyecto eliminado exitosamente');
                } else {
                    flash('error', 'Proyecto no encontrado');
                }
                redirect('?action=projects');
                break;
        }
    }
}
