<?php

declare(strict_types=1);

/**
 * VersaORM Trello Demo
 * Aplicación de demostración tipo Trello para mostrar las capacidades de VersaORM.
 */

require_once __DIR__ . '/bootstrap.php';

use App\Models\Label;
use App\Models\Project;
use App\Models\Task;
use App\Models\User;

// Obtener la acción y parámetros de la URL
$action = $_GET['action'] ?? 'dashboard';
$id = isset($_GET['id']) ? (int) $_GET['id'] : null;

try {
    switch ($action) {

        // ======================
        // DASHBOARD
        // ======================
        case 'dashboard':
            $totalProjects = count(Project::all());
            $totalTasks = count(Task::all());
            $totalUsers = count(User::all());
            $totalLabels = count(Label::all());

            // Obtener las tareas recientes usando find para obtener objetos
            $allTasks = Task::all();
            // Ordenar por fecha de creación y tomar las 5 más recientes
            usort($allTasks, function ($a, $b) {
                return safe_strtotime($b->created_at) - safe_strtotime($a->created_at);
            });
            $recentTasks = array_slice($allTasks, 0, 5);

            render('dashboard', compact('totalProjects', 'totalTasks', 'totalUsers', 'totalLabels', 'recentTasks'));
            break;

        // ======================
        // PROYECTOS
        // ======================
        case 'projects':
            $projects = Project::all();
            $users = User::all();
            render('projects/index', compact('projects', 'users'));
            break;

        case 'project_show':
            if (!$id) {
                flash('error', 'ID de proyecto requerido');
                redirect('?action=projects');
            }

            $project = Project::find($id);
            if (!$project) {
                flash('error', 'Proyecto no encontrado');
                redirect('?action=projects');
            }

            $tasks = Task::getAll('SELECT * FROM tasks WHERE project_id = ? ORDER BY status, created_at DESC', [$id]);
            $members = $project->members();
            $owner = User::findArray($project->owner_id);

            // Obtener todos los usuarios primero
            $allUsers = User::all();

            // Obtener IDs de miembros actuales
            $memberIds = array_column($members, 'id');
            $memberIds[] = $project->owner_id; // Excluir también al propietario

            // Filtrar usuarios disponibles
            $availableUsers = [];
            foreach ($allUsers as $user) {
                if (!in_array($user->id, $memberIds)) {
                    $availableUsers[] = $user;
                }
            }

            render('projects/show', compact('project', 'tasks', 'members', 'owner', 'availableUsers'));
            break;

        case 'project_create':
            if ($_POST) {
                try {
                    $project = Project::create($_POST);
                    flash('success', 'Proyecto creado exitosamente');
                    redirect('?action=project_show&id=' . $project->id);
                } catch (Exception $e) {
                    flash('error', 'Error al crear proyecto: ' . $e->getMessage());
                }
            }

            $users = User::all();
            render('projects/create', compact('users'));
            break;

        case 'project_edit':
            if (!$id) {
                flash('error', 'ID de proyecto requerido');
                redirect('?action=projects');
            }

            $project = Project::find($id);
            if (!$project) {
                flash('error', 'Proyecto no encontrado');
                redirect('?action=projects');
            }

            if ($_POST) {
                try {
                    $project->fill($_POST);
                    $project->store();
                    flash('success', 'Proyecto actualizado exitosamente');
                    redirect('?action=project_show&id=' . $project->id);
                } catch (Exception $e) {
                    flash('error', 'Error al actualizar proyecto: ' . $e->getMessage());
                }
            }

            $users = User::all();
            render('projects/edit', compact('project', 'users'));
            break;

        case 'project_add_member':
            if ($_POST && isset($_POST['project_id']) && isset($_POST['user_id'])) {
                try {
                    $project = Project::find($_POST['project_id']);
                    if (!$project) {
                        flash('error', 'Proyecto no encontrado');
                        redirect('?action=projects');
                        break;
                    }

                    $user = User::find($_POST['user_id']);
                    if (!$user) {
                        flash('error', 'Usuario no encontrado');
                        redirect('?action=project_show&id=' . $_POST['project_id']);
                        break;
                    }

                    // Verificar que el usuario no sea ya miembro
                    $existing = Project::getAll(
                        'SELECT * FROM project_users WHERE project_id = ? AND user_id = ? LIMIT 1',
                        [$_POST['project_id'], $_POST['user_id']]
                    );

                    if (!empty($existing)) {
                        flash('warning', 'El usuario ya es miembro del proyecto');
                    } else {
                        // Agregar el miembro usando el ORM global
                        $orm = Project::getGlobalORM();
                        $orm->exec(
                            'INSERT INTO project_users (project_id, user_id, created_at) VALUES (?, ?, NOW())',
                            [$_POST['project_id'], $_POST['user_id']]
                        );
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
            if ($_POST && isset($_POST['project_id']) && isset($_POST['user_id'])) {
                try {
                    $project = Project::find($_POST['project_id']);
                    if (!$project) {
                        flash('error', 'Proyecto no encontrado');
                        redirect('?action=projects');
                        break;
                    }

                    // Remover el miembro usando el ORM global
                    $orm = Project::getGlobalORM();
                    $orm->exec(
                        'DELETE FROM project_users WHERE project_id = ? AND user_id = ?',
                        [$_POST['project_id'], $_POST['user_id']]
                    );

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
            if (!$id) {
                flash('error', 'ID de proyecto requerido');
                redirect('?action=projects');
            }

            $project = Project::find($id);
            if ($project) {
                $project->trash();
                flash('success', 'Proyecto eliminado exitosamente');
            } else {
                flash('error', 'Proyecto no encontrado');
            }
            redirect('?action=projects');
            break;

        // ======================
        // TAREAS
        // ======================
        case 'tasks':
            // Parámetros de paginación y filtros
            $page = max(1, (int)($_GET['page'] ?? 1));
            $perPageParam = $_GET['per_page'] ?? 10;
            $perPage = in_array((int)$perPageParam, [1, 5, 10, 20, 50, 100]) ? (int)$perPageParam : 10;
            $offset = ($page - 1) * $perPage;

            // Filtros
            $statusFilter = $_GET['status'] ?? '';
            $priorityFilter = $_GET['priority'] ?? '';
            $projectFilter = $_GET['project_id'] ?? '';
            $userFilter = $_GET['user_id'] ?? '';

            // Obtener todas las tareas y aplicar filtros
            $allTasks = Task::all();
            $filteredTasks = array_filter($allTasks, function ($task) use ($statusFilter, $priorityFilter, $projectFilter, $userFilter) {
                if ($statusFilter && $task->status !== $statusFilter) return false;
                if ($priorityFilter && $task->priority !== $priorityFilter) return false;
                if ($projectFilter && $task->project_id != $projectFilter) return false;
                if ($userFilter && $task->user_id != $userFilter) return false;
                return true;
            });

            // Calcular totales
            $totalTasks = count($filteredTasks);
            $totalPages = $perPage > 0 ? ceil($totalTasks / $perPage) : 1;

            // Aplicar paginación
            $tasks = array_slice($filteredTasks, $offset, $perPage);

            // Convertir objetos a arrays para la vista
            $tasks = array_map(function ($task) {
                $taskArray = $task->export();

                // Añadir información del proyecto
                if ($task->project_id) {
                    $project = Project::find($task->project_id);
                    $taskArray['project_name'] = $project ? $project->name : 'Sin proyecto';
                } else {
                    $taskArray['project_name'] = 'Sin proyecto';
                }

                // Añadir información del usuario
                if ($task->user_id) {
                    $user = User::find($task->user_id);
                    $taskArray['user_name'] = $user ? $user->name : 'Sin asignar';
                } else {
                    $taskArray['user_name'] = 'Sin asignar';
                }

                return $taskArray;
            }, $tasks);

            // Obtener datos para filtros
            $projects = array_map(fn($p) => $p->export(), Project::all());
            $users = array_map(fn($u) => $u->export(), User::all());

            // Datos de paginación
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
                'end' => min($offset + $perPage, $totalTasks)
            ];

            // Datos de filtros actuales
            $filters = [
                'status' => $statusFilter,
                'priority' => $priorityFilter,
                'project_id' => $projectFilter,
                'user_id' => $userFilter
            ];

            // Construir query string para filtros
            $filterParams = [];
            if ($statusFilter) $filterParams['status'] = $statusFilter;
            if ($priorityFilter) $filterParams['priority'] = $priorityFilter;
            if ($projectFilter) $filterParams['project_id'] = $projectFilter;
            if ($userFilter) $filterParams['user_id'] = $userFilter;
            $filterQueryString = $filterParams ? '&' . http_build_query($filterParams) : '';

            render('tasks/index', compact('tasks', 'projects', 'users', 'pagination', 'filters', 'filterQueryString'));
            break;

        case 'task_create':
            if ($_POST) {
                try {
                    // Extraer las etiquetas del POST antes de crear la tarea
                    $labels = isset($_POST['labels']) ? $_POST['labels'] : [];
                    $taskData = $_POST;
                    unset($taskData['labels']); // Remover labels del array de datos

                    $task = Task::create($taskData);

                    // Asignar etiquetas si se enviaron
                    if (!empty($labels) && is_array($labels)) {
                        $task->setLabels($labels);
                    }

                    flash('success', 'Tarea creada exitosamente');
                    redirect('?action=project_show&id=' . $task->project_id);
                } catch (Exception $e) {
                    flash('error', 'Error al crear tarea: ' . $e->getMessage());
                }
            }

            $projects = array_map(fn($p) => $p->export(), Project::all());
            $users = array_map(fn($u) => $u->export(), User::all());
            $labels = array_map(fn($l) => $l->export(), Label::all());
            render('tasks/create', compact('projects', 'users', 'labels'));
            break;

        case 'task_edit':
            if (!$id) {
                flash('error', 'ID de tarea requerido');
                redirect('?action=tasks');
            }

            $task = Task::find($id);
            if (!$task) {
                flash('error', 'Tarea no encontrada');
                redirect('?action=tasks');
            }

            if ($_POST) {
                try {
                    // Extraer las etiquetas del POST antes de actualizar la tarea
                    $labels = isset($_POST['labels']) ? $_POST['labels'] : [];
                    $taskData = $_POST;
                    unset($taskData['labels']); // Remover labels del array de datos

                    $task->fill($taskData);
                    $task->store();

                    // Actualizar etiquetas
                    if (!empty($labels) && is_array($labels)) {
                        $task->setLabels($labels);
                    } else {
                        $task->setLabels([]);
                    }

                    flash('success', 'Tarea actualizada exitosamente');
                    redirect('?action=project_show&id=' . $task->project_id);
                } catch (Exception $e) {
                    flash('error', 'Error al actualizar tarea: ' . $e->getMessage());
                }
            }

            $projects = array_map(fn($p) => $p->export(), Project::all());
            $users = array_map(fn($u) => $u->export(), User::all());
            $labels = array_map(fn($l) => $l->export(), Label::all());
            $taskLabels = $task->getLabelIds();
            render('tasks/edit', compact('task', 'projects', 'users', 'labels', 'taskLabels'));
            break;

        case 'task_delete':
            if (!$id) {
                flash('error', 'ID de tarea requerido');
                redirect('?action=tasks');
            }

            $task = Task::find($id);
            if ($task) {
                $projectId = $task->project_id;
                $task->trash();
                flash('success', 'Tarea eliminada exitosamente');
                redirect('?action=project_show&id=' . $projectId);
            } else {
                flash('error', 'Tarea no encontrada');
                redirect('?action=tasks');
            }
            break;

        case 'task_change_status':
            if (!$id || empty($_POST['status'])) {
                flash('error', 'Datos incompletos');
                redirect($_SERVER['HTTP_REFERER'] ?? '?action=tasks');
            }

            $task = Task::find($id);
            if ($task) {
                try {
                    $task->changeStatus($_POST['status']);
                    flash('success', 'Estado de tarea actualizado');
                } catch (Exception $e) {
                    flash('error', 'Error al cambiar estado: ' . $e->getMessage());
                }
            } else {
                flash('error', 'Tarea no encontrada');
            }
            redirect($_SERVER['HTTP_REFERER'] ?? '?action=tasks');
            break;

        // ======================
        // USUARIOS
        // ======================
        case 'users':
            $users = User::all();
            render('users/index', compact('users'));
            break;

        case 'user_create':
            if ($_POST) {
                try {
                    $user = User::create($_POST);
                    flash('success', 'Usuario creado exitosamente');
                    redirect('?action=users');
                } catch (Exception $e) {
                    flash('error', 'Error al crear usuario: ' . $e->getMessage());
                }
            }

            render('users/create');
            break;

        case 'user_edit':
            if (!$id) {
                flash('error', 'ID de usuario requerido');
                redirect('?action=users');
            }

            $user = User::find($id);
            if (!$user) {
                flash('error', 'Usuario no encontrado');
                redirect('?action=users');
            }

            if ($_POST) {
                try {
                    $user->fill($_POST);
                    $user->store();
                    flash('success', 'Usuario actualizado exitosamente');
                    redirect('?action=users');
                } catch (Exception $e) {
                    flash('error', 'Error al actualizar usuario: ' . $e->getMessage());
                }
            }

            render('users/edit', compact('user'));
            break;

        case 'user_delete':
            if (!$id) {
                flash('error', 'ID de usuario requerido');
                redirect('?action=users');
            }

            $user = User::find($id);
            if ($user) {
                $user->trash();
                flash('success', 'Usuario eliminado exitosamente');
            } else {
                flash('error', 'Usuario no encontrado');
            }
            redirect('?action=users');
            break;

        // ======================
        // ETIQUETAS
        // ======================
        case 'labels':
            $labels = Label::all();
            // Agregar conteo de tareas para cada etiqueta
            foreach ($labels as &$label) {
                $count = Label::getAll('SELECT COUNT(*) as count FROM task_labels WHERE label_id = ?', [$label->id]);
                $label->tasks_count = $count[0]['count'] ?? 0;
            }
            render('labels/index', compact('labels'));
            break;

        case 'label_create':
            if ($_POST) {
                try {
                    $label = Label::create($_POST);
                    flash('success', 'Etiqueta creada exitosamente');
                    redirect('?action=labels');
                } catch (Exception $e) {
                    flash('error', 'Error al crear etiqueta: ' . $e->getMessage());
                }
            }

            render('labels/create');
            break;

        case 'label_edit':
            if (!$id) {
                flash('error', 'ID de etiqueta requerido');
                redirect('?action=labels');
            }

            $label = Label::find($id);
            if (!$label) {
                flash('error', 'Etiqueta no encontrada');
                redirect('?action=labels');
            }

            // Añadir conteo de tareas
            $count = Label::getAll('SELECT COUNT(*) as count FROM task_labels WHERE label_id = ?', [$label->id]);
            $label->tasks_count = $count[0]['count'] ?? 0;

            if ($_POST) {
                try {
                    $label->fill($_POST);
                    $label->store();
                    flash('success', 'Etiqueta actualizada exitosamente');
                    redirect('?action=labels');
                } catch (Exception $e) {
                    flash('error', 'Error al actualizar etiqueta: ' . $e->getMessage());
                }
            }

            render('labels/edit', compact('label'));
            break;

        case 'label_delete':
            if (!$id) {
                flash('error', 'ID de etiqueta requerido');
                redirect('?action=labels');
            }

            $label = Label::find($id);
            if ($label) {
                $label->trash();
                flash('success', 'Etiqueta eliminada exitosamente');
            } else {
                flash('error', 'Etiqueta no encontrada');
            }
            redirect('?action=labels');
            break;

        default:
            flash('error', 'Acción no encontrada');
            redirect('?action=dashboard');
            break;
    }
} catch (Exception $e) {
    flash('error', 'Error del sistema: ' . $e->getMessage());
    render('error', ['message' => $e->getMessage()]);
}
