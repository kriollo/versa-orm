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
            // 🚀 ANTES (Múltiples consultas separadas):
            // $totalProjects = count(Project::all());
            // $totalTasks = count(Task::all());
            // $totalUsers = count(User::all());
            // $totalLabels = count(Label::all());

            // ✅ DESPUÉS (Optimizado con consultas agregadas):
            $orm = app()->orm();

            // Conteos eficientes usando el ORM
            $totalProjects = $orm->table('projects')->count();
            $totalTasks = $orm->table('tasks')->count();
            $totalUsers = $orm->table('users')->count();
            $totalLabels = $orm->table('labels')->count();

            // 🚀 Tareas recientes con información relacionada usando Modo Lazy
            $recentTasks = $orm->table('tasks as t')
                ->lazy()                                                    // 🚀 Activa optimización automática
                ->select(['t.*', 'u.name as user_name', 'p.name as project_name'])
                ->leftJoin('users as u', 't.user_id', '=', 'u.id')        // JOIN optimizado
                ->leftJoin('projects as p', 't.project_id', '=', 'p.id')  // JOIN optimizado
                ->orderBy('t.created_at', 'desc')                         // ORDER BY optimizado
                ->limit(5)                                                 // LIMIT optimizado
                ->collect()                                               // ✅ UNA consulta optimizada
            ;

            render('dashboard', ['totalProjects' => $totalProjects, 'totalTasks' => $totalTasks, 'totalUsers' => $totalUsers, 'totalLabels' => $totalLabels, 'recentTasks' => $recentTasks]);
            break;

            // ======================
            // PROYECTOS
            // ======================
        case 'projects':
            // Usar modelos para que las vistas sigan accediendo con ->propiedad
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

            // 🚀 ANTES (SQL manual):
            // $tasks = Task::getAll('SELECT * FROM tasks WHERE project_id = ? ORDER BY status, created_at DESC', [$id]);

            // ✅ DESPUÉS (Modo Lazy con información relacionada):
            $orm = app()->orm();
            $tasks = $orm->table('tasks as t')
                ->lazy()                                                    // 🚀 Activa optimización automática
                ->select(['t.*', 'u.name as user_name', 'u.email as user_email'])
                ->leftJoin('users as u', 't.user_id', '=', 'u.id')        // JOIN optimizado para datos del usuario
                ->where('t.project_id', '=', $id)                         // WHERE optimizado
                ->orderBy('t.status')                                     // ORDER BY optimizado
                ->orderBy('t.created_at', 'desc')                         // ORDER BY secundario optimizado
                ->collect()                                               // ✅ UNA consulta optimizada
            ;

            // Obtener el recuento de notas para las tareas obtenidas
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

            // Añadir el recuento de notas a cada tarea
            foreach ($tasks as &$task) {
                $task['notes_count'] = $noteCounts[$task['id']] ?? 0;
            }
            unset($task); // Romper la referencia

            $members = $project->members();
            $owner = models()->user()->findArray($project->owner_id);

            // Obtener usuarios disponibles de forma eficiente
            $allUsers = models()->user()->all();
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
            // Mantener usuarios como objetos de modelo para consistencia en las vistas
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
            // Mantener usuarios como objetos (no arrays exportados) para evitar warnings en la vista edit
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

                    // Verificar que el usuario no sea ya miembro
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

                    // Remover el miembro usando el ORM global
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

            // ======================
            // TAREAS
            // ======================
        case 'tasks':
            // Parámetros de paginación y filtros
            $page = max(1, (int) ($_GET['page'] ?? 1));
            $perPageParam = $_GET['per_page'] ?? 10;
            $perPage = in_array((int) $perPageParam, [1, 5, 10, 20, 50, 100], true) ? (int) $perPageParam : 10;
            $offset = ($page - 1) * $perPage;

            // Filtros
            $statusFilter = $_GET['status'] ?? '';
            $priorityFilter = $_GET['priority'] ?? '';
            $projectFilter = $_GET['project_id'] ?? '';
            $userFilter = $_GET['user_id'] ?? '';

            // 🚀 ANTES (Muy ineficiente):
            // - Obtener TODAS las tareas en memoria
            // - Filtrar en PHP (muy lento con muchas tareas)
            // - Consultas N+1 para proyecto y usuario de cada tarea
            // $allTasks = Task::all();
            // $filteredTasks = array_filter($allTasks, function ($task) use (...) { ... });

            // ✅ DESPUÉS (Modo Lazy - Ultra optimizado):
            $orm = app()->orm();

            // Construcción dinámica de consulta con filtros aplicados en DB
            $queryBuilder = $orm->table('tasks as t')
                ->lazy()                                                    // 🚀 Activa optimización automática
                ->select(['t.*', 'u.name as user_name', 'u.avatar_color', 'p.name as project_name', 'p.color as project_color'])
                ->leftJoin('users as u', 't.user_id', '=', 'u.id')        // JOIN optimizado
                ->leftJoin('projects as p', 't.project_id', '=', 'p.id')  // JOIN optimizado
            ;

            // Aplicar filtros dinámicamente (solo si están presentes)
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

            // Contar total para paginación (consulta simple sin JOINs)
            $countQueryBuilder = $orm->table('tasks as t');

            // Aplicar los mismos filtros para el conteo
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

            $totalTasks = $countQueryBuilder->count();                      // Conteo optimizado sin JOINs
            $totalPages = $perPage > 0 ? ceil($totalTasks / $perPage) : 1;

            // Obtener tareas paginadas
            $tasks = $queryBuilder
                ->orderBy('t.created_at', 'desc')                          // ORDER BY optimizado
                ->limit($perPage)                                          // LIMIT optimizado
                ->offset($offset)                                          // OFFSET optimizado
                ->collect()                                               // ✅ UNA consulta optimizada
            ;

            // Obtener el recuento de notas para las tareas obtenidas
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

            // Añadir el recuento de notas a cada tarea
            foreach ($tasks as &$task) {
                $task['notes_count'] = $noteCounts[$task['id']] ?? 0;
            }
            unset($task); // Romper la referencia

            // Obtener datos para filtros (solo los necesarios)
            $projects = $orm->table('projects')->select(['id', 'name'])->getAll();
            $users = $orm->table('users')->select(['id', 'name'])->getAll();

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
                'end' => min($offset + $perPage, $totalTasks),
                'showing_from' => $totalTasks > 0 ? $offset + 1 : 0,
                'showing_to' => min($offset + $perPage, $totalTasks),
            ];

            // Datos de filtros actuales
            $filters = [
                'status' => $statusFilter,
                'priority' => $priorityFilter,
                'project_id' => $projectFilter,
                'user_id' => $userFilter,
            ];

            // Construir query string para filtros
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

            render('tasks/index', ['tasks' => $tasks, 'projects' => $projects, 'users' => $users, 'pagination' => $pagination, 'filters' => $filters, 'filterQueryString' => $filterQueryString]);
            break;

        case 'task_create':
            if ($_POST !== []) {
                try {
                    // Extraer las etiquetas del POST antes de crear la tarea
                    $labels = $_POST['labels'] ?? [];
                    $taskData = $_POST;
                    unset($taskData['labels']); // Remover labels del array de datos

                    $task = models()->task()->createOne($taskData);

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

            $projects = array_map(static fn ($p) => $p->export(), models()->project()->all());
            $users = array_map(static fn ($u) => $u->export(), models()->user()->all());
            $labels = array_map(static fn ($l): array => $l->export(), app()->orm()->table('labels')->findAll());
            render('tasks/create', ['projects' => $projects, 'users' => $users, 'labels' => $labels]);
            break;

        case 'task_edit':
            if ($id === null || $id === 0) {
                flash('error', 'ID de tarea requerido');
                redirect('?action=tasks');
            }

            $task = models()->task()->find($id);

            if (!$task instanceof Task) {
                flash('error', 'Tarea no encontrada');
                redirect('?action=tasks');
            }

            if ($_POST !== []) {
                try {
                    // Extraer las etiquetas del POST antes de actualizar la tarea
                    $labels = $_POST['labels'] ?? [];
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

            $projects = array_map(static fn ($p) => $p->export(), models()->project()->all());
            $users = array_map(static fn ($u) => $u->export(), models()->user()->all());
            $labels = array_map(static fn ($l): array => $l->export(), app()->orm()->table('labels')->findAll());
            $taskLabels = $task->getLabelIds();
            render('tasks/edit', ['task' => $task, 'projects' => $projects, 'users' => $users, 'labels' => $labels, 'taskLabels' => $taskLabels]);
            break;

        case 'task_delete':
            if ($id === null || $id === 0) {
                flash('error', 'ID de tarea requerido');
                redirect('?action=tasks');
            }

            $task = models()->task()->find($id);

            if ($task instanceof Task) {
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
            if ($id === null || $id === 0 || empty($_POST['status'])) {
                flash('error', 'Datos incompletos');
                redirect($_SERVER['HTTP_REFERER'] ?? '?action=tasks');
            }

            $task = models()->task()->find($id);

            if ($task instanceof Task) {
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
            $users = models()->user()->all();
            render('users/index', ['users' => $users]);
            break;

        case 'user_create':
            if ($_POST !== []) {
                try {
                    $user = models()->user()->createOne($_POST);
                    flash('success', 'Usuario creado exitosamente');
                    redirect('?action=users');
                } catch (Exception $e) {
                    flash('error', 'Error al crear usuario: ' . $e->getMessage());
                }
            }
            // Render único (se había duplicado por error)
            render('users/create');
            break;

        case 'user_edit':
            if ($id === null || $id === 0) {
                flash('error', 'ID de usuario requerido');
                redirect('?action=users');
            }

            $user = models()->user()->find($id);

            if (!$user instanceof User) {
                flash('error', 'Usuario no encontrado');
                redirect('?action=users');
            }

            if ($_POST !== []) {
                try {
                    $user->fill($_POST);
                    $user->store();
                    flash('success', 'Usuario actualizado exitosamente');
                    redirect('?action=users');
                } catch (Exception $e) {
                    flash('error', 'Error al actualizar usuario: ' . $e->getMessage());
                }
            }
            // Render único (se había duplicado por error)
            render('users/edit', ['user' => $user]);
            break;

        case 'user_delete':
            if ($id === null || $id === 0) {
                flash('error', 'ID de usuario requerido');
                redirect('?action=users');
            }

            $user = models()->user()->find($id);

            if ($user instanceof User) {
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
            $labels = app()->orm()->table('labels')->findAll();

            if ($labels !== []) {
                $labelIds = array_map(static fn ($l) => $l->id, $labels);
                $countsRows = app()->orm()->table('task_labels')
                    ->select(['label_id', 'COUNT(*) as c'])
                    ->whereIn('label_id', $labelIds)
                    ->groupBy('label_id')
                    ->getAll();
                $map = [];

                foreach ($countsRows as $r) {
                    $map[$r['label_id']] = (int) $r['c'];
                }

                foreach ($labels as $l) {
                    $l->tasks_count = $map[$l->id] ?? 0;
                }
            }
            render('labels/index', ['labels' => $labels]);
            break;

        case 'label_tasks':
            $labelId = $_GET['label_id'] ?? null;

            if (!$labelId) {
                echo json_encode(['error' => 'ID de etiqueta requerido']);
                exit;
            }

            // 🚀 ANTES (SQL manual complejo):
            // $tasks = Label::getAll('
            //     SELECT t.*, u.name as user_name, p.name as project_name
            //     FROM tasks t
            //     INNER JOIN task_labels tl ON t.id = tl.task_id
            //     LEFT JOIN users u ON t.user_id = u.id
            //     LEFT JOIN projects p ON t.project_id = p.id
            //     WHERE tl.label_id = ?
            //     ORDER BY t.created_at DESC
            // ', [$labelId]);

            // ✅ DESPUÉS (Modo Lazy optimizado automáticamente):
            $orm = app()->orm();
            $tasks = $orm->table('tasks as t')
                ->lazy()                                                    // 🚀 Activa optimización automática
                ->select(['t.*', 'u.name as user_name', 'p.name as project_name'])
                ->join('task_labels as tl', 't.id', '=', 'tl.task_id')    // INNER JOIN optimizado
                ->leftJoin('users as u', 't.user_id', '=', 'u.id')        // LEFT JOIN optimizado
                ->leftJoin('projects as p', 't.project_id', '=', 'p.id')  // LEFT JOIN optimizado
                ->where('tl.label_id', '=', $labelId)                     // WHERE optimizado
                ->orderBy('t.created_at', 'desc')                         // ORDER BY optimizado
                ->collect()                                               // ✅ Ejecuta UNA consulta optimizada
            ;

            header('Content-Type: application/json');
            echo json_encode($tasks);
            exit;

        case 'label_create':
            if ($_POST !== []) {
                try {
                    $label = new Label(Label::tableName(), app()->orm());
                    $label->createOne($_POST);
                    flash('success', 'Etiqueta creada exitosamente');
                    redirect('?action=labels');
                } catch (Exception $e) {
                    flash('error', 'Error al crear etiqueta: ' . $e->getMessage());
                }
            }

            render('labels/create');
            break;

        case 'label_edit':
            if ($id === null || $id === 0) {
                flash('error', 'ID de etiqueta requerido');
                redirect('?action=labels');
            }

            $label = (new Label(Label::tableName(), app()->orm()))->find($id);

            if (!$label instanceof Label) {
                flash('error', 'Etiqueta no encontrada');
                redirect('?action=labels');
            }

            // Añadir conteo de tareas
            $countRow = app()->orm()->table('task_labels')
                ->select(['COUNT(*) as c'])
                ->where('label_id', '=', $label->id)
                ->firstArray();
            $label->tasks_count = (int) ($countRow['c'] ?? 0);

            if ($_POST !== []) {
                try {
                    $label->fill($_POST);
                    $label->store();
                    flash('success', 'Etiqueta actualizada exitosamente');
                    redirect('?action=labels');
                } catch (Exception $e) {
                    flash('error', 'Error al actualizar etiqueta: ' . $e->getMessage());
                }
            }

            render('labels/edit', ['label' => $label]);
            break;

        case 'label_delete':
            if ($id === null || $id === 0) {
                flash('error', 'ID de etiqueta requerido');
                redirect('?action=labels');
            }

            $label = (new Label(Label::tableName(), app()->orm()))->find($id);

            if ($label instanceof Label) {
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
