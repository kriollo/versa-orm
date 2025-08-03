<?php

/**
 * VersaORM Trello Demo
 * Aplicación de demostración tipo Trello para mostrar las capacidades de VersaORM
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
                return strtotime($b->created_at) - strtotime($a->created_at);
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

            $tasks = Task::getAll("SELECT * FROM tasks WHERE project_id = ? ORDER BY status, created_at DESC", [$id]);
            $members = $project->members();
            $owner = User::findArray($project->owner_id);

            render('projects/show', compact('project', 'tasks', 'members', 'owner'));
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
            $tasks = Task::getAll("
                SELECT t.*, p.name as project_name, u.name as user_name
                FROM tasks t
                LEFT JOIN projects p ON t.project_id = p.id
                LEFT JOIN users u ON t.user_id = u.id
                ORDER BY t.created_at DESC
            ");
            render('tasks/index', compact('tasks'));
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

            $projects = Project::all();
            $users = User::all();
            $labels = Label::all();
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

            $projects = Project::all();
            $users = User::all();
            $labels = Label::all();
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
                $count = Label::getAll("SELECT COUNT(*) as count FROM task_labels WHERE label_id = ?", [$label->id]);
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
