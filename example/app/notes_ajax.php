<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use App\Models\Note;
use App\Models\Task;

header('Content-Type: application/json');

$action = $_POST['action'] ?? $_GET['action'] ?? null;
$taskId = $_POST['task_id'] ?? $_GET['task_id'] ?? null;

switch ($action) {
    case 'get_notes':
        if ($taskId) {
            // Obtener ORM perezosamente y consultar notas como arrays
            $orm = app()->orm();
            $notes = $orm->table('task_notes')
                ->where('task_id', '=', (int) $taskId)
                ->orderBy('created_at', 'DESC')
                ->get() // array<int,array>
            ;
            $notesData = [];

            foreach ($notes as $noteArr) {
                // Obtener usuario de la nota (user_id en array)
                $userName = 'Usuario desconocido';

                if (isset($noteArr['user_id'])) {
                    $user = app()->orm()->table('users')->where('id', '=', (int) $noteArr['user_id'])->firstArray();

                    if ($user !== null && $user !== []) {
                        $userName = $user['name'] ?? $userName;
                    }
                }
                $noteArr['user_name'] = $userName;
                $notesData[] = $noteArr;
            }
            echo json_encode(['success' => true, 'notes' => $notesData]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Task ID is required.']);
        }
        break;

    case 'add_note':
        $taskId = $_POST['task_id'] ?? null;
        $content = $_POST['content'] ?? null;

        if ($taskId && $content) {
            try {
                // Iniciar sesión para obtener el ID de usuario, o usar 1 por defecto para la demo
                if (session_status() === PHP_SESSION_NONE) {
                    session_start();
                }
                $orm = app()->orm();
                $task = (new Task(Task::tableName(), $orm))->find((int) $taskId);
                $userId = $task instanceof Task ? $task->getUserIdByTaskId((int) $taskId) : 1; // Asignar usuario por defecto si no se encuentra

                // Crear nota usando el ORM directamente
                $note = (new Note(Note::tableName(), $orm));
                $note->fill([
                    'task_id' => (int) $taskId,
                    'content' => $content,
                    'user_id' => $userId,
                ]);
                $note->store();
                echo json_encode(['success' => true]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'message' => 'Error al guardar la nota: ' . $e->getMessage()]);
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'El ID de la tarea y el contenido son obligatorios.']);
        }
        break;

    case 'update_note':
        $noteId = $_POST['note_id'] ?? null;
        $content = $_POST['content'] ?? null;

        if ($noteId && $content) {
            try {
                $note = (new Note(Note::tableName(), app()->orm()))->find((int) $noteId);

                if ($note instanceof Note) {
                    $note->content = $content;
                    $note->store();
                    echo json_encode(['success' => true]);
                } else {
                    echo json_encode(['success' => false, 'message' => 'Note not found.']);
                }
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'message' => $e->getMessage()]);
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'Note ID and content are required.']);
        }
        break;

    case 'delete_note':
        $noteId = $_POST['note_id'] ?? null;

        if ($noteId) {
            try {
                $note = (new Note(Note::tableName(), app()->orm()))->find((int) $noteId);

                if ($note instanceof Note) {
                    $note->trash();
                    echo json_encode(['success' => true]);
                } else {
                    echo json_encode(['success' => false, 'message' => 'Note not found.']);
                }
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'message' => $e->getMessage()]);
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'Note ID is required.']);
        }
        break;

    default:
        echo json_encode(['success' => false, 'message' => 'Invalid action.']);
        break;
}
