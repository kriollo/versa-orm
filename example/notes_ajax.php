<?php

require_once __DIR__ . '/bootstrap.php';

use App\Models\Note;
use App\Models\Task;

header('Content-Type: application/json');

$action = $_POST['action'] ?? $_GET['action'] ?? null;
$taskId = $_POST['task_id'] ?? $_GET['task_id'] ?? null;

switch ($action) {
    case 'get_notes':
        if ($taskId) {
            $notes     = Note::findByTask((int)$taskId);
            $notesData = [];
            foreach ($notes as $note) {
                $user                  = $note->user();
                $noteData              = $note->export();
                $noteData['user_name'] = $user ? $user->name : 'Usuario desconocido';
                $notesData[]           = $noteData;
            }
            echo json_encode(['success' => true, 'notes' => $notesData]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Task ID is required.']);
        }
        break;

    case 'add_note':
        $taskId  = $_POST['task_id'] ?? null;
        $content = $_POST['content'] ?? null;

        if ($taskId && $content) {
            try {
                // Iniciar sesión para obtener el ID de usuario, o usar 1 por defecto para la demo
                if (session_status() === PHP_SESSION_NONE) {
                    session_start();
                }
                $orm    = Note::getGlobalORM();
                $task   = Task::find((int)$taskId);
                $userId = $task ? $task->getUserIdByTaskId((int)$taskId) : 1; // Asignar usuario por defecto si no se encuentra

                Note::create([
                    'task_id' => (int)$taskId,
                    'content' => $content,
                    'user_id' => $userId,
                ]);
                echo json_encode(['success' => true]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'message' => 'Error al guardar la nota: ' . $e->getMessage()]);
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'El ID de la tarea y el contenido son obligatorios.']);
        }
        break;

    case 'update_note':
        $noteId  = $_POST['note_id'] ?? null;
        $content = $_POST['content'] ?? null;
        if ($noteId && $content) {
            try {
                $note = Note::find((int)$noteId);
                if ($note) {
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
                $note = Note::find((int)$noteId);
                if ($note) {
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
