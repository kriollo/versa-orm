<?php

declare(strict_types=1);

namespace Controllers;

use App\Models\Label;

class LabelController
{
    public static function handle(string $action, null|int $id): void
    {
        switch ($action) {
            case 'labels':
                $labels = models()->label()->all();
                if ($labels !== []) {
                    $labelIds = array_map(static fn ($l) => $l->id, $labels);
                    $countsRows = app()
                        ->orm()
                        ->table('task_labels')
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
                    exit();
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
                $tasks = $orm
                    ->table('tasks as t')
                    ->lazy()
                    ->select(['t.*', 'u.name as user_name', 'p.name as project_name'])
                    ->join('task_labels as tl', 't.id', '=', 'tl.task_id')
                    ->leftJoin('users as u', 't.user_id', '=', 'u.id')
                    ->leftJoin('projects as p', 't.project_id', '=', 'p.id')
                    ->where('tl.label_id', '=', $labelId)
                    ->orderBy('t.created_at', 'desc')
                    ->collect(); // 🚀 Activa optimización automática // INNER JOIN optimizado // LEFT JOIN optimizado // LEFT JOIN optimizado // WHERE optimizado // ORDER BY optimizado // ✅ Ejecuta UNA consulta optimizada

                header('Content-Type: application/json');
                echo json_encode($tasks);
                exit();

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
                $countRow = app()
                    ->orm()
                    ->table('task_labels')
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
                    flash('error', 'Etiqueta no encontrada');
                }
                redirect('?action=labels');
                break;
        }
    }
}
