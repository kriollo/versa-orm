<?php

declare(strict_types=1);

namespace Controllers;

class LabelController
{
    public static function handle(string $action, ?int $id): void
    {
        switch ($action) {
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
                // ...otros casos: label_tasks, label_create, label_edit, label_delete
        }
    }
}
