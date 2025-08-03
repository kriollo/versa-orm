<?php
// Vista: Editar tarea estilo Trello
?>
<div class="mb-6">
    <a href="?action=list" class="inline-flex items-center text-blue-600 hover:text-blue-800 font-medium">
        <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
        </svg>
        Volver a tareas
    </a>
</div>
<div class="max-w-xl mx-auto">
    <div class="bg-white shadow-xl rounded-lg overflow-hidden">
        <div class="bg-gradient-to-r from-green-600 to-emerald-600 px-6 py-6">
            <h1 class="text-3xl font-bold text-white flex items-center">
                <svg class="w-8 h-8 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                </svg>
                Editar Tarea
            </h1>
            <p class="text-green-100 mt-2">Modifica los detalles de la tarea</p>
        </div>
        <form method="post" action="?action=update" class="p-6 space-y-6">
            <input type="hidden" name="id" value="<?= is_array($task) ? $task['id'] : $task->id ?>" />
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">Título de la tarea *</label>
                <input type="text" name="title" value="<?= htmlspecialchars(is_array($task) ? $task['title'] : $task->title) ?>" required class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-green-500 transition duration-200" placeholder="Ej: Implementar login" />
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">Descripción</label>
                <textarea name="description" rows="3" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-green-500 transition duration-200" placeholder="Detalles de la tarea..."><?= htmlspecialchars(is_array($task) ? $task['description'] : $task->description) ?></textarea>
            </div>
            <div class="flex gap-4">
                <div class="flex-1">
                    <label class="block text-sm font-medium text-gray-700 mb-2">Proyecto</label>
                    <select name="project_id" class="w-full border rounded px-2 py-2">
                        <?php foreach ($allProjects as $proj): ?>
                            <option value="<?= $proj['id'] ?>" <?= $proj['id'] == $task['project_id'] ? 'selected' : '' ?>><?= htmlspecialchars($proj['name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="flex-1">
                    <label class="block text-sm font-medium text-gray-700 mb-2">Usuario asignado</label>
                    <select name="user_id" class="w-full border rounded px-2 py-2">
                        <option value="">Sin asignar</option>
                        <?php foreach ($allUsers as $user): ?>
                            <option value="<?= $user['id'] ?>" <?= $user['id'] == $task['user_id'] ? 'selected' : '' ?>><?= htmlspecialchars($user['name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">Etiquetas</label>
                <div class="flex flex-wrap gap-2">
                    <?php foreach ($allLabels as $label): ?>
                        <label class="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-semibold" style="background:<?= htmlspecialchars($label['color'] ?? '#eee') ?>;color:#222;">
                            <input type="checkbox" name="labels[]" value="<?= $label['id'] ?>" <?= in_array($label['id'], $task['label_ids'] ?? []) ? 'checked' : '' ?> />
                            <?= htmlspecialchars($label['name']) ?>
                        </label>
                    <?php endforeach; ?>
                </div>
            </div>
            <div class="flex items-center gap-4">
                <label class="flex items-center gap-2">
                    <input type="checkbox" name="completed" value="1" <?= isset($task['completed']) && $task['completed'] ? 'checked' : '' ?> />
                    <span class="text-sm">Completada</span>
                </label>
                <button type="submit" class="bg-green-600 hover:bg-green-700 text-white px-6 py-2 rounded shadow font-bold">Guardar cambios</button>
            </div>
        </form>
    </div>
</div>
<?php $content = ob_get_clean(); ?>
