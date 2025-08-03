<?php
// Vista: Crear nueva tarea estilo Trello
?>
<div class="mb-6">
    <?php if (isset($_GET['project_id'])): ?>
        <a href="?action=show_project&id=<?= htmlspecialchars($_GET['project_id']) ?>" class="inline-flex items-center text-blue-600 hover:text-blue-800 font-medium">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
            </svg>
            Volver al proyecto
        </a>
    <?php else: ?>
        <a href="?action=projects" class="inline-flex items-center text-blue-600 hover:text-blue-800 font-medium">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
            </svg>
            Volver a proyectos
        </a>
    <?php endif; ?>
</div>
<div class="max-w-xl mx-auto">
    <div class="bg-white shadow-xl rounded-lg overflow-hidden">
        <div class="bg-gradient-to-r from-indigo-600 to-purple-600 px-6 py-6">
            <h1 class="text-3xl font-bold text-white flex items-center">
                <svg class="w-8 h-8 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
                </svg>
                Crear Nueva Tarea
            </h1>
            <p class="text-indigo-100 mt-2">
                <?php if (isset($_GET['project_id'])): ?>
                    Añade una nueva tarea a este proyecto
                <?php else: ?>
                    Organiza tu trabajo creando una nueva tarea
                <?php endif; ?>
            </p>
        </div>
        <form method="post" action="?action=create" class="p-6 space-y-6">
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">Título de la tarea *</label>
                <input type="text" name="title" required class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition duration-200" placeholder="Ej: Implementar login" />
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">Descripción</label>
                <textarea name="description" rows="3" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition duration-200" placeholder="Detalles de la tarea..."></textarea>
            </div>
            <div class="flex gap-4">
                <div class="flex-1">
                    <label class="block text-sm font-medium text-gray-700 mb-2">Proyecto</label>
                    <select name="project_id" class="w-full border rounded px-2 py-2">
                        <?php foreach ($allProjects as $proj): ?>
                            <option value="<?= $proj['id'] ?>" <?= isset($_GET['project_id']) && $_GET['project_id'] == $proj['id'] ? 'selected' : '' ?>><?= htmlspecialchars($proj['name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="flex-1">
                    <label class="block text-sm font-medium text-gray-700 mb-2">Usuario asignado</label>
                    <select name="user_id" class="w-full border rounded px-2 py-2">
                        <option value="">Sin asignar</option>
                        <?php foreach ($allUsers as $user): ?>
                            <option value="<?= $user['id'] ?>"><?= htmlspecialchars($user['name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">Etiquetas</label>
                <div class="flex flex-wrap gap-2">
                    <?php foreach ($allLabels as $label): ?>
                        <label class="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-semibold" style="background:<?= htmlspecialchars($label['color'] ?? '#eee') ?>;color:#222;">
                            <input type="checkbox" name="labels[]" value="<?= $label['id'] ?>" />
                            <?= htmlspecialchars($label['name']) ?>
                        </label>
                    <?php endforeach; ?>
                </div>
            </div>
            <div class="flex items-center gap-4">
                <label class="flex items-center gap-2">
                    <input type="checkbox" name="completed" value="1" />
                    <span class="text-sm">Completada</span>
                </label>
                <button type="submit" class="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-2 rounded shadow font-bold">Crear tarea</button>
            </div>
        </form>
    </div>
</div>
<?php $content = ob_get_clean(); ?>
