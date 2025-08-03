<?php
// Vista: Editar proyecto estilo Trello
?>
<div class="mb-6">
    <a href="?action=projects" class="inline-flex items-center text-blue-600 hover:text-blue-800 font-medium">
        <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
        </svg>
        Volver a proyectos
    </a>
</div>
<div class="max-w-xl mx-auto">
    <div class="bg-white shadow-xl rounded-lg overflow-hidden">
        <div class="bg-gradient-to-r from-blue-600 to-green-600 px-6 py-6">
            <h1 class="text-3xl font-bold text-white flex items-center">
                <svg class="w-8 h-8 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                </svg>
                Editar Proyecto
            </h1>
            <p class="text-blue-100 mt-2">Modifica los detalles del proyecto</p>
        </div>
        <form method="post" action="?action=update_project" class="p-6 space-y-6">
            <input type="hidden" name="id" value="<?= htmlspecialchars($project['id']) ?>" />
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">Nombre del Proyecto *</label>
                <input type="text" name="name" value="<?= htmlspecialchars($project['name']) ?>" required class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-200" placeholder="Ej: Desarrollo de aplicación web" />
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">Descripción</label>
                <textarea name="description" rows="3" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-200" placeholder="Detalles del proyecto..."><?= htmlspecialchars($project['description']) ?></textarea>
            </div>
            <div class="flex items-center gap-4">
                <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded shadow font-bold">Guardar cambios</button>
            </div>
        </form>
    </div>
</div>
<?php $content = ob_get_clean(); ?>
