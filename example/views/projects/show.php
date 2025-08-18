<?php

/**
 * Vista para mostrar detalles de un proyecto.
 */
?>

<div class="max-w-6xl mx-auto">
    <!-- Header del proyecto -->
    <div class="bg-white dark:bg-gray-800 shadow rounded-lg mb-6 transition-colors">
        <div class="h-32" style="background: linear-gradient(135deg, <?php echo htmlspecialchars($project->color); ?>, <?php echo htmlspecialchars($project->color); ?>80);">
            <div class="p-6 h-full flex items-end">
                <div class="flex-1">
                    <h1 class="text-white text-3xl font-bold mb-2"><?php echo htmlspecialchars($project->name); ?></h1>
                    <?php if ($project->description) { ?>
                        <p class="text-white/90"><?php echo htmlspecialchars($project->description); ?></p>
                    <?php } ?>
                </div>
                <div class="flex items-center space-x-3">
                    <a href="?action=project_edit&id=<?php echo $project->id; ?>" class="bg-white/20 hover:bg-white/30 text-white px-4 py-2 rounded-lg transition-colors">
                        <i class="fas fa-edit mr-2"></i>
                        Editar
                    </a>
                    <a href="?action=projects" class="bg-white/20 hover:bg-white/30 text-white px-4 py-2 rounded-lg transition-colors">
                        <i class="fas fa-arrow-left mr-2"></i>
                        Volver
                    </a>
                </div>
            </div>
        </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Información del proyecto -->
        <div class="lg:col-span-1">
            <div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6 mb-6 transition-colors">
                <h3 class="text-lg font-semibold mb-4 text-gray-900 dark:text-white transition-colors">Información del Proyecto</h3>

                <div class="space-y-3">
                    <div>
                        <label class="text-sm font-medium text-gray-500 dark:text-gray-300 transition-colors">Propietario</label>
                        <div class="flex items-center mt-1">
                            <?php if ($owner) { ?>
                                <div class="avatar mr-2" style="background-color: <?php echo htmlspecialchars($owner['avatar_color']); ?>">
                                    <?php echo strtoupper(substr($owner['name'], 0, 2)); ?>
                                </div>
                                <span class="text-gray-900 dark:text-white transition-colors"><?php echo htmlspecialchars($owner['name']); ?></span>
                            <?php } else { ?>
                                <span class="text-gray-400">Sin propietario</span>
                            <?php } ?>
                        </div>
                    </div>

                    <div>
                        <label class="text-sm font-medium text-gray-500 dark:text-gray-300 transition-colors">Fecha de creación</label>
                        <p class="mt-1 text-gray-900 dark:text-gray-200 transition-colors"><?php echo isset($project->created_at) ? safe_date('M Y', $project->created_at) : ''; ?></p>
                    </div>

                    <div>
                        <label class="text-sm font-medium text-gray-500 dark:text-gray-300 transition-colors">Última actualización</label>
                        <p class="mt-1 text-gray-900 dark:text-gray-200 transition-colors"><?php echo isset($project->updated_at) ? safe_date('M Y', $project->updated_at) : ''; ?></p>
                    </div>
                </div>
            </div>

            <!-- Miembros del proyecto -->
            <div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6 transition-colors">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-semibold text-gray-900 dark:text-white transition-colors">Miembros (<?php echo count($members); ?>)</h3>
                    <button id="addMemberBtn" class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 text-sm font-medium transition-colors">
                        <i class="fas fa-plus mr-1"></i>
                        Agregar
                    </button>
                </div>

                <?php if (!empty($members)) { ?>
                    <div class="space-y-2">
                        <?php foreach ($members as $member) { ?>
                            <div class="flex items-center justify-between p-2 hover:bg-gray-50 dark:hover:bg-gray-700 rounded group transition-colors">
                                <div class="flex items-center">
                                    <div class="avatar mr-3" style="background-color: <?php echo htmlspecialchars($member['avatar_color']); ?>">
                                        <?php echo strtoupper(substr($member['name'], 0, 2)); ?>
                                    </div>
                                    <div>
                                        <p class="font-medium text-gray-900 dark:text-white transition-colors"><?php echo htmlspecialchars($member['name']); ?></p>
                                        <p class="text-sm text-gray-500 dark:text-gray-300 transition-colors"><?php echo htmlspecialchars($member['email']); ?></p>
                                    </div>
                                </div>
                                <form method="POST" action="?action=project_remove_member" class="inline">
                                    <input type="hidden" name="project_id" value="<?php echo $project->id; ?>">
                                    <input type="hidden" name="user_id" value="<?php echo $member['id']; ?>">
                                    <button type="submit"
                                        class="text-red-500 hover:text-red-700 p-1 rounded hover:bg-red-50 transition-all duration-200 opacity-50 group-hover:opacity-100"
                                        onclick="return confirm('¿Estás seguro de que quieres eliminar este miembro?')"
                                        title="Eliminar miembro">
                                        <i class="fas fa-trash-alt text-sm"></i>
                                    </button>
                                </form>
                            </div>
                        <?php } ?>
                    </div>
                <?php } else { ?>
                    <p class="text-gray-500 dark:text-gray-300 text-center py-4 transition-colors">No hay miembros asignados</p>
                <?php } ?>
            </div>
        </div>

        <!-- Tareas del proyecto -->
        <div class="lg:col-span-2">
            <div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6 transition-colors">
                <div class="flex items-center justify-between mb-6">
                    <h3 class="text-lg font-semibold text-gray-900 dark:text-white transition-colors">Tareas (<?php echo count($tasks); ?>)</h3>
                    <a href="?action=task_create&project_id=<?php echo $project->id; ?>" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors dark:bg-blue-600 dark:hover:bg-blue-500">
                        <i class="fas fa-plus mr-2"></i>
                        Nueva Tarea
                    </a>
                </div>

                <!-- Progreso general -->
                <?php if (count($tasks) > 0) { ?>
                    <?php
                    $completedTasks = array_filter($tasks, static fn ($t): bool => $t['status'] === 'done');
                    $progressPercent = (count($completedTasks) / count($tasks)) * 100;
                    ?>
                    <div class="mb-6">
                        <div class="flex justify-between text-sm text-gray-600 dark:text-gray-300 mb-2 transition-colors">
                            <span>Progreso del proyecto</span>
                            <span><?php echo count($completedTasks); ?>/<?php echo count($tasks); ?> tareas completadas</span>
                        </div>
                        <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3 transition-colors">
                            <div class="bg-green-600 h-3 rounded-full transition-all duration-300" style="width: <?php echo $progressPercent; ?>%"></div>
                        </div>
                    </div>
                <?php } ?>

                <!-- Lista de tareas por estado -->
                <?php
                $tasksByStatus = [
                    'todo' => array_filter($tasks, static fn ($t): bool => $t['status'] === 'todo'),
                    'in_progress' => array_filter($tasks, static fn ($t): bool => $t['status'] === 'in_progress'),
                    'done' => array_filter($tasks, static fn ($t): bool => $t['status'] === 'done'),
                ];
$statusNames = [
    'todo' => 'Por Hacer',
    'in_progress' => 'En Progreso',
    'done' => 'Completadas',
];
$statusColors = [
    'todo' => 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200',
    'in_progress' => 'bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300',
    'done' => 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
];
?>

                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <?php foreach ($tasksByStatus as $status => $statusTasks) { ?>
                        <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4 transition-colors">
                            <h4 class="font-medium text-gray-900 dark:text-white mb-3 flex items-center transition-colors">
                                <span class="inline-block w-3 h-3 rounded-full mr-2 <?php echo $statusColors[$status]; ?>"></span>
                                <?php echo $statusNames[$status]; ?> (<?php echo count($statusTasks); ?>)
                            </h4>

                            <?php if ($statusTasks !== []) { ?>
                                <div class="space-y-2">
                                    <?php foreach ($statusTasks as $task) { ?>
                                        <div class="bg-gray-50 dark:bg-gray-700 p-3 rounded border border-gray-200 dark:border-gray-600 transition-colors">
                                            <div class="flex items-start justify-between">
                                                <div class="flex-1">
                                                    <h5 class="font-medium text-sm mb-1 text-gray-900 dark:text-white transition-colors"><?php echo htmlspecialchars($task['title']); ?></h5>
                                                    <?php if ($task['description']) { ?>
                                                        <p class="text-xs text-gray-600 dark:text-gray-300 mb-2 transition-colors"><?php echo htmlspecialchars(substr($task['description'], 0, 80)); ?><?php echo strlen($task['description']) > 80 ? '...' : ''; ?></p>
                                                    <?php } ?>

                                                    <div class="flex items-center justify-between">
                                                        <span class="text-xs px-2 py-1 rounded <?php echo getPriorityClass($task['priority']); ?>">
                                                            <?php echo ucfirst($task['priority']); ?>
                                                        </span>
                                                        <?php if ($task['due_date']) { ?>
                                                            <?php
                                            $dueRaw = $task['due_date'];

                                                            $fmt = $dueRaw instanceof DateTimeInterface ? $dueRaw->format('d/m') : safe_date_format($dueRaw, 'd/m');
                                                            ?>
                                                            <span class="text-xs text-gray-500 dark:text-gray-400 transition-colors">
                                                                <?php echo htmlspecialchars($fmt); ?>
                                                            </span>
                                                        <?php } ?>
                                                    </div>
                                                </div>
                                                <a href="?action=task_edit&id=<?php echo $task['id']; ?>" class="text-gray-400 hover:text-gray-600 dark:text-gray-300 dark:hover:text-gray-100 ml-2 transition-colors">
                                                    <i class="fas fa-edit text-xs"></i>
                                                </a>
                                                <button class="text-gray-400 hover:text-gray-600 dark:text-gray-300 dark:hover:text-gray-100 ml-2 transition-colors open-status-modal" data-task-id="<?php echo $task['id']; ?>" data-task-status="<?php echo $task['status']; ?>">
                                                    <i class="fas fa-exchange-alt text-xs"></i>
                                                </button>
                                            </div>
                                        </div>
                                    <?php } ?>
                                </div>
                            <?php } else { ?>
                                <p class="text-gray-400 dark:text-gray-300 text-sm text-center py-4 transition-colors">No hay tareas</p>
                            <?php } ?>
                        </div>
                    <?php } ?>
                </div>
            </div>
        </div>
    </div>
</div>

<?php
function getPriorityClass($priority): string
{
    return match ($priority) {
        'urgent' => 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300',
        'high' => 'bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300',
        'medium' => 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300',
        'low' => 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
        default => 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200',
    };
}
?>

<!-- Modal para agregar miembros -->
<div id="addMemberModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 dark:bg-black/70 overflow-y-auto h-full w-full z-50 hidden">
    <div class="relative top-20 mx-auto p-5 border border-gray-200 dark:border-gray-700 w-96 shadow-lg rounded-md bg-white dark:bg-gray-800 transition-colors">
        <div class="mt-3">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-lg font-medium text-gray-900 dark:text-white transition-colors">Agregar Miembro</h3>
                <button id="closeMemberModal" class="text-gray-400 hover:text-gray-600 dark:text-gray-300 dark:hover:text-gray-100 transition-colors">
                    <i class="fas fa-times"></i>
                </button>
            </div>

            <form method="POST" action="?action=project_add_member">
                <input type="hidden" name="project_id" value="<?php echo $project->id; ?>">

                <div class="mb-4">
                    <label for="user_id" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">
                        Seleccionar Usuario
                    </label>
                    <select name="user_id" id="user_id" required class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors">
                        <option value="">Selecciona un usuario</option>
                        <?php if (isset($availableUsers) && is_array($availableUsers)) { ?>
                            <?php foreach ($availableUsers as $user) { ?>
                                <option value="<?php echo $user->id; ?>" class="bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                                    <?php echo htmlspecialchars($user->name); ?> (<?php echo htmlspecialchars($user->email); ?>)
                                </option>
                            <?php } ?>
                        <?php } else { ?>
                            <option value="">No hay usuarios disponibles</option>
                        <?php } ?>
                    </select>

                    <!-- Debug temporal -->
                    <?php if (isset($_GET['debug'])) { ?>
                        <div class="mt-2 text-xs text-gray-500">
                            <p>Debug info:</p>
                            <p>Available users count: <?php echo isset($availableUsers) ? count($availableUsers) : 'undefined'; ?></p>
                            <p>Members count: <?php echo count($members); ?></p>
                            <p>Owner ID: <?php echo $project->owner_id; ?></p>
                        </div>
                    <?php } ?>
                </div>

                <div class="flex items-center justify-end space-x-3">
                    <button type="button" id="cancelAddMember" class="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50">
                        Cancelar
                    </button>
                    <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700">
                        Agregar
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
    // Funcionalidad del modal para agregar miembros
    document.addEventListener('DOMContentLoaded', function() {
        const addMemberBtn = document.getElementById('addMemberBtn');
        const modal = document.getElementById('addMemberModal');
        const closeModal = document.getElementById('closeMemberModal');
        const cancelBtn = document.getElementById('cancelAddMember');

        // Abrir modal
        addMemberBtn?.addEventListener('click', function() {
            modal.classList.remove('hidden');
        });

        // Cerrar modal
        function closeModalFunc() {
            modal.classList.add('hidden');
        }

        closeModal?.addEventListener('click', closeModalFunc);
        cancelBtn?.addEventListener('click', closeModalFunc);

        // Cerrar modal al hacer click fuera
        modal?.addEventListener('click', function(e) {
            if (e.target === modal) {
                closeModalFunc();
            }
        });
    });
</script>

<!-- Modal para Notas -->
<div id="notes-modal" class="fixed z-10 inset-0 overflow-y-auto hidden" aria-labelledby="modal-title" role="dialog" aria-modal="true">
    <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
        <div class="fixed inset-0 bg-gray-500 bg-opacity-75 dark:bg-black/70 transition-opacity" aria-hidden="true"></div>
        <span class="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>
        <div class="inline-block align-bottom bg-white dark:bg-gray-900 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full border border-gray-200 dark:border-gray-700">
            <div class="bg-white dark:bg-gray-900 px-4 pt-5 pb-4 sm:p-6 sm:pb-4 transition-colors">
                <div class="sm:flex sm:items-start">
                    <div class="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-blue-100 dark:bg-blue-900/40 sm:mx-0 sm:h-10 sm:w-10 transition-colors">
                        <i class="fas fa-sticky-note text-blue-600 dark:text-blue-400"></i>
                    </div>
                    <div class="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left">
                        <h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white transition-colors" id="modal-title">Notas para la Tarea</h3>
                        <p id="modal-task-title" class="text-sm text-gray-500 dark:text-gray-300 transition-colors"></p>
                        <div class="mt-4 space-y-2" id="notes-container">
                            <!-- Las notas se cargarán aquí -->
                        </div>
                        <div class="mt-4">
                            <form id="add-note-form">
                                <input type="hidden" name="task_id" id="note-task-id">
                                <textarea name="content" class="w-full border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 rounded-md px-3 py-2 transition-colors" placeholder="Escribe una nueva nota..."></textarea>
                                <button type="submit" class="mt-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors">Agregar Nota</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
            <div class="bg-gray-50 dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse transition-colors">
                <button type="button" class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 shadow-sm px-4 py-2 bg-white dark:bg-gray-800 text-base font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 dark:focus:ring-offset-gray-900 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm transition-colors" id="close-notes-modal">
                    Cerrar
                </button>
            </div>
        </div>
    </div>
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        const modal = document.getElementById('notes-modal');
        const closeButton = document.getElementById('close-notes-modal');
        const notesContainer = document.getElementById('notes-container');
        const modalTaskTitle = document.getElementById('modal-task-title');
        const addNoteForm = document.getElementById('add-note-form');
        const noteTaskIdInput = document.getElementById('note-task-id');

        document.querySelectorAll('.open-notes-modal').forEach(button => {
            button.addEventListener('click', function() {
                const taskId = this.dataset.taskId;
                const taskTitle = this.dataset.taskTitle;
                modalTaskTitle.textContent = taskTitle;
                noteTaskIdInput.value = taskId;

                // Cargar notas
                loadNotes(taskId);

                modal.classList.remove('hidden');
            });
        });

        closeButton.addEventListener('click', function() {
            modal.classList.add('hidden');
            window.location.reload(); // <-- Recargar la página
        });

        function loadNotes(taskId) {
            fetch('notes_ajax.php?action=get_notes&task_id=' + taskId)
                .then(response => response.json())
                .then(data => {
                    notesContainer.innerHTML = '';
                    if (data.success && data.notes.length > 0) {
                        data.notes.forEach(note => {
                            const noteElement = document.createElement('div');
                            noteElement.classList.add('note-item', 'mb-2', 'p-2', 'bg-gray-100', 'dark:bg-gray-800', 'rounded', 'transition-colors');
                            noteElement.innerHTML = `
                            <div class="flex justify-between items-start">
                                <p class="text-sm text-gray-800 dark:text-gray-200">${note.content}</p>
                                <div class="flex-shrink-0 ml-2">
                                    <button class="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300 edit-note" data-note-id="${note.id}" data-note-content="${note.content}"><i class="fas fa-edit"></i></button>
                                    <button class="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300 delete-note" data-note-id="${note.id}"><i class="fas fa-trash"></i></button>
                                </div>
                            </div>
                            <p class="text-xs text-gray-500 dark:text-gray-400">- ${note.user_name} en ${note.created_at}</p>
                        `;
                            notesContainer.appendChild(noteElement);
                        });
                    } else {
                        notesContainer.innerHTML = '<p class="text-sm text-gray-500 dark:text-gray-400 transition-colors">No hay notas para esta tarea.</p>';
                    }
                });
        }

        addNoteForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            formData.append('action', 'add_note');

            fetch('notes_ajax.php', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        loadNotes(noteTaskIdInput.value);
                        this.reset();
                    } else {
                        alert(data.message);
                    }
                });
        });

        notesContainer.addEventListener('click', function(e) {
            if (e.target.closest('.edit-note')) {
                const button = e.target.closest('.edit-note');
                const noteId = button.dataset.noteId;
                const noteContent = button.dataset.noteContent;

                const editForm = `
                <form class="edit-note-form">
                    <input type="hidden" name="note_id" value="${noteId}">
                    <textarea name="content" class="w-full border border-gray-300 rounded-md px-3 py-2">${noteContent}</textarea>
                    <button type="submit" class="mt-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors">Guardar</button>
                    <button type="button" class="mt-2 bg-gray-500 hover:bg-gray-600 text-white px-4 py-2 rounded-lg transition-colors cancel-edit">Cancelar</button>
                </form>
            `;

                const noteItem = button.closest('.note-item');
                noteItem.innerHTML = editForm;
            }

            if (e.target.closest('.cancel-edit')) {
                loadNotes(noteTaskIdInput.value);
            }

            if (e.target.closest('.delete-note')) {
                const button = e.target.closest('.delete-note');
                const noteId = button.dataset.noteId;

                if (confirm('¿Estás seguro de que quieres eliminar esta nota?')) {
                    fetch('notes_ajax.php', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            body: `action=delete_note&note_id=${noteId}`
                        })
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                loadNotes(noteTaskIdInput.value);
                            } else {
                                alert(data.message);
                            }
                        });
                }
            }
        });

        notesContainer.addEventListener('submit', function(e) {
            if (e.target.classList.contains('edit-note-form')) {
                e.preventDefault();
                const formData = new FormData(e.target);
                formData.append('action', 'update_note');

                fetch('notes_ajax.php', {
                        method: 'POST',
                        body: formData
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            loadNotes(noteTaskIdInput.value);
                        } else {
                            alert(data.message);
                        }
                    });
            }
        });
    });
</script>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const statusModal = document.getElementById('status-modal');
    const statusForm = document.getElementById('status-form');
    const taskStatusSelect = document.getElementById('task-status');

    document.querySelectorAll('.open-status-modal').forEach(button => {
        button.addEventListener('click', function() {
            const taskId = this.dataset.taskId;
            const taskStatus = this.dataset.taskStatus;

            statusForm.action = `?action=task_change_status&id=${taskId}`;
            taskStatusSelect.value = taskStatus;

            statusModal.classList.remove('hidden');
        });
    });

    document.querySelectorAll('.close-status-modal').forEach(button => {
        button.addEventListener('click', function() {
            statusModal.classList.add('hidden');
        });
    });
});
</script>

<!-- Modal para cambiar estado de tarea -->
<div id="status-modal" class="fixed z-10 inset-0 overflow-y-auto hidden" aria-labelledby="modal-title" role="dialog" aria-modal="true">
    <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
        <div class="fixed inset-0 bg-gray-500 bg-opacity-75 dark:bg-black/70 transition-opacity" aria-hidden="true"></div>
        <span class="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>
        <div class="inline-block align-bottom bg-white dark:bg-gray-900 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full border border-gray-200 dark:border-gray-700">
            <form id="status-form" method="POST" action="">
                <div class="bg-white dark:bg-gray-900 px-4 pt-5 pb-4 sm:p-6 sm:pb-4 transition-colors">
                    <div class="sm:flex sm:items-start">
                        <div class="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-blue-100 dark:bg-blue-900/40 sm:mx-0 sm:h-10 sm:w-10 transition-colors">
                            <i class="fas fa-exchange-alt text-blue-600 dark:text-blue-400"></i>
                        </div>
                        <div class="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left">
                            <h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white transition-colors" id="modal-title">Cambiar Estado de la Tarea</h3>
                            <div class="mt-4">
                                <label for="task-status" class="block text-sm font-medium text-gray-700 dark:text-gray-300">Nuevo Estado</label>
                                <select id="task-status" name="status" class="mt-1 block w-full pl-3 pr-10 py-2 text-base border-gray-300 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm rounded-md dark:bg-gray-800 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white">
                                    <option value="todo">Por Hacer</option>
                                    <option value="in_progress">En Progreso</option>
                                    <option value="done">Completada</option>
                                </select>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="bg-gray-50 dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse transition-colors">
                    <button type="submit" class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-blue-600 text-base font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:ml-3 sm:w-auto sm:text-sm">
                        Guardar
                    </button>
                    <button type="button" class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 shadow-sm px-4 py-2 bg-white dark:bg-gray-800 text-base font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 dark:focus:ring-offset-gray-900 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm close-status-modal">
                        Cancelar
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<style>
    .note-count-badge {
        background-color: #3498db;
        color: white;
        border-radius: 50%;
        padding: 2px 6px;
        font-size: 10px;
        position: relative;
        top: -10px;
        right: 5px;
    }

    .has-notes .fa-sticky-note {
        color: #2980b9;
    }

    #status-modal.hidden {
        display: none;
    }
</style>
