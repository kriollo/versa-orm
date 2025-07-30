<?php
// Vista: Crear nuevo usuario
echo '<h1 class="text-2xl font-bold text-blue-800 mb-6">Nuevo Usuario</h1>';
echo '<form method="post" action="?action=create_user" class="bg-white shadow rounded-lg p-6 max-w-lg mx-auto">';
echo '  <div class="mb-4">';
echo '    <label class="block text-gray-700 font-semibold mb-2">Nombre:</label>';
echo '    <input type="text" name="name" required class="w-full border border-gray-300 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400" />';
echo '  </div>';
echo '  <div class="mb-4">';
echo '    <label class="block text-gray-700 font-semibold mb-2">Email:</label>';
echo '    <input type="email" name="email" required class="w-full border border-gray-300 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400" />';
echo '  </div>';
echo '  <div class="flex justify-end space-x-2">';
echo '    <button type="submit" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded shadow">Crear Usuario</button>';
echo '    <a href="index.php?action=projects" class="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded">Cancelar</a>';
echo '  </div>';
echo '</form>';
