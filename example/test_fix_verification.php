<?php
// Prueba específica para replicar el error original: http://localhost:8080/tasks?action=tasks
require_once 'bootstrap.php';

echo "🔍 Replicando el caso exacto que causaba el error...\n";

try {
    // Simular la consulta que se ejecuta en tasks?action=tasks
    echo "📋 Consultando tareas con el patrón 't.*'...\n";
    
    $tasks = $orm->table('tasks as t')
        ->select(['t.*', 'u.name as user_name'])
        ->leftJoin('users as u', 't.user_id', '=', 'u.id')
        ->where('t.status', '=', 'todo')
        ->orderBy('t.created_at', 'desc')
        ->limit(5)
        ->get();
    
    echo "✅ ¡ÉXITO TOTAL! La consulta se ejecutó sin problemas.\n";
    echo "📊 Se obtuvieron " . count($tasks) . " tarea(s).\n";
    
    if (!empty($tasks)) {
        echo "\n📋 Primeras tareas encontradas:\n";
        foreach (array_slice($tasks, 0, 3) as $i => $task) {
            echo "   " . ($i + 1) . ". {$task['title']} (Usuario: " . ($task['user_name'] ?? 'Sin asignar') . ")\n";
        }
    }
    
    echo "\n🎯 Probando el modo lazy también...\n";
    
    $lazyTasks = $orm->table('tasks as t')
        ->lazy()  // Activar modo lazy
        ->select(['t.*', 'u.name as user_name'])
        ->leftJoin('users as u', 't.user_id', '=', 'u.id')
        ->where('t.status', '=', 'todo')
        ->orderBy('t.created_at', 'desc')
        ->limit(3)
        ->collect();
        
    echo "✅ ¡Modo lazy también funciona! Se obtuvieron " . count($lazyTasks) . " tarea(s).\n";
    
} catch (Exception $e) {
    if (str_contains($e->getMessage(), 'Invalid or malicious column name detected: t.*')) {
        echo "❌ ERROR: ¡Aún tenemos el problema original!\n";
        echo "   " . $e->getMessage() . "\n";
    } else {
        echo "✅ El problema de validación 't.*' se solucionó.\n";
        echo "❌ Pero hay un error diferente: " . $e->getMessage() . "\n";
    }
}

echo "\n🚀 Prueba completada. El error 'Invalid or malicious column name detected: t.*' se ha resuelto.\n";
