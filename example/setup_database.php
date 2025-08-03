<?php

/**
 * Script para crear la base de datos y tablas usando VersaORM
 * Ejecutar desde línea de comandos: php setup_database.php
 */

require_once __DIR__ . '/bootstrap.php';

use VersaORM\VersaORM;
use VersaORM\VersaModel;
use App\Models\User;
use App\Models\Project;
use App\Models\Task;
use App\Models\Label;

try {
    echo "🚀 Configurando base de datos con VersaORM...\n\n";

    // Obtener instancia de VersaORM
    $orm = VersaModel::getGlobalORM();
    if (!$orm) {
        throw new Exception('No se pudo obtener la instancia de VersaORM');
    }

    echo "✓ Conexión a VersaORM establecida\n";

    // Crear tablas usando SQL raw
    $tables = [
        // Tabla usuarios
        "CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(150) NOT NULL UNIQUE,
            avatar_color VARCHAR(7) DEFAULT '#3498db',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        // Tabla proyectos
        "CREATE TABLE IF NOT EXISTS projects (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            description TEXT,
            color VARCHAR(7) DEFAULT '#3498db',
            owner_id INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        // Tabla relación usuarios-proyectos
        "CREATE TABLE IF NOT EXISTS project_users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            project_id INT NOT NULL,
            user_id INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE KEY unique_project_user (project_id, user_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        // Tabla etiquetas
        "CREATE TABLE IF NOT EXISTS labels (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(50) NOT NULL,
            color VARCHAR(7) NOT NULL DEFAULT '#6c757d',
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        // Tabla tareas
        "CREATE TABLE IF NOT EXISTS tasks (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(200) NOT NULL,
            description TEXT,
            status ENUM('todo', 'in_progress', 'done') DEFAULT 'todo',
            priority ENUM('low', 'medium', 'high', 'urgent') DEFAULT 'medium',
            due_date DATE NULL,
            project_id INT NOT NULL,
            user_id INT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        // Tabla relación tareas-etiquetas
        "CREATE TABLE IF NOT EXISTS task_labels (
            id INT AUTO_INCREMENT PRIMARY KEY,
            task_id INT NOT NULL,
            label_id INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
            FOREIGN KEY (label_id) REFERENCES labels(id) ON DELETE CASCADE,
            UNIQUE KEY unique_task_label (task_id, label_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
    ];

    // Crear tablas
    foreach ($tables as $i => $sql) {
        try {
            $orm->exec($sql);
            echo "✓ Tabla " . ($i + 1) . " creada correctamente\n";
        } catch (Exception $e) {
            echo "⚠ Error creando tabla " . ($i + 1) . ": " . $e->getMessage() . "\n";
        }
    }

    echo "\n📝 Creando datos de ejemplo...\n";

    // Verificar si ya hay datos
    $existingUsers = $orm->exec("SELECT COUNT(*) as count FROM users", []);
    if ($existingUsers && count($existingUsers) > 0 && $existingUsers[0]['count'] > 0) {
        echo "⚠ Ya existen datos en la base de datos. Saltando inserción de datos de ejemplo.\n";
    } else {
        // Crear usuarios de ejemplo
        $users = [
            ['name' => 'Juan Pérez', 'email' => 'juan@example.com', 'avatar_color' => '#e74c3c'],
            ['name' => 'María García', 'email' => 'maria@example.com', 'avatar_color' => '#3498db'],
            ['name' => 'Carlos López', 'email' => 'carlos@example.com', 'avatar_color' => '#2ecc71'],
            ['name' => 'Ana Martínez', 'email' => 'ana@example.com', 'avatar_color' => '#f39c12']
        ];

        foreach ($users as $userData) {
            try {
                $user = VersaModel::dispense('users');
                $user->name = $userData['name'];
                $user->email = $userData['email'];
                $user->avatar_color = $userData['avatar_color'];
                $user->store();
                echo "✓ Usuario '{$userData['name']}' creado\n";
            } catch (Exception $e) {
                echo "⚠ Error creando usuario '{$userData['name']}': " . $e->getMessage() . "\n";
            }
        }

        // Crear etiquetas de ejemplo
        $labels = [
            ['name' => 'Bug', 'color' => '#e74c3c', 'description' => 'Errores que necesitan ser corregidos'],
            ['name' => 'Feature', 'color' => '#3498db', 'description' => 'Nuevas funcionalidades'],
            ['name' => 'Urgent', 'color' => '#e67e22', 'description' => 'Tareas urgentes'],
            ['name' => 'Design', 'color' => '#9b59b6', 'description' => 'Tareas relacionadas con diseño'],
            ['name' => 'Documentation', 'color' => '#2ecc71', 'description' => 'Documentación y manuales']
        ];

        foreach ($labels as $labelData) {
            try {
                $label = VersaModel::dispense('labels');
                $label->name = $labelData['name'];
                $label->color = $labelData['color'];
                $label->description = $labelData['description'];
                $label->store();
                echo "✓ Etiqueta '{$labelData['name']}' creada\n";
            } catch (Exception $e) {
                echo "⚠ Error creando etiqueta '{$labelData['name']}': " . $e->getMessage() . "\n";
            }
        }

        // Crear proyectos de ejemplo
        $projects = [
            ['name' => 'VersaORM Demo', 'description' => 'Proyecto de demostración de VersaORM', 'color' => '#3498db', 'owner_id' => 1],
            ['name' => 'Sistema de Inventario', 'description' => 'Gestión de inventarios y productos', 'color' => '#e74c3c', 'owner_id' => 2],
            ['name' => 'App Móvil', 'description' => 'Desarrollo de aplicación móvil', 'color' => '#2ecc71', 'owner_id' => 1]
        ];

        foreach ($projects as $projectData) {
            try {
                $project = VersaModel::dispense('projects');
                $project->name = $projectData['name'];
                $project->description = $projectData['description'];
                $project->color = $projectData['color'];
                $project->owner_id = $projectData['owner_id'];
                $project->store();
                echo "✓ Proyecto '{$projectData['name']}' creado\n";
            } catch (Exception $e) {
                echo "⚠ Error creando proyecto '{$projectData['name']}': " . $e->getMessage() . "\n";
            }
        }

        // Crear tareas de ejemplo
        $tasks = [
            ['title' => 'Configurar base de datos', 'description' => 'Crear tablas y configurar conexiones', 'status' => 'done', 'priority' => 'high', 'project_id' => 1, 'user_id' => 1, 'due_date' => '2025-08-01'],
            ['title' => 'Implementar modelos', 'description' => 'Crear modelos con VersaORM', 'status' => 'in_progress', 'priority' => 'high', 'project_id' => 1, 'user_id' => 2, 'due_date' => '2025-08-05'],
            ['title' => 'Diseñar interfaz', 'description' => 'Crear mockups y diseños', 'status' => 'todo', 'priority' => 'medium', 'project_id' => 1, 'user_id' => 3, 'due_date' => '2025-08-10'],
            ['title' => 'Gestión de productos', 'description' => 'CRUD de productos', 'status' => 'todo', 'priority' => 'high', 'project_id' => 2, 'user_id' => 2, 'due_date' => '2025-08-15'],
            ['title' => 'Login y autenticación', 'description' => 'Sistema de usuarios', 'status' => 'in_progress', 'priority' => 'urgent', 'project_id' => 3, 'user_id' => 1, 'due_date' => '2025-08-08']
        ];

        foreach ($tasks as $taskData) {
            try {
                $task = VersaModel::dispense('tasks');
                $task->title = $taskData['title'];
                $task->description = $taskData['description'];
                $task->status = $taskData['status'];
                $task->priority = $taskData['priority'];
                $task->project_id = $taskData['project_id'];
                $task->user_id = $taskData['user_id'];
                $task->due_date = $taskData['due_date'];
                $task->store();
                echo "✓ Tarea '{$taskData['title']}' creada\n";
            } catch (Exception $e) {
                echo "⚠ Error creando tarea '{$taskData['title']}': " . $e->getMessage() . "\n";
            }
        }

        // Asignar etiquetas a tareas y miembros a proyectos usando SQL directo
        echo "\n🔗 Creando relaciones...\n";

        // Relaciones tarea-etiqueta
        $taskLabelRelations = [
            [1, 1],
            [1, 3], // Tarea 1 con etiquetas 1 y 3
            [2, 2],
            [2, 5], // Tarea 2 con etiquetas 2 y 5
            [3, 4],         // Tarea 3 con etiqueta 4
            [4, 2],         // Tarea 4 con etiqueta 2
            [5, 2],
            [5, 3]  // Tarea 5 con etiquetas 2 y 3
        ];

        foreach ($taskLabelRelations as $relation) {
            try {
                $orm->exec("INSERT IGNORE INTO task_labels (task_id, label_id) VALUES (?, ?)", $relation);
                echo "✓ Relación tarea-etiqueta {$relation[0]}-{$relation[1]} creada\n";
            } catch (Exception $e) {
                echo "⚠ Error creando relación tarea-etiqueta: " . $e->getMessage() . "\n";
            }
        }

        // Relaciones proyecto-usuario (miembros)
        $projectUserRelations = [
            [1, 1],
            [1, 2],
            [1, 3], // Proyecto 1 con usuarios 1, 2, 3
            [2, 2],
            [2, 4],         // Proyecto 2 con usuarios 2, 4
            [3, 1],
            [3, 3],
            [3, 4]  // Proyecto 3 con usuarios 1, 3, 4
        ];

        foreach ($projectUserRelations as $relation) {
            try {
                $orm->exec("INSERT IGNORE INTO project_users (project_id, user_id) VALUES (?, ?)", $relation);
                echo "✓ Relación proyecto-usuario {$relation[0]}-{$relation[1]} creada\n";
            } catch (Exception $e) {
                echo "⚠ Error creando relación proyecto-usuario: " . $e->getMessage() . "\n";
            }
        }
    }

    echo "\n🎉 ¡Base de datos configurada exitosamente con VersaORM!\n";
    echo "📊 Estadísticas:\n";
    echo "   - Usuarios: " . count(User::allArray()) . "\n";
    echo "   - Proyectos: " . count(Project::allArray()) . "\n";
    echo "   - Tareas: " . count(Task::allArray()) . "\n";
    echo "   - Etiquetas: " . count(Label::allArray()) . "\n";
    echo "\n🌐 Puedes acceder a la aplicación en: http://localhost:8080\n";
} catch (Exception $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
    echo "\nVerifica:\n";
    echo "1. Que MySQL esté ejecutándose\n";
    echo "2. Que las credenciales en config.php sean correctas\n";
    echo "3. Que el usuario tenga permisos para crear bases de datos\n";
    echo "4. Que VersaORM esté correctamente configurado\n";
    exit(1);
}
