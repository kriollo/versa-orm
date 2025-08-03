# VersaORM Trello Demo

Una aplicación de demostración tipo Trello construida con PHP y VersaORM para mostrar todas las capacidades del ORM.

## 🚀 Características

- **Gestión de Proyectos**: Crear, editar, eliminar y visualizar proyectos
- **Tablero Kanban**: Visualización de tareas en columnas (To Do, In Progress, Done)
- **Gestión de Tareas**: CRUD completo de tareas con prioridades y fechas de vencimiento
- **Sistema de Etiquetas**: Organización de tareas con etiquetas de colores
- **Gestión de Usuarios**: Administración de usuarios y asignación a proyectos
- **Interfaz Moderna**: UI responsive con Tailwind CSS
- **Demostraciones VersaORM**: Uso completo de todas las características del ORM

## 📋 Requisitos

- PHP 8.1 o superior
- MySQL 5.7 o superior
- Servidor web (Apache/Nginx)
- Composer

## 🛠️ Instalación

1. **Clonar el repositorio**:
   ```bash
   git clone https://github.com/kriollo/versa-orm.git
   cd versa-orm/example
   ```

2. **Instalar dependencias**:
   ```bash
   composer install
   ```

3. **Configurar base de datos**:
   - Crear una base de datos MySQL llamada `versaorm_trello`
   - Importar el archivo `database.sql`
   - Editar `config.php` con tus credenciales de base de datos

4. **Configurar servidor web**:
   - Configurar el document root a la carpeta `example`
   - Asegurar que mod_rewrite esté habilitado (Apache)

5. **Permisos**:
   ```bash
   chmod -R 755 .
   chmod -R 777 ../logs
   ```

## 🎯 Uso

1. Abrir la aplicación en tu navegador
2. El dashboard mostrará estadísticas generales
3. Crear usuarios desde la sección "Usuarios"
4. Crear proyectos y asignar propietarios
5. Añadir tareas a los proyectos
6. Usar etiquetas para organizar las tareas
7. Visualizar el progreso en la vista Kanban de cada proyecto

## 🔧 Estructura del Proyecto

```
example/
├── config.php              # Configuración de la aplicación
├── bootstrap.php            # Inicialización y autoloader
├── index.php               # Controlador principal
├── database.sql            # Script de base de datos
├── .htaccess              # Configuración Apache
├── models/                # Modelos de VersaORM
│   ├── BaseModel.php      # Modelo base con funcionalidades comunes
│   ├── User.php           # Modelo de usuarios
│   ├── Project.php        # Modelo de proyectos
│   ├── Task.php           # Modelo de tareas
│   └── Label.php          # Modelo de etiquetas
└── views/                 # Plantillas PHP
    ├── layout.php         # Layout principal
    ├── dashboard.php      # Dashboard principal
    ├── projects/          # Vistas de proyectos
    ├── tasks/             # Vistas de tareas
    ├── users/             # Vistas de usuarios
    └── labels/            # Vistas de etiquetas
```

## 🎨 Características de VersaORM Demostradas

### 1. **Modelos ActiveRecord**
```php
// Crear registros
$user = User::create(['name' => 'Juan', 'email' => 'juan@example.com']);

// Buscar registros
$user = User::find(1);
$users = User::all();

// Actualizar registros
$user->name = 'Juan Carlos';
$user->store();

// Eliminar registros
$user->trash();
```

### 2. **Consultas SQL Personalizadas**
```php
// Consultas con parámetros
$tasks = Task::getAll("SELECT * FROM tasks WHERE status = ?", ['todo']);

// Consultas con joins
$tasks = Task::getAll("
    SELECT t.*, p.name as project_name
    FROM tasks t
    LEFT JOIN projects p ON t.project_id = p.id
");
```

### 3. **Relaciones Many-to-Many**
```php
// Asignar etiquetas a una tarea
$task->setLabels([1, 2, 3]);

// Obtener etiquetas de una tarea
$labels = $task->labels();
```

### 4. **Validaciones**
```php
protected array $rules = [
    'name' => ['required', 'min:2', 'max:100'],
    'email' => ['required', 'email']
];
```

### 5. **Asignación Masiva**
```php
protected array $fillable = ['name', 'email', 'avatar_color'];

$user = User::dispense('users');
$user->fill($_POST);
```

### 6. **Timestamps Automáticos**
```php
protected bool $timestamps = true;
// Maneja automáticamente created_at y updated_at
```

## 📊 Esquema de Base de Datos

- **users**: Gestión de usuarios del sistema
- **projects**: Proyectos de trabajo
- **project_users**: Relación many-to-many usuarios-proyectos
- **tasks**: Tareas individuales
- **labels**: Etiquetas para organización
- **task_labels**: Relación many-to-many tareas-etiquetas

## 🌟 Ejemplos de Uso Avanzado

### Consultas Complejas
```php
// Tareas con información de proyecto y usuario
$tasks = Task::getAll("
    SELECT
        t.*,
        p.name as project_name,
        p.color as project_color,
        u.name as user_name,
        u.avatar_color
    FROM tasks t
    LEFT JOIN projects p ON t.project_id = p.id
    LEFT JOIN users u ON t.user_id = u.id
    WHERE t.status = ? AND t.due_date < NOW()
    ORDER BY t.priority DESC, t.created_at ASC
", ['todo']);
```

### Estadísticas de Proyecto
```php
// Progreso del proyecto
$project = Project::find(1);
$tasks = $project->tasks();
$completed = array_filter($tasks, fn($t) => $t['status'] === 'done');
$progress = count($tasks) > 0 ? (count($completed) / count($tasks)) * 100 : 0;
```

## 🤝 Contribuir

1. Fork el proyecto
2. Crear rama de feature (`git checkout -b feature/nueva-caracteristica`)
3. Commit los cambios (`git commit -am 'Añadir nueva característica'`)
4. Push a la rama (`git push origin feature/nueva-caracteristica`)
5. Crear Pull Request

## 📄 Licencia

Este proyecto está bajo la licencia MIT. Ver el archivo [LICENSE](../LICENSE) para más detalles.

## 🎯 Objetivos de la Demo

Esta aplicación demuestra:

- ✅ Operaciones CRUD básicas
- ✅ Relaciones entre modelos
- ✅ Consultas SQL personalizadas
- ✅ Validaciones de datos
- ✅ Asignación masiva segura
- ✅ Manejo de timestamps
- ✅ Transacciones de base de datos
- ✅ Paginación de resultados
- ✅ Búsquedas y filtros
- ✅ Interfaz de usuario moderna
- ✅ Arquitectura MVC
- ✅ Seguridad básica

## 🚀 Próximas Características

- [ ] Autenticación de usuarios
- [ ] API REST
- [ ] Notificaciones en tiempo real
- [ ] Exportación de datos
- [ ] Múltiples idiomas
- [ ] Temas personalizables
