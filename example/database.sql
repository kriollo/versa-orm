-- Migración para VersaORM Trello Demo
-- Archivo: database.sql

-- Crear base de datos si no existe
CREATE DATABASE IF NOT EXISTS versaorm_trello CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE versaorm_trello;

-- Tabla usuarios
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    avatar_color VARCHAR(7) DEFAULT '#3498db',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Tabla proyectos
CREATE TABLE projects (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    color VARCHAR(7) DEFAULT '#3498db',
    owner_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Tabla relación usuarios-proyectos (many-to-many)
CREATE TABLE project_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    project_id INT NOT NULL,
    user_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_project_user (project_id, user_id)
);

-- Tabla etiquetas
CREATE TABLE labels (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    color VARCHAR(7) NOT NULL DEFAULT '#6c757d',
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Tabla tareas
CREATE TABLE tasks (
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
);

-- Tabla relación tareas-etiquetas (many-to-many)
CREATE TABLE task_labels (
    id INT AUTO_INCREMENT PRIMARY KEY,
    task_id INT NOT NULL,
    label_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
    FOREIGN KEY (label_id) REFERENCES labels(id) ON DELETE CASCADE,
    UNIQUE KEY unique_task_label (task_id, label_id)
);

-- Datos de ejemplo
INSERT INTO users (name, email, avatar_color) VALUES
('Juan Pérez', 'juan@example.com', '#e74c3c'),
('María García', 'maria@example.com', '#3498db'),
('Carlos López', 'carlos@example.com', '#2ecc71'),
('Ana Martínez', 'ana@example.com', '#f39c12');

INSERT INTO labels (name, color, description) VALUES
('Bug', '#e74c3c', 'Errores que necesitan ser corregidos'),
('Feature', '#3498db', 'Nuevas funcionalidades'),
('Urgent', '#e67e22', 'Tareas urgentes'),
('Design', '#9b59b6', 'Tareas relacionadas con diseño'),
('Documentation', '#2ecc71', 'Documentación y manuales');

INSERT INTO projects (name, description, color, owner_id) VALUES
('VersaORM Demo', 'Proyecto de demostración de VersaORM', '#3498db', 1),
('Sistema de Inventario', 'Gestión de inventarios y productos', '#e74c3c', 2),
('App Móvil', 'Desarrollo de aplicación móvil', '#2ecc71', 1);

-- Asignar usuarios a proyectos
INSERT INTO project_users (project_id, user_id) VALUES
(1, 1), (1, 2), (1, 3),
(2, 2), (2, 4),
(3, 1), (3, 3), (3, 4);

-- Tareas de ejemplo
INSERT INTO tasks (title, description, status, priority, project_id, user_id, due_date) VALUES
('Configurar base de datos', 'Crear tablas y configurar conexiones', 'done', 'high', 1, 1, '2025-08-01'),
('Implementar modelos', 'Crear modelos con VersaORM', 'in_progress', 'high', 1, 2, '2025-08-05'),
('Diseñar interfaz', 'Crear mockups y diseños', 'todo', 'medium', 1, 3, '2025-08-10'),
('Gestión de productos', 'CRUD de productos', 'todo', 'high', 2, 2, '2025-08-15'),
('Login y autenticación', 'Sistema de usuarios', 'in_progress', 'urgent', 3, 1, '2025-08-08');

-- Asignar etiquetas a tareas
INSERT INTO task_labels (task_id, label_id) VALUES
(1, 1), (1, 3),
(2, 2), (2, 5),
(3, 4),
(4, 2),
(5, 2), (5, 3);
