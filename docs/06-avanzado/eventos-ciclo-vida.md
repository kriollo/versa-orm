# ⚡️ Eventos del Ciclo de Vida en VersaORM

Esta sección te enseña cómo usar el sistema de eventos del ciclo de vida en VersaORM, permitiendo ejecutar código personalizado en momentos clave de las operaciones CRUD. Ideal para validaciones, logging, auditoría o lógica de negocio avanzada.

## 📋 Contenido de esta sección

Además, puedes consultar la sección de [Ejemplos prácticos de eventos](eventos-ciclo-vida-ejemplos.md) para ver casos de uso frecuentes y comparaciones con triggers SQL.


## 🚦 ¿Qué son los eventos del ciclo de vida?

Los eventos del ciclo de vida son "ganchos" (hooks) que te permiten ejecutar funciones automáticamente antes o después de operaciones como crear, actualizar o eliminar registros. Son equivalentes a los triggers en SQL, pero escritos en PHP y mucho más flexibles.

**Ventajas:**
- Validación y lógica personalizada sin modificar el core del modelo.
- Auditoría y logging centralizado.
- Cancelar operaciones si no cumplen condiciones.
- Fácil de testear y mantener.

**Homólogo en SQL:**
```sql
-- Trigger que valida antes de insertar
CREATE TRIGGER validar_usuario BEFORE INSERT ON users
FOR EACH ROW
BEGIN
  IF NEW.email IS NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Email requerido';
  END IF;
END;
```

En VersaORM, esto se logra con listeners en PHP:

```php
use VersaORM\VersaModel;
VersaModel::on('creating', function ($model, $event) {
    if (empty($model->email)) {
        $event->cancel = true;
    }
});
```

---

## 🏁 Ejemplo básico: registro de listeners

Supongamos que quieres registrar una función que se ejecute antes de crear un usuario:

```php
use VersaORM\VersaModel;
VersaModel::on('creating', function ($model, $event) {
    // Validar que el email no esté vacío
    if (empty($model->email)) {
        $event->cancel = true; // Cancela la operación
    }
});

$user = VersaModel::dispense('users');
$user->name = 'Juan';
$user->email = '';
$result = $user->store(); // $result será null porque se canceló
```

**Explicación:**
- `on('creating', ...)` registra un listener para el evento "creating".
- El listener recibe el modelo y el evento.
- Si el email está vacío, se cancela la operación.

**Homólogo en SQL:**
Ver ejemplo de trigger arriba.

---

## 📅 Tabla de eventos disponibles

| Evento     | Momento de ejecución           | Método mágico equivalente |
|------------|-------------------------------|--------------------------|
| creating   | Antes de crear (insert)       | beforeCreate             |
| created    | Después de crear (insert)     | afterCreate              |
| updating   | Antes de actualizar (update)  | beforeUpdate             |
| updated    | Después de actualizar (update)| afterUpdate              |
| deleting   | Antes de eliminar (delete)    | beforeDelete             |
| deleted    | Después de eliminar (delete)  | afterDelete              |

Puedes registrar listeners para cualquiera de estos eventos:

```php
VersaModel::on('updating', function ($model, $event) {
    // Lógica antes de actualizar
});
```

---

## ⛔ Cancelación de operaciones desde listeners

Puedes cancelar cualquier operación (insert, update, delete) desde el listener:

```php
VersaModel::on('deleting', function ($model, $event) {
    if ($model->status === 'admin') {
        $event->cancel = true; // No permitir borrar admins
    }
});

$user = VersaModel::dispense('users');
$user->name = 'Admin';
$user->status = 'admin';
$user->store();
$user->trash(); // No se borra porque el listener lo cancela
```

**Homólogo en SQL:**
```sql
CREATE TRIGGER no_borrar_admin BEFORE DELETE ON users
FOR EACH ROW
BEGIN
  IF OLD.status = 'admin' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'No se puede borrar admin';
  END IF;
END;
```

---

## ✨ Métodos mágicos y personalización

Puedes definir métodos mágicos en tu modelo para lógica personalizada:

```php
class UserModel extends VersaModel {
    public function beforeCreate() {
        // Se ejecuta antes de crear
        if (empty($this->email)) {
            throw new Exception('Email requerido');
        }
    }
}
```

**Explicación:**
- Si existe un método mágico como `beforeCreate`, se ejecuta automáticamente en el ciclo de vida.
- Puedes lanzar excepciones o modificar el modelo.

**Homólogo en SQL:**
Ver trigger de validación arriba.

---

## 🌐 Listeners globales vs. listeners por modelo

- **Globales:** Se registran con `VersaModel::on()` y afectan todos los modelos.
- **Por modelo:** Puedes registrar listeners en clases hijas o instancias específicas.

```php
class UserModel extends VersaModel {
    public static function boot() {
        self::on('created', function ($model, $event) {
            // Solo para UserModel
        });
    }
}
```

---

## 🐞 Debug y testing de eventos

Para verificar que los listeners se ejecutan correctamente, puedes usar assertions en tus tests:

```php
$called = false;
VersaModel::on('created', function ($model, $event) use (&$called) {
    $called = true;
});
$model = VersaModel::dispense('users');
$model->name = 'Test';
$model->email = 'test@example.com';
$model->store();
assert($called === true);
```

**Homólogo en SQL:**
Puedes verificar triggers con logs o select sobre tablas de auditoría.

---

## ✅ Buenas prácticas y advertencias

- Mantén la lógica de listeners simple y rápida.
- Evita dependencias externas pesadas dentro de listeners.
- Documenta bien los listeners registrados.
- Usa tests para validar que los eventos se disparan correctamente.
- Si usas cancelación, informa al usuario del motivo.

---

¿Tienes dudas? Consulta la sección de [Manejo de Errores](../03-basico/manejo-errores.md) para ver cómo capturar y gestionar excepciones en listeners.
