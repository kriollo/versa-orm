# Ejemplos prácticos de eventos del ciclo de vida

Esta sección complementa la guía principal con ejemplos adicionales y casos de uso frecuentes, pensados para usuarios sin experiencia previa. Cada ejemplo incluye explicación y, cuando es posible, el homólogo en SQL.

---

## 1. Validación antes de crear un registro

**PHP (VersaORM):**
```php
VersaModel::on('creating', function ($model, $event) {
    if (!filter_var($model->email, FILTER_VALIDATE_EMAIL)) {
        $event->cancel = true;
    }
});
$user = VersaModel::dispense('users');
$user->name = 'Juan';
$user->email = 'no-es-email';
$result = $user->store(); // null, operación cancelada
```

**SQL (Trigger):**
```sql
CREATE TRIGGER validar_email BEFORE INSERT ON users
FOR EACH ROW
BEGIN
  IF NEW.email NOT LIKE '%@%' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Email inválido';
  END IF;
END;
```

---

## 2. Auditoría automática después de crear

**PHP (VersaORM):**
```php
VersaModel::on('created', function ($model, $event) {
    error_log('Usuario creado: ' . $model->email);
});
```

**SQL (Trigger):**
```sql
CREATE TRIGGER log_usuario AFTER INSERT ON users
FOR EACH ROW
BEGIN
  INSERT INTO audit_log (accion, usuario) VALUES ('creado', NEW.email);
END;
```

---

## 3. Prevenir borrado de usuarios especiales

**PHP (VersaORM):**
```php
VersaModel::on('deleting', function ($model, $event) {
    if ($model->status === 'admin') {
        $event->cancel = true;
    }
});
```

**SQL (Trigger):**
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

## 4. Listener solo para un modelo específico

**PHP (VersaORM):**
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

## 5. Uso de métodos mágicos para validación

**PHP (VersaORM):**
```php
class UserModel extends VersaModel {
    public function beforeCreate() {
        if (empty($this->email)) {
            throw new Exception('Email requerido');
        }
    }
}
```

---

## 6. Debug y testing de listeners

**PHP (VersaORM):**
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

---

¿Tienes dudas o necesitas más ejemplos? Consulta la guía principal de [Eventos del Ciclo de Vida](eventos-ciclo-vida.md) o la sección de [Manejo de Errores](../../03-basico/manejo-errores.md).
