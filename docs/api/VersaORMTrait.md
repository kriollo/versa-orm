# VersaORMTrait

The `VersaORMTrait` provides utility methods to manage connections to the VersaORM instance within a class, allowing quick integration.

## Contents

- [Attributes](#attributes)
- [Methods](#methods)

---

## Attributes

- **`protected ?VersaORM $db`**: Holds the current VersaORM instance.

- **`protected static array $DEFAULT_CONFIG`**: Contains default settings for database connections.

---

## Methods

### `connectORM(): void`

Establishes a connection using global configuration settings.

**Usage:**
```php
class SomeService {
    use \VersaORM\Traits\VersaORMTrait;

    public function init() {
        $this->connectORM();
    }
}
```

### `disconnectORM(): void`

Disconnects and cleans up the current VersaORM instance.

**Usage:**
```php
$this->disconnectORM();
```

### `getORM(): ?VersaORM`

Returns the current instance of VersaORM.

**Return:**
Returns the connected VersaORM instance, or `null` if not connected.

**Usage:**
```php
$orm = $this->getORM();
```

---

## Examples of Use

### Basic Usage
```php
class UserManager {
    use \VersaORM\Traits\VersaORMTrait;

    public function __construct() {
        $this->connectORM();
    }

    public function listActiveUsers() {
        $orm = $this->getORM();
        return $orm->table('users')->where('active', 1)->getAll();
    }
}
```

### Graceful Disconnection
```php
$manager = new UserManager();
$users = $manager->listActiveUsers();

// Perform operations with $users

$manager->disconnectORM();
```

---

## Advanced Scenarios

### Dynamic Configuration
Configure specific settings before initialization:
```php
class AdvancedManager {
    use \VersaORM\Traits\VersaORMTrait;

    public function customConnect($settings) {
        global $config;
        $config['DB'] = array_merge($config['DB'], $settings);
        $this->connectORM();
    }
}
```

