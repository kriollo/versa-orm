# Tipado y Validación Avanzada

Complemento a la sección de Seguridad y Tipado: enfoques para reforzar consistencia sin sacrificar rendimiento.

## ✅ Prerrequisitos
- Haber leído [Seguridad y Tipado](../07-seguridad-tipado/README.md)
- Conocer ciclo básico `store()` / `storeAll()`
- Familiaridad con batch ([Operaciones Batch Avanzadas](batch-operaciones-avanzado.md)) para validar antes de insertar grandes volúmenes

> Desde seguridad básica pasas aquí a políticas más finas de consistencia y prevención de errores silenciosos.

## Objetivos
- Reducir errores de tipo silenciosos.
- Detectar desalineaciones de esquema tempranamente.
- Proteger contra mass assignment.

## Patrón: Método `rules()` en Modelo
Extiende tu modelo para declarar reglas simples:
```php
class UserModel extends VersaModel {
  public static function rules(): array {
    return [
      'email' => ['required','string','max:255'],
      'active' => ['bool'],
      'age' => ['int','min:0','max:150'],
    ];
  }
}
```
Crea un validador ligero que recorra `rules()` antes de `store()`.

## Validación Manual Pre-Batch
```php
foreach ($lote as $m) {
  if (!filter_var($m->email, FILTER_VALIDATE_EMAIL)) {
    throw new InvalidArgumentException('Email inválido: ' . $m->email);
  }
}
$ids = VersaModel::storeAll($lote);
```

## Casting Consistente
Implementa getters/setters específicos si necesitas normalizar:
```php
class ProductModel extends VersaModel {
  public function setPrice($v) { $this->price = (int)round($v * 100); }
  public function getPrice() { return $this->price / 100; }
}
```
Uso:
```php
$p = ProductModel::dispense('products');
$p->setPrice(19.99);
$p->store();
```
**SQL Equivalente (almacenando precio en centavos):**
```sql
INSERT INTO products (price) VALUES (1999);
```

## Protección Mass Assignment
Lista blanca de campos permitidos:
```php
$white = ['name','email','active'];
foreach ($input as $k=>$v) {
  if (!in_array($k,$white,true)) { continue; }
  $user->$k = $v;
}
```
**SQL potencial posterior (si se hace store()):**
```sql
INSERT INTO users (name,email,active) VALUES (?,?,?);
```

## Sincronización con Esquema
Script utilitario para comparar columnas esperadas vs reales usando el SchemaBuilder:
```php
use VersaORM\Schema\VersaSchema;

function diffSchema($orm, $table, array $expectedCols) {
  // Usar el SchemaBuilder moderno para obtener metadatos
  $schema = $orm->schemaBuilder();
  $cols = $schema->getColumns($table); // devuelve metadatos completos
  $dbCols = array_column($cols, 'name');

  return [
    'missing' => array_diff($expectedCols, $dbCols),
    'extra' => array_diff($dbCols, $expectedCols),
  ];
}

// También puedes verificar directamente
if (!VersaSchema::hasColumn('users', 'email')) {
    VersaSchema::table('users', function ($table) {
        $table->string('email', 100)->unique();
    });
}
```
**SQL subyacente (ejemplo MySQL inspección columnas):**
```sql
SHOW COLUMNS FROM <tabla>;
```

## Checklist de Validación
| Requisito | Verificado |
|-----------|-----------|
| Data limpia antes de `store()` | ✅ |
| Casting homogéneo (bool/int/datetime) | ✅ |
| Emails y formatos validados | ✅ |
| Mass assignment controlado | ✅ |
| Comparación schema periódica | ✅ |

## Cuándo Elevar a Excepción vs Ignorar
| Caso | Acción recomendada |
|------|--------------------|
| Campo requerido ausente | Lanzar excepción |
| Campo extra no usado | Ignorar silencioso (log debug) |
| Valor fuera de rango crítico | Excepción |
| Tipo convertible ("1"→int) | Convertir y continuar |

## Integración con Pruebas
Crea tests que construyan modelos con valores límite (edad -1, email inválido) y espera excepción o resultado nulo según tu política.

## Buenas Prácticas
- Mantén reglas cerca del modelo (cohesión).
- Evita validación duplicada si tu framework HTTP ya valida (no repitas regex complejas).
- Usa tipos nativos de PHP siempre que sea suficiente (bool/int casting simple).

## Roadmap Local
- Helper interno opcional para validar reglas declarativas.
- Normalizador centralizado para DateTime.

## ➡️ Próximos Pasos
- Modelar datos especiales: [Datos Avanzados](datos-avanzados.md)
- Monitorear integridad bajo carga: [Métricas](observabilidad/metricas.md)
- Congelar esquema en producción: [DDL / Freeze](ddl-freeze-migraciones.md)
