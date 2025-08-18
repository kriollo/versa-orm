# Arquitectura y Flujo Interno (VersaORM-PHP PDO)

Visión práctica de cómo las llamadas de alto nivel se traducen en SQL ejecutado vía PDO.

## ✅ Prerrequisitos
- Haber recorrido [CRUD Básico](../03-basico/crud-basico.md)
- Conocer el [Query Builder](../04-query-builder/README.md)
- Entender fundamentos de batch ([Operaciones Batch Avanzadas](batch-operaciones-avanzado.md))

> Llegaste aquí: ahora puedes alinear mentalmente cada llamada del ORM con su SQL resultante y decidir dónde optimizar.

## Capas Principales
```
Tu Código (Modelos / QueryBuilder)
        ↓
VersaModel / QueryBuilder
        ↓
VersaORM (coordinador)
        ↓
PdoEngine (construcción + ejecución SQL)
        ↓
PDO (driver nativo)
        ↓
Base de Datos
```

## Flujo: Insertar un Modelo
1. `VersaModel::dispense('users')` crea objeto con metadatos de tabla.
2. Asignas propiedades (`$user->name = 'Ana';`).
3. `store()`:
   - Determina si es INSERT o UPDATE según tenga PK.
   - Normaliza valores (casting simple, fechas, booleanos).
   - Llama a `VersaORM->insert()` (interno) / método equivalente.
4. `PdoEngine` construye SQL parametrizado y array de bindings.
5. Ejecuta `PDOStatement->execute()`.
6. Recupera última ID (si aplica) y se asigna al modelo.
7. Devuelve la ID (o null si era update / sin PK auto).
**SQL Equivalente típico (INSERT):**
```sql
INSERT INTO users (name) VALUES (?);
-- Recuperación de ID autoincrement (driver) p.ej. SELECT LAST_INSERT_ID(); (MySQL)
```
**SQL Equivalente UPDATE:**
```sql
UPDATE users SET name = ? WHERE id = ?;
```

## Flujo: Query Builder `where()->get()`
1. `table('users')` inicia estructura con nombre de tabla.
2. Cada `where()` añade un fragmento a una lista de condiciones + binding.
3. `get()` ensambla: `SELECT * FROM users WHERE ... ORDER BY ... LIMIT ...`.
4. `PdoEngine` prepara y ejecuta.
5. Se obtienen filas como arrays asociativos.
6. (Opcional) Se hidratan modelos (`toModels()` / métodos equivalentes) si se solicita.
**SQL Equivalente:**
```sql
SELECT * FROM users WHERE <condiciones> ORDER BY <criterio> LIMIT <n>;
```

## Construcción de SQL Segura
- Siempre placeholders `?` para valores.
- Lista blanca de operadores (`=`, `<`, `>`, `IN`, `LIKE`, etc.).
- Columnas y tablas no se interpolan desde entrada directa sin validar.

## Batch Optimizado (`storeAll`)
1. Detecta condiciones: todos nuevos + misma tabla.
2. Recolecta columnas unión de todas las filas.
3. Genera `INSERT INTO tabla (c1,c2,...) VALUES (...),(...)` con placeholders.
4. Ejecuta una sola vez.
5. Infiero IDs si el driver lo permite y las asigna a cada modelo.
**SQL Equivalente (3 inserciones):**
```sql
INSERT INTO users (name) VALUES (?), (?), (?);
```

## Caché (Lectura)
- Ciertas operaciones (`count()`, `exists()`, lecturas simples) consultan caché interna.
- Cache miss: ejecuta SQL, almacena resultado.
- Cache hit: evita roundtrip y no incrementa contador `queries`.
- Operaciones de escritura pueden invalidar claves relacionadas (en evolución).
**SQL involucrado en operaciones cacheables:**
```sql
SELECT COUNT(*) AS aggregate FROM users;            -- count()
SELECT 1 FROM users WHERE email = ? LIMIT 1;        -- exists()
SELECT * FROM users WHERE id = ? LIMIT 1;           -- lectura simple
```

## Métricas
- Hooks ligeros antes y después de ejecutar SQL miden duración y actualizan contadores.

## Freeze Mode (Resumen)
- Bandera global que bloquea DDL (ALTER / DROP / CREATE) cuando está activa.
- Verifica patrones en la sentencia antes de ejecutar.
- Lanza `VersaORMException` si coincide.

## Conversión de Tipos (Casting Básico)
- Boolean: normaliza a `0/1` al escribir, `true/false` al leer.
- Date/DateTime: mantiene formato estándar `Y-m-d H:i:s`.
- JSON (texto): codifica/decodifica según métodos utilitarios (si se aplican en modelos personalizados).
**SQL Ejemplo multi-tipo:**
```sql
INSERT INTO events (active, created_at, payload) VALUES (1, '2025-08-18 10:12:00', '{"k":"v"}');
```

## Manejo de Errores
- Excepciones PDO se transforman / encapsulan en `VersaORMException`.
- Mensajes se mantienen útiles para diagnóstico pero se recomienda no mostrarlos crudos al usuario final.

## Puntos de Extensión (Actual)
| Punto | Descripción | Cómo aprovechar |
|-------|-------------|-----------------|
| Model subclass | Lógica de dominio/casting adicional | Extiende `BaseModel` ejemplo |
| Métodos relación | Definir `tasksArray()` etc. | Encapsula join/lazy logic |
| Envoltorio de ejecución | Función helper `withOrm()` | Añade retry / logging |
| Caché externa | Rodear llamadas `get()` | Inyecta lógica de capa superior |

## Patrón de Uso Recomendado
```php
$orm = new VersaORM($config);
VersaModel::setORM($orm);

// Carga
$user = VersaModel::load('users', 10);

// Crear
$new = VersaModel::dispense('users');
$new->name = 'Alice';
$id = $new->store();

// Batch
$list = [];
foreach (['A','B','C'] as $n) {
  $u = VersaModel::dispense('users');
  $u->name = $n;
  $list[] = $u;
}
$ids = VersaModel::storeAll($list);

// Query Builder
$active = $orm->table('users')->where('active','=',1)->orderBy('id','desc')->limit(10)->get();
```
**SQL Equivalente de las operaciones anteriores:**
```sql
SELECT * FROM users WHERE id = 10 LIMIT 1;                 -- load()
INSERT INTO users (name) VALUES ('Alice');                 -- store() nuevo
INSERT INTO users (name) VALUES ('A'),('B'),('C');         -- storeAll() batch
SELECT * FROM users WHERE active = 1 ORDER BY id DESC LIMIT 10; -- query builder
```

## Diagnóstico Rápido
| Síntoma | Posible causa | Verifica |
|---------|---------------|----------|
| Muchas queries repetidas | N+1 en relaciones | Métricas `queries` + revisar patrones de acceso |
| IDs nulos tras batch | Inferencia no soportada | Usa inserciones individuales para caso crítico |
| Violación de integridad | Datos duplicados / FK | Log SQL y revisar constraints |
| Rendimiento bajo | Falta de índices / no caché | Plan de consulta DB + métricas latencia |

## Checklist Arquitectura
- [ ] Usas `VersaModel::setORM` una sola vez
- [ ] Centralizas configuración de conexión
- [ ] Evitas SQL crudo salvo necesidad real
- [ ] Agrupas inserciones masivas con `storeAll` / `insertMany`
- [ ] Monitoreas métricas en entornos de test / staging

## ➡️ Próximos Pasos
- Optimizar relaciones: [Lazy y N+1](lazy-n+1.md)
- Afinar caché: [Caché Interna](cache-interna.md)
- Endurecer datos: [Tipado y Validación Avanzada](tipado-validacion-avanzado.md)
