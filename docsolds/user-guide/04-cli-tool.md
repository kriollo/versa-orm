# Guía de la Herramienta de Línea de Comandos (CLI)

VersaORM incluye un potente binario de línea de comandos (`versaorm_cli`) que es, de hecho, el núcleo de Rust que ejecuta todas las operaciones de base de datos. Aunque normalmente interactuarás con él a través de la capa de PHP, puedes usarlo directamente para depuración, pruebas, scripting o para entender mejor cómo funciona el ORM por debajo.

## Ubicación del Binario

El binario se encuentra en el directorio `src/binary/` de la biblioteca. Hay una versión para cada sistema operativo principal:

-   **Windows:** `src/binary/versaorm_cli_windows.exe`
-   **Linux:** `src/binary/versaorm_cli_linux`
-   **macOS:** `src/binary/versaorm_cli_darwin`

Para usarlo, abre una terminal o consola y navega al directorio raíz de tu proyecto.

## ¿Cómo Funciona?

La CLI opera de una manera muy simple: recibe un único argumento, que es una **cadena JSON** que contiene toda la información necesaria para realizar una operación.

El formato del comando es:

```bash
# En Linux/macOS
./src/binary/versaorm_cli_linux '<json_payload>'

# En Windows
.\src\binary\versaorm_cli_windows.exe "<json_payload>"
```

-   `<json_payload>`: Es una cadena JSON que contiene la configuración de la base de datos, la acción a realizar y los parámetros de esa acción.

La CLI procesará la solicitud, se conectará a la base de datos, ejecutará la consulta y devolverá el resultado (o un error) como una cadena JSON a la salida estándar (`stdout`).

## Estructura del Payload JSON

El JSON de entrada siempre debe tener esta estructura:

```json
{
  "config": {
    "driver": "mysql",
    "host": "localhost",
    "port": 3306,
    "database": "versaorm_test",
    "username": "local",
    "password": "local",
    "debug": true
  },
  "action": "nombre_de_la_accion",
  "params": {
    // ... parámetros específicos de la acción
  }
}
```

### Acciones Soportadas

-   `query`: Para construir y ejecutar consultas con el Query Builder.
-   `raw`: Para ejecutar una consulta SQL directa.
-   `schema`: Para inspeccionar el esquema de la base de datos.

---

## Ejemplos de Uso Directo

Aquí tienes algunos ejemplos de cómo podrías usar la CLI directamente. Estos son excelentes para depurar por qué una consulta no funciona como esperas.

### Ejemplo 1: Consulta `SELECT` Simple

Vamos a replicar el equivalente a `$orm->table('tasks')->where('completed', '=', 1)->getAll();`.

**Payload JSON (`test.json`):**
```json
{
  "config": {
    "driver": "mysql",
    "host": "localhost",
    "database": "versaorm_test",
    "username": "local",
    "password": "local"
  },
  "action": "query",
  "params": {
    "table": "tasks",
    "method": "get",
    "where": [
      {
        "column": "completed",
        "operator": "=",
        "value": true
      }
    ]
  }
}
```

**Ejecución:**

```bash
# Pasamos el contenido del archivo como argumento
./src/binary/versaorm_cli_linux "$(cat test.json)"
```

**Salida Esperada (JSON):**
```json
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "title": "Comprar leche",
      "description": "Leche deslactosada",
      "completed": true,
      "created_at": "2024-07-29T12:30:00Z"
    }
  ],
  "metadata": {
    "execution_time_ms": 5.2,
    "item_count": 1
  }
}
```

### Ejemplo 2: Ejecutar una Consulta `RAW`

**Payload JSON:**
```json
{
  "config": {
    "driver": "mysql",
    "host": "localhost",
    "database": "versaorm_test",
    "username": "local",
    "password": "local"
  },
  "action": "raw",
  "params": {
    "query": "SELECT COUNT(*) as total FROM tasks WHERE status = ?",
    "bindings": ["pending"]
  }
}
```

### Ejemplo 3: Inspeccionar el Esquema

**Payload JSON:**
```json
{
  "config": {
    "driver": "mysql",
    "host": "localhost",
    "database": "versaorm_test",
    "username": "local",
    "password": "local"
  },
  "action": "schema",
  "params": {
    "subject": "columns",
    "table_name": "tasks"
  }
}
```

## Manejo de Errores

Si algo sale mal (p. ej., un error de sintaxis SQL, un problema de conexión), la CLI devolverá un JSON de error, que es exactamente lo que la capa de PHP captura y convierte en una `VersaORMException`.

**Ejemplo de Salida de Error:**
```json
{
  "status": "error",
  "error": {
    "code": "EXECUTION_ERROR",
    "message": "(1146) Table 'versaorm_test.taskss' doesn't exist",
    "query": "SELECT * FROM taskss",
    "bindings": [],
    "sql_state": "42S02"
  }
}
```

Usar la CLI directamente es una excelente manera de aislar problemas. Si una consulta falla aquí, el problema está en el núcleo de Rust o en tu SQL, no en la capa de PHP. Si funciona aquí pero falla en tu aplicación, el problema probablemente esté en cómo la capa de PHP está construyendo el payload JSON.
