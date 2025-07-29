# Arquitectura del Proyecto

Entender la arquitectura de VersaORM es fundamental para contribuir eficazmente al proyecto. VersaORM tiene una arquitectura híbrida única que combina una interfaz de alto nivel en PHP con un núcleo de ejecución de bajo nivel en Rust. Este diseño busca ofrecer lo mejor de ambos mundos: la facilidad de desarrollo de PHP y el rendimiento bruto de Rust.

## Diagrama de Arquitectura General

```
┌───────────────────────────┐      ┌──────────────────────────────────┐
│        Capa de PHP        │      │           Núcleo de Rust         │
│  (Interfaz de Usuario)    │      │      (Motor de Base de Datos)    │
├───────────────────────────┤      ├──────────────────────────────────┤
│                           │      │                                  │
│  - VersaORM.php (Fachada) │      │  - main.rs (Punto de entrada)    │
│  - QueryBuilder.php       │      │  - connection.rs (Gestor de Conex) │
│  - VersaModel.php         │      │  - query.rs (Constructor SQL)    │
│  - Traits/Modelos         │      │  - schema.rs (Inspector)         │
│                           │      │                                  │
└─────────────┬─────────────┘      └─────────────────▲────────────────┘
              │                                      │
              │           Comunicación vía           │
              │         Línea de Comandos (CLI)      │
              │                                      │
              ▼                                      │
┌───────────────────────────┐      ┌─────────────────┴────────────────┐
│      Payload JSON         │      │         Respuesta JSON           │
│ (Config + Acción + Params)│◄─────►│      (Datos o Error Detallado)   │
└───────────────────────────┘      └──────────────────────────────────┘
```

## Componentes Principales

### 1. La Capa de PHP (`src/`)

Esta es la capa con la que interactúan los desarrolladores que usan el ORM. Sus responsabilidades son:

-   **Proveer una API fluida y expresiva:** Clases como `QueryBuilder` y `VersaModel` están diseñadas para ser intuitivas y potentes.
-   **Construir el payload de la consulta:** Traduce las llamadas a métodos encadenados (p. ej., `->where(...)->orderBy(...)`) en una estructura de datos de PHP (un array).
-   **Gestionar la comunicación con el núcleo de Rust:** La clase `VersaORM` es la responsable de tomar el array de la consulta, combinarlo con la configuración de la BD, serializarlo a JSON y ejecutar el binario de Rust.
-   **Procesar la respuesta:** Recibe el JSON de vuelta desde Rust, lo deserializa y lo transforma en el formato de salida adecuado (un array de datos o un array de objetos `VersaModel`).
-   **Manejar errores:** Si Rust devuelve un error, la capa de PHP lo captura y lo lanza como una `VersaORMException`, añadiendo contexto útil de PHP.

**En resumen, la capa de PHP no habla con la base de datos. Habla en JSON con el núcleo de Rust.**

### 2. El Núcleo de Rust (`versaorm_cli/`)

Este es el motor de trabajo pesado del ORM. Es un binario de línea de comandos compilado e independiente. Sus responsabilidades son:

-   **Recibir y parsear el payload JSON:** Utiliza las bibliotecas `clap` y `serde` para interpretar la solicitud de PHP.
-   **Gestionar la conexión a la base de datos:** Utiliza la biblioteca `sqlx` para crear y gestionar un pool de conexiones asíncrono y seguro a la base de datos (MySQL, PostgreSQL, o SQLite).
-   **Construir y ejecutar SQL seguro:** A partir de los parámetros recibidos, construye la consulta SQL final. **Crucialmente, utiliza consultas preparadas (`prepared statements`)** para vincular los parámetros, lo que previene inyecciones SQL.
-   **Mapear tipos de datos:** Al leer los resultados de la base de datos, `sqlx` y `serde` trabajan juntos para asegurar que los tipos de datos se preserven (p. ej., un `INT` de la base de datos se convierte en un `Number` en JSON, no en un `String`).
-   **Inspeccionar el esquema:** Realiza consultas a las tablas de metadatos de la base de datos (`INFORMATION_SCHEMA`, etc.) para obtener información sobre tablas, columnas, etc.
-   **Devolver una respuesta JSON estandarizada:** Siempre devuelve un JSON, ya sea con los datos solicitados (`status: "success"`) o con información detallada del error (`status: "error"`).

**En resumen, el núcleo de Rust es el único que habla con la base de datos. Es rápido, seguro y eficiente en el manejo de memoria.**

## El Flujo de una Consulta

Para entender cómo encaja todo, veamos el ciclo de vida de una consulta simple:

1.  **Código de Usuario (PHP):**
    ```php
    $users = $orm->table('users')->where('status', '=', 'active')->findAll();
    ```

2.  **Capa PHP:**
    -   El `QueryBuilder` crea un array: `['table' => 'users', 'wheres' => [...]]`.
    -   El método `findAll()` le dice a `VersaORM.php` que el método de ejecución es `get` (para obtener todos los resultados) y que debe convertirlos en modelos.
    -   `VersaORM.php` crea el payload JSON final y ejecuta: `versaorm_cli_linux '{...json...}'`.

3.  **Núcleo Rust:**
    -   Parsea el JSON.
    -   Se conecta a la base de datos.
    -   Construye el SQL: `SELECT * FROM users WHERE status = ?`.
    -   Ejecuta la consulta con `sqlx`, pasando `'active'` como un parámetro vinculado.
    -   Recibe las filas de la base de datos.
    -   Serializa las filas a una cadena JSON, preservando los tipos.
    -   Imprime el JSON a `stdout`.

4.  **De vuelta en la Capa PHP:**
    -   `VersaORM.php` lee la cadena JSON de `stdout`.
    -   La deserializa en un array de PHP.
    -   Itera sobre el array y, para cada ítem, crea una nueva instancia de `VersaModel` (`new VersaModel('users', $this->orm)`).
    -   Devuelve el array de objetos `VersaModel` al código de usuario.

## Siguientes Pasos

Ahora que entiendes la arquitectura, el siguiente paso es aprender a configurar tu entorno para empezar a desarrollar. Dirígete a la guía de **[Configuración del Entorno de Desarrollo](02-development-setup.md)**.
