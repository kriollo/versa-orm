# Guía Técnica para Desarrolladores

Este documento detalla la arquitectura interna de VersaORM-PHP y las pautas para contribuir al proyecto.

## Arquitectura del Proyecto

- **/src**: Contiene el código fuente de PHP (VersaORM, QueryBuilder, Model).
- **/versaorm_cli**: Contiene el código fuente del núcleo de Rust, responsable de las interacciones con la base de datos.
- **/tests**: Pruebas unitarias de PHPUnit.
- **/docs**: Documentación para usuarios y desarrolladores.

## Sistema de Manejo de Errores

VersaORM incluye un sistema robusto de manejo de errores que proporciona mensajes detallados y sugerencias útiles para resolver problemas comunes.

### Características Principales

- **Validación de parámetros**: Validación estricta de parámetros con mensajes de error descriptivos.
- **Mensajes de error detallados**: Incluyen código de error, mensaje, estado SQL (cuando está disponible) y contexto.
- **Sugerencias automáticas**: Recomendaciones específicas basadas en el tipo de error.
- **Detección de referencias circulares**: Previene bucles infinitos en estructuras de datos complejas.
- **Validación por acción**: Reglas de validación específicas para cada tipo de acción (raw, schema, cache).

### Ejemplo de Manejo de Errores

```php
try {
    // Ejemplo de consulta con error
    $result = VersaORM::table('usuarios')
        ->where('nombre', '=', 'Juan')
        ->first();
} catch (\Exception $e) {
    // El mensaje de error incluirá:
    // - Código de error
    // - Mensaje descriptivo
    // - Sugerencias para resolver el problema
    // - Detalles adicionales (si están disponibles)
    error_log($e->getMessage());
    
    // También puedes acceder al código de error original
    if (strpos($e->getMessage(), 'ER_NO_SUCH_TABLE') !== false) {
        // Manejar error de tabla no encontrada
    }
}
```

### Tipos de Validaciones

1. **Validaciones de Parámetros**
   - Tipos de datos correctos
   - Longitudes máximas
   - Valores requeridos
   - Formatos específicos

2. **Validaciones de Esquema**
   - Existencia de tablas
   - Tipos de columnas
   - Restricciones de integridad

3. **Validaciones de Seguridad**
   - Inyección SQL
   - Referencias circulares
   - Tamaño máximo de consultas

### Personalización de Mensajes de Error

Puedes extender la clase `VersaORM` y sobrescribir los siguientes métodos para personalizar el manejo de errores:

```php
class MiVersaORM extends VersaORM {
    protected function buildDetailedErrorMessage(
        string $errorCode,
        string $errorMessage,
        array $errorDetails,
        ?string $sqlState,
        string $action,
        ?string $query
    ): string {
        // Implementación personalizada
    }
    
    protected function getErrorSuggestions(string $errorCode, string $errorMessage): array {
        // Añadir sugerencias personalizadas
    }
}
```

## Componentes Clave

### 1. `VersaORM.php`
Es la clase principal que actúa como fachada. Gestiona la configuración, la conexión y la invocación del binario de Rust. Expone métodos estáticos para un uso sencillo y puede ser instanciada para manejar múltiples conexiones.

### 2. `QueryBuilder.php`
Proporciona una interfaz fluida para construir consultas SQL. Cada método de esta clase corresponde a una parte de una consulta SQL (SELECT, WHERE, JOIN, etc.). Las llamadas se acumulan y se envían al núcleo de Rust para su ejecución.

### 3. `Model.php`
Implementa el patrón ActiveRecord. Utiliza `__get`, `__set` y `__call` para manejar dinámicamente los atributos y métodos del modelo, proporcionando una capa de abstracción sobre el QueryBuilder.

## El Núcleo de Rust (`versaorm_cli`)

El rendimiento de VersaORM se debe a su núcleo en Rust, que maneja directamente las conexiones a la base de datos.

- **Comunicación**: PHP invoca al binario `versaorm_cli` a través de `shell_exec()`.
- **Payload**: Los datos de la consulta (acción, parámetros, configuración) se serializan en formato JSON y se pasan como un argumento de línea de comandos.
- **Respuesta**: El binario ejecuta la consulta y devuelve los resultados (o errores) como una cadena JSON a la salida estándar, que PHP decodifica.

## Contribuir al Proyecto

### Ejecutar Pruebas
Es fundamental que todas las pruebas pasen antes de enviar un Pull Request.

```bash
# Instalar dependencias
composer install

# Ejecutar la suite de pruebas
composer test
```

### Estándares de Código
- Sigue el estándar PSR-12 para el código PHP.
- Documenta el código nuevo o modificado usando bloques de documentación PHPDoc.
- Asegúrate de que el código Rust siga las convenciones estándar y pase `cargo clippy`.

### Flujo de Pull Request
1. Haz un fork del repositorio.
2. Crea una nueva rama para tu funcionalidad (`feature/nombre-feature`) o corrección (`fix/nombre-bug`).
3. Implementa tus cambios y añade las pruebas correspondientes.
4. Asegúrate de que todas las pruebas pasen.
5. Envía un Pull Request detallando los cambios realizados.
