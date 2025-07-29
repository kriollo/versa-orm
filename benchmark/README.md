# 🚀 VersaORM Performance Benchmarks

Este directorio contiene scripts para probar el rendimiento de VersaORM con diferentes cargas de trabajo.

## 📋 Scripts Disponibles

### 1. `connection_test.php` - Prueba Básica
**Propósito**: Verificar que VersaORM funciona correctamente antes de ejecutar benchmarks intensivos.

```bash
php benchmark/connection_test.php
```

**Qué hace**:
- ✅ Prueba la conexión a la base de datos
- ✅ Crea la tabla de prueba
- ✅ Ejecuta operaciones CRUD básicas
- ✅ Inserta 100 registros para prueba de rendimiento básica

**Tiempo estimado**: 5-10 segundos

### 2. `quick_test.php` - Benchmark Rápido
**Propósito**: Prueba de rendimiento con 5,000 registros para obtener métricas rápidas.

```bash
php benchmark/quick_test.php
```

**Qué mide**:
- 📝 Inserciones individuales con ORM
- 📦 Inserciones por lotes con SQL raw  
- 🔍 Consultas de lectura (COUNT, SELECT, WHERE)
- 📊 Comparación de rendimiento

**Tiempo estimado**: 30-60 segundos

### 3. `performance_test.php` - Benchmark Completo
**Propósito**: Prueba intensiva con 100,000 registros para mediciones de rendimiento detalladas.

```bash
php benchmark/performance_test.php
```

**Qué mide**:
- 📈 Rendimiento a gran escala
- 💾 Uso de memoria
- ⚡ Velocidad de inserción (records/sec)
- 📊 Estadísticas completas de la base de datos

**Tiempo estimado**: 5-20 minutos (dependiendo del hardware)

## ⚙️ Configuración

### Requisitos Previos
- PHP 7.4+
- MySQL/MariaDB ejecutándose
- VersaORM binario compilado en `src/binary/`

### Configurar Base de Datos

Edita la configuración en cada script según tu entorno:

```php
$config = [
    'host' => 'localhost',
    'username' => 'root',
    'password' => '',           // Tu password de MySQL
    'database' => 'versaorm_test', // Se crea automáticamente
    'charset' => 'utf8mb4'
];
```

## 🏃‍♂️ Cómo Ejecutar

### Paso 1: Prueba de Conectividad
```bash
cd /ruta/a/versaorm-php
php benchmark/connection_test.php
```

Si ves "🎉 TODAS LAS PRUEBAS PASARON EXITOSAMENTE!", continúa al siguiente paso.

### Paso 2: Benchmark Rápido
```bash
php benchmark/quick_test.php
```

### Paso 3: Benchmark Completo (Opcional)
```bash
php benchmark/performance_test.php
```

⚠️ **Nota**: El benchmark completo puede tomar varios minutos y usar recursos significativos.

## 📊 Interpretando los Resultados

### Métricas Clave

- **Records/sec**: Registros procesados por segundo (mayor es mejor)
- **Tiempo**: Duración total de la operación
- **Memoria**: Uso de memoria durante la operación
- **Factor de Mejora**: Cuánto más rápido es un método vs otro

### Ejemplo de Salida

```
📊 RESUMEN
========================================
ORM Individual:  12.45 s (401 records/sec)
Batch Insert:    2.31 s (2,164 records/sec)
Mejora:          5.4x más rápido con lotes

📈 ESTADÍSTICAS:
Total: 5,000 | Completadas: 1,487 (29.7%) | Pendientes: 3,513 (70.3%)
```

## 🔧 Personalización

### Cambiar Cantidad de Registros

En `quick_test.php`:
```php
$TOTAL_RECORDS = 10000; // Cambiar a la cantidad deseada
$BATCH_SIZE = 500;      // Ajustar tamaño de lote
```

### Modificar Datos de Prueba

Edita la función `generateTaskData()` para cambiar el tipo de datos generados:

```php
function generateTaskData($index) {
    return [
        'title' => 'Mi Tarea #' . $index,
        'description' => 'Descripción personalizada',
        'completed' => rand(0, 1)
    ];
}
```

## 🚨 Troubleshooting

### Error de Conexión
```
❌ ERROR: Database configuration is not set
```
**Solución**: Verifica las credenciales en `$config`

### Binario No Encontrado
```
❌ ERROR: VersaORM binary not found
```
**Solución**: Asegúrate de que el binario esté compilado en `src/binary/`

### Tabla Ya Existe
```
❌ ERROR: Table 'tasks' already exists
```
**Solución**: Los scripts limpian automáticamente las tablas. Si persiste, elimina manualmente:
```sql
DROP TABLE IF EXISTS tasks;
```

### Rendimiento Lento
- Verifica que MySQL esté optimizado
- Asegúrate de tener suficiente RAM
- Considera usar SSD en lugar de HDD
- Revisa que no haya otros procesos consumiendo recursos

## 📈 Benchmarks de Referencia

### Hardware de Referencia
- **CPU**: Intel i7-12700K
- **RAM**: 32GB DDR4
- **Storage**: NVMe SSD
- **MySQL**: 8.0

### Resultados Esperados (5,000 registros)
- **ORM Individual**: ~500-1,000 records/sec
- **Batch Insert**: ~2,000-5,000 records/sec  
- **Mejora**: 3-5x más rápido con lotes

## 💡 Tips de Optimización

1. **Usa inserciones por lotes** para grandes volúmenes de datos
2. **Configura MySQL** con `innodb_buffer_pool_size` apropiado
3. **Deshabilita autocommit** para operaciones masivas
4. **Usa índices** en columnas de búsqueda frecuente
5. **Considera el tipo de storage engine** (InnoDB vs MyISAM)

## 📞 Soporte

Si encuentras problemas:
1. Revisa la sección Troubleshooting
2. Verifica los logs de MySQL
3. Ejecuta primero `connection_test.php`
4. Reporta issues en el repositorio de GitHub
