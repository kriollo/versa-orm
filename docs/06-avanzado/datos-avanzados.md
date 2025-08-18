# Tipos de Datos Avanzados (Prácticas)

Cómo tratar tipos menos triviales de forma portable.

## ✅ Prerrequisitos
- Conocer casting básico en modelos (ver [Tipado y Validación Avanzada](tipado-validacion-avanzado.md))
- Manejar operaciones CRUD y batch simples
- Haber revisado errores comunes ([Errores y Logging](errores-logging.md)) para tratar validaciones fallidas

> Este módulo eleva la robustez al tratar datos con formato y semántica específica.

## Booleanos
- Almacena como `TINYINT(1)` / `INTEGER` 0|1.
- Normaliza entrada:
```php
$model->active = (int)!!$valor;
```

## Fechas y Tiempos
Formato estándar recomendado: `Y-m-d H:i:s`.
```php
$model->created_at = date('Y-m-d H:i:s');
```
Conversión a objeto:
```php
$dt = DateTime::createFromFormat('Y-m-d H:i:s', $row['created_at']);
```

## JSON
Guardar estructuras flexibles:
```php
$settings = ['theme' => 'dark','lang' => 'es'];
$model->preferences = json_encode($settings, JSON_UNESCAPED_UNICODE);
```
Leer:
```php
$prefs = json_decode($model->preferences, true) ?? [];
```
Validar tamaño para evitar blobs gigantes inesperados.

## ENUM / SET
Si la base soporta ENUM, igualmente valida por código:
```php
$roles = ['admin','user','guest'];
if (!in_array($rol,$roles,true)) throw new InvalidArgumentException();
$model->role = $rol;
```

## IP / INET
Almacena como texto normalizado:
```php
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
if (filter_var($ip, FILTER_VALIDATE_IP)) {
  $log->ip = $ip;
}
```
Para búsquedas de rango, añade columna numérica opcional (IPv4 -> int).

## Cantidades Monetarias
Evita float binario:
```php
$priceDecimal = '19.99';
$model->price_cents = (int) bcmul($priceDecimal, '100');
```
Formato de salida:
```php
number_format($model->price_cents / 100, 2, '.', '');
```

## Arrays
Serializa como JSON:
```php
$model->tags = json_encode($tags);
$tags = json_decode($model->tags, true) ?? [];
```

## Texto Largo / Logs
- Usa `TEXT` / `CLOB`.
- Comprueba longitud antes de almacenar para evitar abusos.

## Checklist Datos Especiales
- [ ] Booleanos normalizados a 0/1
- [ ] Fechas en formato consistente
- [ ] JSON validado (decode OK)
- [ ] ENUM validado por lista blanca
- [ ] Monetario sin float
- [ ] Arrays serializados (JSON)
- [ ] Long text con límites

## ➡️ Próximos Pasos
- Validar reglas complejas: [Tipado y Validación Avanzada](tipado-validacion-avanzado.md)
- Controlar cambios de esquema: [DDL / Freeze](ddl-freeze-migraciones.md)
- Medir impacto de formatos: [Métricas](observabilidad/metricas.md)
