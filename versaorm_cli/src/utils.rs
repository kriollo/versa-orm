use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

/// Sanitiza valores de entrada para prevenir inyección SQL
#[allow(dead_code)]
pub fn sanitize(input: &str) -> String {
    input
        .replace("\\", "\\\\")
        .replace("'", "''")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
}

/// Aplica casting automático a los valores de una fila basándose en el tipo de dato
#[allow(dead_code)]
pub fn cast_types(row: &mut HashMap<String, Value>, column_types: &HashMap<String, String>) {
    for (column, value) in row.iter_mut() {
        if let Some(data_type) = column_types.get(column) {
            *value = cast_value_by_type(value.clone(), data_type);
        }
    }
}

/// Convierte un valor a su tipo correcto basándose en el tipo de dato SQL
#[allow(dead_code)]
pub fn cast_value_by_type(value: Value, data_type: &str) -> Value {
    match value {
        Value::String(s) => {
            let s_lower = s.to_lowercase();
            match data_type.to_lowercase().as_str() {
                "int" | "integer" | "bigint" | "smallint" | "tinyint" => {
                    s.parse::<i64>().map(Value::from).unwrap_or(Value::Null)
                }
                "float" | "double" | "decimal" | "numeric" | "real" => s
                    .parse::<f64>()
                    .map(|f| {
                        Value::Number(
                            serde_json::Number::from_f64(f).unwrap_or(serde_json::Number::from(0)),
                        )
                    })
                    .unwrap_or(Value::Null),
                "boolean" | "bool" | "bit" => match s_lower.as_str() {
                    "true" | "1" | "yes" | "on" => Value::Bool(true),
                    "false" | "0" | "no" | "off" => Value::Bool(false),
                    _ => Value::Bool(!s.is_empty()),
                },
                "date" | "datetime" | "timestamp" | "time" => {
                    if s.is_empty() {
                        Value::Null
                    } else {
                        Value::String(s)
                    }
                }
                // Tipos avanzados
                "json" | "jsonb" => cast_json_type(s),
                "uuid" => cast_uuid_type(s),
                "inet" | "cidr" => cast_inet_type(s),
                "enum" => cast_enum_type(s),
                "set" => cast_set_type(s),
                "blob" | "varbinary" | "binary" => cast_binary_type(s),
                // Arrays PostgreSQL
                t if t.ends_with("[]") => cast_postgresql_array(s, t),
                _ => Value::String(s),
            }
        }
        Value::Number(n) => match data_type.to_lowercase().as_str() {
            "boolean" | "bool" | "bit" => {
                if let Some(i) = n.as_i64() {
                    Value::Bool(i != 0)
                } else if let Some(f) = n.as_f64() {
                    Value::Bool(f != 0.0)
                } else {
                    Value::Bool(false)
                }
            }
            _ => Value::Number(n),
        },
        _ => value,
    }
}

/// Genera un UUID v4
#[allow(dead_code)]
pub fn uuid() -> String {
    Uuid::new_v4().to_string()
}

/// Retorna la fecha y hora actual en formato ISO 8601
#[allow(dead_code)]
pub fn now() -> String {
    Utc::now().to_rfc3339()
}

/// Convierte un valor de PHP/JSON a un tipo compatible con SQL
#[allow(dead_code)]
pub fn prepare_value_for_sql(value: &Value) -> String {
    match value {
        Value::String(s) => format!("'{}'", sanitize(s)),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => {
            if *b {
                "1".to_string()
            } else {
                "0".to_string()
            }
        }
        Value::Null => "NULL".to_string(),
        _ => format!("'{}'", sanitize(&value.to_string())),
    }
}

/// Valida si un nombre de tabla o columna es seguro
#[allow(dead_code)]
pub fn is_safe_identifier(identifier: &str) -> bool {
    if identifier.is_empty() {
        return false;
    }

    // Casos especiales para patrones SQL válidos
    // Permitir table.* (todas las columnas de una tabla específica)
    if let Some(table_part) = identifier.strip_suffix(".*") {
        return table_part.chars().all(|c| c.is_alphanumeric() || c == '_');
    }

    // Permitir * simple (todas las columnas)
    if identifier == "*" {
        return true;
    }

    // Permite caracteres alfanuméricos, guiones bajos y puntos (para columnas calificadas como table.column)
    identifier
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
}

/// Convierte snake_case a camelCase
#[allow(dead_code)]
pub fn snake_to_camel(snake_str: &str) -> String {
    let mut camel = String::new();
    let mut capitalize_next = false;

    for c in snake_str.chars() {
        if c == '_' {
            capitalize_next = true;
        } else if capitalize_next {
            camel.push(c.to_uppercase().next().unwrap_or(c));
            capitalize_next = false;
        } else {
            camel.push(c);
        }
    }

    camel
}

/// Convierte camelCase a snake_case
#[allow(dead_code)]
pub fn camel_to_snake(camel_str: &str) -> String {
    let mut snake = String::new();

    for (i, c) in camel_str.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            snake.push('_');
        }
        snake.push(c.to_lowercase().next().unwrap_or(c));
    }

    snake
}

/// Limpia y valida un nombre de tabla
#[allow(dead_code)]
pub fn clean_table_name(table_name: &str) -> Result<String, String> {
    // Manejar aliases de tabla (ej: "users as u", "tasks as t")
    if table_name.to_lowercase().contains(" as ") {
        let parts: Vec<&str> = table_name.split_whitespace().collect();
        if parts.len() == 3 && parts[1].to_lowercase() == "as" {
            let table = parts[0];
            let alias = parts[2];
            
            // Validar tanto la tabla como el alias
            if is_safe_identifier(table) && is_safe_identifier(alias) {
                return Ok(table_name.to_string());
            } else {
                return Err(format!("Invalid table or alias name: {}", table_name));
            }
        } else {
            return Err(format!("Invalid table alias syntax: {}", table_name));
        }
    }
    
    // Validación normal para nombres sin alias
    if !is_safe_identifier(table_name) {
        return Err(format!("Invalid table name: {}", table_name));
    }
    Ok(table_name.to_string())
}

/// Limpia y valida un nombre de columna
#[allow(dead_code)]
pub fn clean_column_name(column_name: &str) -> Result<String, String> {
    // Permitir funciones SQL como COUNT(*), SUM(), etc. y alias
    if is_sql_function_or_alias(column_name) || is_safe_identifier(column_name) {
        Ok(column_name.to_string())
    } else {
        Err(format!("Invalid column name: {}", column_name))
    }
}

/// Verifica si una cadena es una función SQL válida o alias
#[allow(dead_code)]
pub fn is_sql_function_or_alias(column_expr: &str) -> bool {
    // Permite patrones como:
    // - COUNT(*)
    // - COUNT(*) as count
    // - SUM(column_name)
    // - AVG(price) as average_price
    // - column_name as alias
    // - table.* (todas las columnas de una tabla)
    // - t.* as table_columns

    // Lista de funciones SQL permitidas
    let allowed_functions = [
        "COUNT", "SUM", "AVG", "MAX", "MIN", "DISTINCT", "UPPER", "LOWER", "LENGTH", "CONCAT",
    ];

    let upper_expr = column_expr.to_uppercase();

    // Verificar si contiene "AS" para alias
    if upper_expr.contains(" AS ") {
        let parts: Vec<&str> = column_expr.split(" as ").collect();
        if parts.len() == 2 {
            let function_part = parts[0].trim();
            let alias_part = parts[1].trim();

            // Verificar que el alias sea un identificador seguro
            if !is_safe_identifier(alias_part) {
                return false;
            }

            // Verificar la parte de la función/columna
            return is_valid_sql_function(function_part, &allowed_functions)
                || is_safe_identifier(function_part);
        }
    } else {
        // Sin alias, verificar si es una función directa o identificador seguro
        return is_valid_sql_function(column_expr, &allowed_functions)
            || is_safe_identifier(column_expr);
    }

    false
}

/// Verifica si una expresión es una función SQL válida
#[allow(dead_code)]
fn is_valid_sql_function(expr: &str, allowed_functions: &[&str]) -> bool {
    let upper_expr = expr.to_uppercase();

    for func in allowed_functions {
        if upper_expr.starts_with(&format!("{}(", func)) && upper_expr.ends_with(")") {
            // Extraer el contenido entre paréntesis
            let content = &expr[func.len() + 1..expr.len() - 1];

            // Para COUNT(*), SUM(*), etc., permitir asterisco
            if content == "*" {
                return true;
            }

            // Para otras funciones, verificar que el contenido sea un identificador seguro
            if is_safe_identifier(content.trim()) {
                return true;
            }
        }
    }

    false
}

/// Construye una cláusula WHERE segura
#[allow(dead_code)]
pub fn build_where_clause(conditions: &[(String, String, Value)]) -> (String, Vec<Value>) {
    if conditions.is_empty() {
        return (String::new(), Vec::new());
    }

    let mut clause = String::from(" WHERE ");
    let mut params = Vec::new();
    let mut parts = Vec::new();

    for (column, operator, value) in conditions {
        if let Ok(clean_column) = clean_column_name(column) {
            parts.push(format!("{} {} ?", clean_column, operator));
            params.push(value.clone());
        }
    }

    clause.push_str(&parts.join(" AND "));
    (clause, params)
}

// ========== FUNCIONES PARA TIPOS AVANZADOS ==========

/// Convierte un string JSON a un Value JSON parseado
#[allow(dead_code)]
pub fn cast_json_type(s: String) -> Value {
    match serde_json::from_str(&s) {
        Ok(json_value) => json_value,
        Err(_) => Value::String(s), // Si no se puede parsear, devolver como string
    }
}

/// Valida y convierte un UUID
#[allow(dead_code)]
pub fn cast_uuid_type(s: String) -> Value {
    match Uuid::parse_str(&s) {
        Ok(_) => Value::String(s), // UUID válido
        Err(_) => Value::Null,     // UUID inválido
    }
}

/// Valida direcciones IP (INET/CIDR)
#[allow(dead_code)]
pub fn cast_inet_type(s: String) -> Value {
    // Regex básica para validar IPv4 y IPv6
    let ipv4_regex = Regex::new(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/[0-9]{1,2})?$").unwrap();
    let ipv6_regex =
        Regex::new(r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?:/[0-9]{1,3})?$").unwrap();

    if ipv4_regex.is_match(&s) || ipv6_regex.is_match(&s) {
        Value::String(s)
    } else {
        Value::Null
    }
}

/// Maneja tipos ENUM (simplemente valida que sea string)
#[allow(dead_code)]
pub fn cast_enum_type(s: String) -> Value {
    if s.is_empty() {
        Value::Null
    } else {
        Value::String(s)
    }
}

/// Maneja tipos SET de MySQL (convierte a array)
#[allow(dead_code)]
pub fn cast_set_type(s: String) -> Value {
    if s.is_empty() {
        Value::Array(vec![])
    } else {
        let values: Vec<Value> = s
            .split(',')
            .map(|v| Value::String(v.trim().to_string()))
            .collect();
        Value::Array(values)
    }
}

/// Maneja tipos binarios (BLOB, VARBINARY) - convierte a base64
#[allow(dead_code)]
pub fn cast_binary_type(s: String) -> Value {
    // Si ya parece ser base64, devolverlo como está
    if is_base64(&s) {
        Value::String(s)
    } else {
        // Si es texto, convertir a base64
        let encoded = general_purpose::STANDARD.encode(s.as_bytes());
        Value::String(encoded)
    }
}

/// Maneja arrays de PostgreSQL
#[allow(dead_code)]
pub fn cast_postgresql_array(s: String, data_type: &str) -> Value {
    // Extraer el tipo base del array (e.g., "integer[]" -> "integer")
    let base_type = data_type.trim_end_matches("[]");

    // Los arrays de PostgreSQL vienen en formato {val1,val2,val3}
    if s.starts_with('{') && s.ends_with('}') {
        let content = &s[1..s.len() - 1]; // Quitar { }

        if content.is_empty() {
            return Value::Array(vec![]);
        }

        let values: Vec<Value> = content
            .split(',')
            .map(|v| {
                let trimmed = v.trim();
                // Quitar comillas si las tiene
                let cleaned = if trimmed.starts_with('"') && trimmed.ends_with('"') {
                    &trimmed[1..trimmed.len() - 1]
                } else {
                    trimmed
                };

                // Aplicar casting según el tipo base
                cast_value_by_type(Value::String(cleaned.to_string()), base_type)
            })
            .collect();

        Value::Array(values)
    } else {
        // Si no es un array válido, devolver como string
        Value::String(s)
    }
}

/// Verifica si un string es base64 válido
#[allow(dead_code)]
fn is_base64(s: &str) -> bool {
    // Regex básica para base64
    let base64_regex = Regex::new(r"^[A-Za-z0-9+/]*={0,2}$").unwrap();
    base64_regex.is_match(s) && s.len() % 4 == 0
}

/// Estructura para configuración de mapeos personalizados
#[derive(Debug, Clone)]
pub struct TypeMapping {
    pub from_type: String,
    pub to_type: String,
    pub custom_cast: Option<String>,
}

/// Carga configuración de mapeos desde JSON
#[allow(dead_code)]
pub fn load_type_mappings(json_config: &str) -> Result<Vec<TypeMapping>, String> {
    match serde_json::from_str::<Value>(json_config) {
        Ok(config) => {
            let mut mappings = Vec::new();

            if let Some(mappings_array) = config.get("type_mappings").and_then(|v| v.as_array()) {
                for mapping in mappings_array {
                    if let (Some(from), Some(to)) = (
                        mapping.get("from").and_then(|v| v.as_str()),
                        mapping.get("to").and_then(|v| v.as_str()),
                    ) {
                        let custom_cast = mapping
                            .get("custom_cast")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());

                        mappings.push(TypeMapping {
                            from_type: from.to_string(),
                            to_type: to.to_string(),
                            custom_cast,
                        });
                    }
                }
            }

            Ok(mappings)
        }
        Err(e) => Err(format!("Error parsing type mappings config: {}", e)),
    }
}

/// Aplica mapeos personalizados a un tipo
#[allow(dead_code)]
pub fn apply_custom_mapping(value: Value, original_type: &str, mappings: &[TypeMapping]) -> Value {
    for mapping in mappings {
        if mapping.from_type.to_lowercase() == original_type.to_lowercase() {
            // Si hay casting personalizado, aplicarlo
            if let Some(_custom_cast) = &mapping.custom_cast {
                // Aquí se podría implementar lógica de casting personalizada
                // Por ahora, aplicamos el casting estándar al tipo destino
                return cast_value_by_type(value, &mapping.to_type);
            } else {
                // Aplicar casting estándar al tipo destino
                return cast_value_by_type(value, &mapping.to_type);
            }
        }
    }

    // Si no hay mapeo personalizado, devolver el valor original
    value
}

/// Valida que un valor sea compatible con el tipo de datos esperado
#[allow(dead_code)]
pub fn validate_type_compatibility(value: &Value, expected_type: &str) -> Result<(), String> {
    match expected_type.to_lowercase().as_str() {
        "int" | "integer" | "bigint" | "smallint" | "tinyint" => {
            if !value.is_number() && !value.is_null() {
                return Err(format!("Expected integer type, got: {:?}", value));
            }
        }
        "float" | "double" | "decimal" | "numeric" | "real" => {
            if !value.is_number() && !value.is_null() {
                return Err(format!("Expected numeric type, got: {:?}", value));
            }
        }
        "boolean" | "bool" | "bit" => {
            if !value.is_boolean() && !value.is_null() {
                return Err(format!("Expected boolean type, got: {:?}", value));
            }
        }
        "string" | "varchar" | "text" | "char" => {
            if !value.is_string() && !value.is_null() {
                return Err(format!("Expected string type, got: {:?}", value));
            }
        }
        "json" | "jsonb" => {
            // JSON puede ser cualquier tipo válido de JSON
            if value.is_null() {
                return Ok(());
            }
            // Si no es null, debe ser un JSON válido (object, array, string, number, boolean)
        }
        "uuid" => {
            if let Some(s) = value.as_str() {
                if Uuid::parse_str(s).is_err() {
                    return Err(format!("Invalid UUID format: {}", s));
                }
            } else if !value.is_null() {
                return Err(format!("Expected UUID string, got: {:?}", value));
            }
        }
        _ => {
            // Para tipos no reconocidos, permitir cualquier valor
        }
    }

    Ok(())
}

/// Convierte un valor de fila a JSON (implementación simplificada)
pub fn simple_value_placeholder() -> serde_json::Value {
    serde_json::Value::String("data".to_string())
}

// mod tests { ... } // Todos los tests han sido movidos a tests.rs
