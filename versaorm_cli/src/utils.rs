use chrono::Utc;
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

    // Permite caracteres alfanuméricos, guiones bajos y puntos (para columnas calificadas como table.column)
    identifier.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.')
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

            // Verificar la parte de la función
            return is_valid_sql_function(function_part, &allowed_functions);
        }
    } else {
        // Sin alias, verificar si es una función directa
        return is_valid_sql_function(column_expr, &allowed_functions);
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

// mod tests { ... } // Todos los tests han sido movidos a tests.rs
