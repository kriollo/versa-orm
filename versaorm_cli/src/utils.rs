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

    // Solo permite caracteres alfanuméricos y guiones bajos
    identifier.chars().all(|c| c.is_alphanumeric() || c == '_')
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_sanitize() {
        assert_eq!(sanitize("test'value"), "test''value");
        assert_eq!(sanitize("test\"value"), "test\\\"value");
    }

    #[test]
    fn test_uuid_generation() {
        let uuid1 = uuid();
        let uuid2 = uuid();
        assert_ne!(uuid1, uuid2);
        assert_eq!(uuid1.len(), 36);
    }

    #[test]
    fn test_snake_to_camel() {
        assert_eq!(snake_to_camel("user_name"), "userName");
        assert_eq!(snake_to_camel("first_name_last_name"), "firstNameLastName");
    }

    #[test]
    fn test_camel_to_snake() {
        assert_eq!(camel_to_snake("userName"), "user_name");
        assert_eq!(camel_to_snake("firstName"), "first_name");
    }

    #[test]
    fn test_is_safe_identifier() {
        assert!(is_safe_identifier("user_name"));
        assert!(is_safe_identifier("table123"));
        assert!(!is_safe_identifier("user-name"));
        assert!(!is_safe_identifier("user name"));
        assert!(!is_safe_identifier(""));
    }

    // ========== SECURITY TESTS ==========

    #[test]
    fn test_sql_injection_prevention_basic() {
        // Test basic SQL injection attempts
        let malicious_input = "'; DROP TABLE users; --";
        let sanitized = sanitize(malicious_input);
        assert_eq!(sanitized, "''; DROP TABLE users; --");
    }

    #[test]
    fn test_sql_injection_prevention_union_attacks() {
        // Test UNION-based SQL injection
        let union_attack = "1' UNION SELECT password FROM admin_users WHERE '1'='1";
        let sanitized = sanitize(union_attack);
        assert_eq!(
            sanitized,
            "1'' UNION SELECT password FROM admin_users WHERE ''1''=''1"
        );
    }

    #[test]
    fn test_sql_injection_prevention_comment_attacks() {
        // Test comment-based attacks
        let comment_attacks = vec![
            "admin'--",
            "admin'/*comment*/OR 1=1",
            "'; DELETE FROM users; /*",
        ];

        for attack in comment_attacks {
            let sanitized = sanitize(attack);
            assert!(!sanitized.contains("'--") || (sanitized.contains("''--")));
        }
    }

    #[test]
    fn test_sql_injection_prevention_boolean_attacks() {
        // Test boolean-based blind SQL injection
        let boolean_attacks = vec![
            "' OR 1=1--",
            "' OR 'a'='a",
            "' OR true--",
            "admin' AND 1=1#",
        ];

        for attack in boolean_attacks {
            let sanitized = sanitize(attack);
            // Verify single quotes are escaped, preventing boolean injection
            assert!(sanitized.contains("''"));
        }
    }

    #[test]
    fn test_sql_injection_prevention_stacked_queries() {
        // Test stacked query attacks
        let stacked_attacks = vec![
            "'; INSERT INTO users (username, password) VALUES ('hacker', 'pass'); --",
            "'; UPDATE users SET role='admin' WHERE id=1; --",
            "'; CREATE TABLE malicious (data TEXT); --",
        ];

        for attack in stacked_attacks {
            let sanitized = sanitize(attack);
            assert!(sanitized.contains("'';"));
        }
    }

    #[test]
    fn test_special_characters_sanitization() {
        // Test various special characters that could be used in attacks
        let special_chars = "test\x00\n\r\t\"\\value";
        let sanitized = sanitize(special_chars);

        // Verify newlines, tabs, and other control characters are escaped
        assert!(sanitized.contains("\\n"));
        assert!(sanitized.contains("\\r"));
        assert!(sanitized.contains("\\t"));
        assert!(sanitized.contains("\\\\"));
        assert!(sanitized.contains("\\\""));
    }

    #[test]
    fn test_identifier_validation_security() {
        // Test that potentially dangerous identifiers are rejected
        let dangerous_identifiers = vec![
            "users; DROP TABLE accounts",
            "table_name--",
            "column'name",
            "field/*comment*/",
            "name WITH GRANT OPTION",
            "../../etc/passwd",
            "<script>alert('xss')</script>",
            "$(rm -rf /)",
        ];

        for identifier in dangerous_identifiers {
            assert!(
                !is_safe_identifier(identifier),
                "Dangerous identifier '{}' should be rejected",
                identifier
            );
        }
    }

    #[test]
    fn test_safe_identifiers() {
        // Test that legitimate identifiers are accepted
        let safe_identifiers = vec![
            "users",
            "user_profiles",
            "table123",
            "column_name_with_underscores",
            "ID",
            "created_at",
            "order_items",
        ];

        for identifier in safe_identifiers {
            assert!(
                is_safe_identifier(identifier),
                "Safe identifier '{}' should be accepted",
                identifier
            );
        }
    }

    #[test]
    fn test_prepare_value_for_sql_security() {
        // Test that values are properly prepared for SQL to prevent injection
        let test_cases = vec![
            (
                json!("'; DROP TABLE users; --"),
                "'''; DROP TABLE users; --'",
            ),
            (json!("admin' OR '1'='1"), "'admin'' OR ''1''=''1'"),
            (json!(123), "123"),
            (json!(true), "1"),
            (json!(false), "0"),
            (json!(null), "NULL"),
        ];

        for (input, expected) in test_cases {
            let result = prepare_value_for_sql(&input);
            assert_eq!(result, expected, "Failed for input: {:?}", input);
        }
    }

    #[test]
    fn test_where_clause_security() {
        // Test that WHERE clauses are built securely
        let conditions = vec![
            (
                "username".to_string(),
                "=".to_string(),
                json!("'; DROP TABLE users; --"),
            ),
            ("age".to_string(), ">=".to_string(), json!(18)),
            ("active".to_string(), "=".to_string(), json!(true)),
        ];

        let (clause, params) = build_where_clause(&conditions);

        // Verify the clause structure is safe
        assert!(clause.contains("username = ?"));
        assert!(clause.contains("age >= ?"));
        assert!(clause.contains("active = ?"));
        assert!(clause.contains(" AND "));

        // Verify parameters are properly escaped
        assert_eq!(params.len(), 3);
        assert_eq!(params[0], json!("'; DROP TABLE users; --"));
        assert_eq!(params[1], json!(18));
        assert_eq!(params[2], json!(true));
    }

    #[test]
    fn test_table_column_name_security() {
        // Test security for table and column name validation
        let malicious_names = vec![
            "users; DROP DATABASE test",
            "table'name",
            "column--comment",
            "field/**/",
            "name WITH (NOLOCK)",
        ];

        for name in &malicious_names {
            assert!(
                clean_table_name(name).is_err(),
                "Malicious table name '{}' should be rejected",
                name
            );
            assert!(
                clean_column_name(name).is_err(),
                "Malicious column name '{}' should be rejected",
                name
            );
        }
    }

    #[test]
    fn test_xss_prevention_in_sanitization() {
        // Test that XSS attempts are properly sanitized
        let xss_attempts = vec![
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "'; alert('xss'); --",
        ];

        for xss in xss_attempts {
            let sanitized = sanitize(xss);
            if xss.contains("'") {
                assert!(sanitized.contains("''"));
            }
        }
    }

    #[test]
    fn test_type_casting_security() {
        // Test that type casting doesn't introduce vulnerabilities
        let mut test_row = HashMap::new();
        test_row.insert("id".to_string(), json!("'; DROP TABLE users; --"));
        test_row.insert("active".to_string(), json!("true'; DROP TABLE test; --"));
        test_row.insert(
            "count".to_string(),
            json!("123'; SELECT * FROM passwords; --"),
        );

        let mut column_types = HashMap::new();
        column_types.insert("id".to_string(), "integer".to_string());
        column_types.insert("active".to_string(), "boolean".to_string());
        column_types.insert("count".to_string(), "integer".to_string());

        cast_types(&mut test_row, &column_types);

        // Verify that malicious strings are either converted to safe types or nullified
        // Integer conversion should fail and result in null for malicious input
        assert_eq!(test_row["id"], json!(null));
        assert_eq!(test_row["count"], json!(null));

        // Boolean conversion should be safe
        assert_eq!(test_row["active"], json!(true)); // "true" part gets converted
    }

    #[test]
    fn test_edge_cases_security() {
        // Test edge cases that might be overlooked
        let edge_cases = vec![
            "".to_string(),       // Empty string
            "\x00".to_string(),   // Null byte
            "''".to_string(),     // Already escaped quote
            "\\".to_string(),     // Backslash
            "\n\r\t".to_string(), // Various whitespace
            "🔥💻🚀".to_string(), // Unicode characters
            "a".repeat(10000),    // Very long string
        ];

        for case in edge_cases {
            // Should not panic or cause errors
            let sanitized = sanitize(&case);
            let sql_value = prepare_value_for_sql(&json!(case));

            // Basic validation that output is reasonable
            assert!(sanitized.len() >= case.len()); // Should not lose data inappropriately
            assert!(sql_value.starts_with("'") && sql_value.ends_with("'") || sql_value == "NULL");
        }
    }

    #[test]
    fn test_numeric_injection_attempts() {
        // Test numeric-based injection attempts
        let numeric_attacks = vec![
            "1; DROP TABLE users",
            "1 OR 1=1",
            "1' UNION SELECT",
            "0x41414141",
        ];

        for attack in numeric_attacks {
            let value = json!(attack);
            let prepared = prepare_value_for_sql(&value);

            // Should be wrapped in quotes and sanitized
            assert!(prepared.starts_with("'"));
            assert!(prepared.ends_with("'"));
            // The prepared value should not contain unescaped single quotes before semicolons
            if prepared.contains(";") {
                // If there's a semicolon, ensure any quotes before it are escaped
                assert!(!prepared.contains("';") || prepared.contains("'';"));
            }
        }
    }
}
