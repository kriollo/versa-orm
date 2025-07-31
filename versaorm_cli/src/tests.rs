// tests.rs - Centralización de pruebas para VersaORM Rust Core
// Ejecutar con: cargo test

use super::*;
use serde_json::json;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ========== UTILIDADES Y SEGURIDAD ==========
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

    // ========== PRUEBAS DE SEGURIDAD ==========
    #[test]
    fn test_sql_injection_prevention_basic() {
        let malicious_input = "'; DROP TABLE users; --";
        let sanitized = sanitize(malicious_input);
        assert_eq!(sanitized, "''; DROP TABLE users; --");
    }

    #[test]
    fn test_sql_injection_prevention_union_attacks() {
        let union_attack = "1' UNION SELECT password FROM admin_users WHERE '1'='1";
        let sanitized = sanitize(union_attack);
        assert_eq!(
            sanitized,
            "1'' UNION SELECT password FROM admin_users WHERE ''1''=''1"
        );
    }

    #[test]
    fn test_sql_injection_prevention_comment_attacks() {
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
        let boolean_attacks = vec![
            "' OR 1=1--",
            "' OR 'a'='a",
            "' OR true--",
            "admin' AND 1=1#",
        ];
        for attack in boolean_attacks {
            let sanitized = sanitize(attack);
            assert!(sanitized.contains("''"));
        }
    }

    #[test]
    fn test_sql_injection_prevention_stacked_queries() {
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
        let special_chars = "test\x00\n\r\t\"\\value";
        let sanitized = sanitize(special_chars);
        assert!(sanitized.contains("\\n"));
        assert!(sanitized.contains("\\r"));
        assert!(sanitized.contains("\\t"));
        assert!(sanitized.contains("\\\\"));
        assert!(sanitized.contains("\\\""));
    }

    #[test]
    fn test_identifier_validation_security() {
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
        assert!(clause.contains("username = ?"));
        assert!(clause.contains("age >= ?"));
        assert!(clause.contains("active = ?"));
        assert!(clause.contains(" AND "));
        assert_eq!(params.len(), 3);
        assert_eq!(params[0], json!("'; DROP TABLE users; --"));
        assert_eq!(params[1], json!(18));
        assert_eq!(params[2], json!(true));
    }

    #[test]
    fn test_table_column_name_security() {
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
        assert_eq!(test_row["id"], json!(null));
        assert_eq!(test_row["count"], json!(null));
        assert_eq!(test_row["active"], json!(true));
    }

    #[test]
    fn test_edge_cases_security() {
        let edge_cases = vec![
            "".to_string(),
            "\x00".to_string(),
            "''".to_string(),
            "\\".to_string(),
            "\n\r\t".to_string(),
            "🔥💻🚀".to_string(),
            "a".repeat(10000),
        ];
        for case in edge_cases {
            let sanitized = sanitize(&case);
            let sql_value = prepare_value_for_sql(&json!(case));
            assert!(sanitized.len() >= case.len());
            assert!(sql_value.starts_with("'") && sql_value.ends_with("'") || sql_value == "NULL");
        }
    }

    #[test]
    fn test_numeric_injection_attempts() {
        let numeric_attacks = vec![
            "1; DROP TABLE users",
            "1 OR 1=1",
            "1' UNION SELECT",
            "0x41414141",
        ];
        for attack in numeric_attacks {
            let value = json!(attack);
            let prepared = prepare_value_for_sql(&value);
            assert!(prepared.starts_with("'"));
            assert!(prepared.ends_with("'"));
            if prepared.contains(";") {
                assert!(!prepared.contains("';") || prepared.contains("'';"));
            }
        }
    }
}
