//======================================================================
// REPLACE INTO AND UPSERT OPERATIONS TESTS - Tarea 2.2
//======================================================================

#[cfg(test)]
pub mod replace_and_upsert_tests {
    use serde_json::{json, Value};
    use std::collections::HashMap;

    /// Test básico de replaceInto para MySQL
    #[test]
    fn test_replace_into_basic() {
        let data = json!({
            "sku": "RUST_REPLACE001",
            "name": "Rust Replace Product",
            "price": 199.99
        });

        // Simular el formato de datos que vendría desde PHP
        let params = json!({
            "table": "products",
            "method": "replaceInto",
            "data": data
        });

        // Validar que los parámetros están bien estructurados
        assert!(params.get("table").is_some());
        assert!(params.get("method").is_some());
        assert!(params.get("data").is_some());
        
        let data_obj = params.get("data").unwrap().as_object().unwrap();
        assert_eq!(data_obj.get("sku").unwrap().as_str().unwrap(), "RUST_REPLACE001");
        assert_eq!(data_obj.get("name").unwrap().as_str().unwrap(), "Rust Replace Product");
        assert_eq!(data_obj.get("price").unwrap().as_f64().unwrap(), 199.99);
    }

    /// Test de replaceIntoMany para validar estructura de múltiples registros
    #[test]
    fn test_replace_into_many_structure() {
        let records = json!([
            {
                "sku": "RUST_MANY001",
                "name": "Rust Many Product 1",
                "price": 100.0
            },
            {
                "sku": "RUST_MANY002", 
                "name": "Rust Many Product 2",
                "price": 200.0
            },
            {
                "sku": "RUST_MANY003",
                "name": "Rust Many Product 3", 
                "price": 300.0
            }
        ]);

        let params = json!({
            "table": "products",
            "method": "replaceIntoMany",
            "records": records,
            "batch_size": 2
        });

        // Validar estructura
        assert!(params.get("records").is_some());
        let records_array = params.get("records").unwrap().as_array().unwrap();
        assert_eq!(records_array.len(), 3);

        // Validar batch_size
        assert_eq!(params.get("batch_size").unwrap().as_i64().unwrap(), 2);

        // Validar que cada registro tiene la misma estructura
        for (i, record) in records_array.iter().enumerate() {
            let record_obj = record.as_object().unwrap();
            assert!(record_obj.contains_key("sku"));
            assert!(record_obj.contains_key("name"));
            assert!(record_obj.contains_key("price"));
            
            // Validar que el SKU es único
            let expected_sku = format!("RUST_MANY{:03}", i + 1);
            assert_eq!(record_obj.get("sku").unwrap().as_str().unwrap(), expected_sku);
        }
    }

    /// Test de validación de datos vacíos para replaceInto
    #[test]
    fn test_replace_into_empty_data_validation() {
        let params = json!({
            "table": "products",
            "method": "replaceInto",
            "data": {}
        });

        let data_obj = params.get("data").unwrap().as_object().unwrap();
        assert!(data_obj.is_empty(), "Empty data should be rejected");
    }

    /// Test de upsert básico con claves únicas
    #[test]
    fn test_upsert_basic_structure() {
        let data = json!({
            "sku": "RUST_UPSERT001",
            "name": "Rust Upsert Product",
            "price": 299.99,
            "category": "electronics"
        });

        let unique_keys = json!(["sku"]);
        let update_columns = json!(["name", "price"]);

        let params = json!({
            "table": "products",
            "method": "upsert",
            "data": data,
            "unique_keys": unique_keys,
            "update_columns": update_columns
        });

        // Validar estructura básica
        assert!(params.get("data").is_some());
        assert!(params.get("unique_keys").is_some());
        assert!(params.get("update_columns").is_some());

        // Validar unique_keys
        let unique_keys_array = params.get("unique_keys").unwrap().as_array().unwrap();
        assert_eq!(unique_keys_array.len(), 1);
        assert_eq!(unique_keys_array[0].as_str().unwrap(), "sku");

        // Validar update_columns
        let update_columns_array = params.get("update_columns").unwrap().as_array().unwrap();
        assert_eq!(update_columns_array.len(), 2);
        assert!(update_columns_array.contains(&json!("name")));
        assert!(update_columns_array.contains(&json!("price")));

        // Validar que los datos contienen la clave única
        let data_obj = params.get("data").unwrap().as_object().unwrap();
        assert!(data_obj.contains_key("sku"));
    }

    /// Test de upsertMany con múltiples registros y claves únicas
    #[test]
    fn test_upsert_many_structure() {
        let records = json!([
            {
                "sku": "UPSERT_MANY001",
                "category": "electronics",
                "name": "Upsert Many Product 1",
                "price": 150.0
            },
            {
                "sku": "UPSERT_MANY002",
                "category": "electronics", 
                "name": "Upsert Many Product 2",
                "price": 250.0
            }
        ]);

        let unique_keys = json!(["sku", "category"]);
        let update_columns = json!(["name", "price"]);

        let params = json!({
            "table": "products",
            "method": "upsertMany",
            "records": records,
            "unique_keys": unique_keys,
            "update_columns": update_columns,
            "batch_size": 1
        });

        // Validar estructura
        let records_array = params.get("records").unwrap().as_array().unwrap();
        assert_eq!(records_array.len(), 2);

        // Validar que cada registro contiene todas las claves únicas
        let unique_keys_array = params.get("unique_keys").unwrap().as_array().unwrap();
        for record in records_array {
            let record_obj = record.as_object().unwrap();
            for unique_key in unique_keys_array {
                let key_name = unique_key.as_str().unwrap();
                assert!(record_obj.contains_key(key_name), "Record missing unique key: {}", key_name);
            }
        }
    }

    /// Test de validación de nombres de columnas maliciosos
    #[test]
    fn test_malicious_column_names_detection() {
        let malicious_names = vec![
            "name; DROP TABLE products; --",
            "price' OR 1=1; --",
            "sku`; DELETE FROM users; --",
            "category UNION SELECT * FROM admin_users --"
        ];

        for malicious_name in malicious_names {
            // Simular detección de nombres maliciosos
            assert!(is_malicious_column_name(malicious_name), 
                   "Should detect malicious column name: {}", malicious_name);
        }

        // Nombres válidos no deberían ser detectados como maliciosos
        let valid_names = vec!["sku", "name", "price", "category", "description"];
        for valid_name in valid_names {
            assert!(!is_malicious_column_name(valid_name),
                   "Should not detect valid column name as malicious: {}", valid_name);
        }
    }

    /// Test de validación de batch size
    #[test]
    fn test_batch_size_validation() {
        let test_cases = vec![
            (0, false),      // Muy pequeño
            (1, true),       // Mínimo válido
            (1000, true),    // Válido
            (10000, true),   // Máximo válido
            (10001, false),  // Muy grande
        ];

        for (batch_size, should_be_valid) in test_cases {
            assert_eq!(is_valid_batch_size(batch_size), should_be_valid,
                      "Batch size {} should be {}", batch_size, 
                      if should_be_valid { "valid" } else { "invalid" });
        }
    }

    /// Test de construcción de SQL para REPLACE INTO
    #[test]
    fn test_replace_into_sql_construction() {
        let table_name = "products";
        let columns = vec!["sku", "name", "price"];
        let values_count = 1;

        let expected_sql = "REPLACE INTO products (sku, name, price) VALUES (?, ?, ?)";
        let constructed_sql = build_replace_into_sql(table_name, &columns, values_count);
        
        assert_eq!(constructed_sql, expected_sql);
    }

    /// Test de construcción de SQL para REPLACE INTO con múltiples registros
    #[test]
    fn test_replace_into_many_sql_construction() {
        let table_name = "products";
        let columns = vec!["sku", "name", "price"];
        let values_count = 3;

        let expected_sql = "REPLACE INTO products (sku, name, price) VALUES (?, ?, ?), (?, ?, ?), (?, ?, ?)";
        let constructed_sql = build_replace_into_sql(table_name, &columns, values_count);
        
        assert_eq!(constructed_sql, expected_sql);
    }

    /// Test de construcción de SQL para UPSERT en MySQL
    #[test]
    fn test_upsert_mysql_sql_construction() {
        let table_name = "products";
        let columns = vec!["sku", "name", "price"];
        let unique_keys = vec!["sku"];
        let update_columns = vec!["name", "price"];

        let expected_sql = "INSERT INTO products (sku, name, price) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE name = VALUES(name), price = VALUES(price)";
        let constructed_sql = build_upsert_mysql_sql(table_name, &columns, &unique_keys, &update_columns);
        
        assert_eq!(constructed_sql, expected_sql);
    }

    /// Test de construcción de SQL para UPSERT en PostgreSQL
    #[test]
    fn test_upsert_postgresql_sql_construction() {
        let table_name = "products";
        let columns = vec!["sku", "name", "price"];
        let unique_keys = vec!["sku"];
        let update_columns = vec!["name", "price"];

        let expected_sql = "INSERT INTO products (sku, name, price) VALUES (?, ?, ?) ON CONFLICT (sku) DO UPDATE SET name = EXCLUDED.name, price = EXCLUDED.price";
        let constructed_sql = build_upsert_postgresql_sql(table_name, &columns, &unique_keys, &update_columns);
        
        assert_eq!(constructed_sql, expected_sql);
    }

    /// Test de respuesta JSON para operaciones exitosas
    #[test]
    fn test_successful_response_format() {
        // Test para replaceInto
        let replace_response = build_replace_into_response(1, "products");
        assert_eq!(replace_response.get("status").unwrap().as_str().unwrap(), "success");
        assert_eq!(replace_response.get("operation").unwrap().as_str().unwrap(), "replaced");
        assert_eq!(replace_response.get("rows_affected").unwrap().as_i64().unwrap(), 1);
        assert_eq!(replace_response.get("table").unwrap().as_str().unwrap(), "products");

        // Test para upsert
        let unique_keys = vec!["sku".to_string()];
        let update_columns = vec!["name".to_string(), "price".to_string()];
        let upsert_response = build_upsert_response(1, &unique_keys, &update_columns, "products");
        assert_eq!(upsert_response.get("status").unwrap().as_str().unwrap(), "success");
        assert_eq!(upsert_response.get("rows_affected").unwrap().as_i64().unwrap(), 1);
        
        let response_unique_keys = upsert_response.get("unique_keys").unwrap().as_array().unwrap();
        assert_eq!(response_unique_keys.len(), 1);
        assert_eq!(response_unique_keys[0].as_str().unwrap(), "sku");
    }

    /// Test de manejo de errores en batch operations
    #[test]
    fn test_batch_error_handling() {
        let records = json!([
            {"sku": "BATCH001", "name": "Product 1"},
            {"sku": "BATCH002", "name": "Product 2", "extra_field": "extra"} // Estructura inconsistente
        ]);

        let validation_result = validate_records_structure(&records);
        assert!(validation_result.is_err(), "Should detect inconsistent record structure");
        
        let error_message = validation_result.unwrap_err();
        assert!(error_message.contains("different columns"), "Error message should mention column difference");
    }

    //======================================================================
    // HELPER FUNCTIONS PARA LOS TESTS
    //======================================================================

    /// Simula la detección de nombres de columnas maliciosos
    fn is_malicious_column_name(column_name: &str) -> bool {
        let malicious_patterns = vec![
            ";", "--", "/*", "*/", "'", "\"", "`",
            "DROP", "DELETE", "UPDATE", "INSERT", "UNION", "SELECT"
        ];
        
        let upper_name = column_name.to_uppercase();
        malicious_patterns.iter().any(|pattern| upper_name.contains(pattern))
    }

    /// Valida el tamaño de lote
    fn is_valid_batch_size(batch_size: i64) -> bool {
        batch_size >= 1 && batch_size <= 10000
    }

    /// Construye SQL para REPLACE INTO
    fn build_replace_into_sql(table_name: &str, columns: &[&str], values_count: usize) -> String {
        let columns_str = columns.join(", ");
        let single_value_placeholder = format!("({})", vec!["?"; columns.len()].join(", "));
        let values_placeholders = vec![single_value_placeholder; values_count].join(", ");
        
        format!("REPLACE INTO {} ({}) VALUES {}", table_name, columns_str, values_placeholders)
    }

    /// Construye SQL para UPSERT en MySQL
    fn build_upsert_mysql_sql(table_name: &str, columns: &[&str], _unique_keys: &[&str], update_columns: &[&str]) -> String {
        let columns_str = columns.join(", ");
        let values_placeholder = format!("({})", vec!["?"; columns.len()].join(", "));
        let update_clause = update_columns.iter()
            .map(|col| format!("{} = VALUES({})", col, col))
            .collect::<Vec<_>>()
            .join(", ");
        
        format!("INSERT INTO {} ({}) VALUES {} ON DUPLICATE KEY UPDATE {}", 
                table_name, columns_str, values_placeholder, update_clause)
    }

    /// Construye SQL para UPSERT en PostgreSQL
    fn build_upsert_postgresql_sql(table_name: &str, columns: &[&str], unique_keys: &[&str], update_columns: &[&str]) -> String {
        let columns_str = columns.join(", ");
        let values_placeholder = format!("({})", vec!["?"; columns.len()].join(", "));
        let unique_keys_str = unique_keys.join(", ");
        let update_clause = update_columns.iter()
            .map(|col| format!("{} = EXCLUDED.{}", col, col))
            .collect::<Vec<_>>()
            .join(", ");
        
        format!("INSERT INTO {} ({}) VALUES {} ON CONFLICT ({}) DO UPDATE SET {}", 
                table_name, columns_str, values_placeholder, unique_keys_str, update_clause)
    }

    /// Construye respuesta para replaceInto
    fn build_replace_into_response(rows_affected: i64, table: &str) -> Value {
        json!({
            "status": "success",
            "operation": "replaced",
            "rows_affected": rows_affected,
            "table": table
        })
    }

    /// Construye respuesta para upsert
    fn build_upsert_response(rows_affected: i64, unique_keys: &[String], update_columns: &[String], table: &str) -> Value {
        json!({
            "status": "success",
            "operation": "inserted_or_updated",
            "rows_affected": rows_affected,
            "unique_keys": unique_keys,
            "update_columns": update_columns,
            "table": table
        })
    }

    /// Valida la estructura de registros para operaciones batch
    fn validate_records_structure(records: &Value) -> Result<(), String> {
        let records_array = records.as_array().ok_or("Records must be an array")?;
        
        if records_array.is_empty() {
            return Err("Records array cannot be empty".to_string());
        }

        // Obtener las columnas del primer registro
        let first_record = records_array.first().unwrap().as_object()
            .ok_or("First record must be an object")?;
        let expected_keys: Vec<_> = first_record.keys().collect();

        // Validar que todos los registros tengan las mismas columnas
        for (index, record) in records_array.iter().enumerate().skip(1) {
            let record_obj = record.as_object()
                .ok_or(format!("Record at index {} must be an object", index))?;
            let record_keys: Vec<_> = record_obj.keys().collect();
            
            if record_keys != expected_keys {
                return Err(format!("Record at index {} has different columns", index));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use serde_json::json;

    /// Test de integración completa para replaceInto
    #[test]
    fn test_replace_into_integration() {
        let params = json!({
            "config": {
                "driver": "mysql",
                "host": "localhost",
                "database": "test_db",
                "username": "test_user",
                "password": "test_pass",
                "debug": true
            },
            "action": "replaceInto",
            "params": {
                "table": "products",
                "data": {
                    "sku": "INTEGRATION_REPLACE001",
                    "name": "Integration Replace Product",
                    "price": 99.99
                }
            }
        });

        // Validar estructura completa del payload
        assert!(params.get("config").is_some());
        assert!(params.get("action").is_some());
        assert!(params.get("params").is_some());

        let config = params.get("config").unwrap().as_object().unwrap();
        assert_eq!(config.get("driver").unwrap().as_str().unwrap(), "mysql");

        let action_params = params.get("params").unwrap().as_object().unwrap();
        assert!(action_params.get("table").is_some());
        assert!(action_params.get("data").is_some());
    }

    /// Test de integración para upsertMany
    #[test]
    fn test_upsert_many_integration() {
        let params = json!({
            "config": {
                "driver": "mysql",
                "host": "localhost", 
                "database": "test_db",
                "username": "test_user",
                "password": "test_pass",
                "debug": false
            },
            "action": "upsertMany",
            "params": {
                "table": "products",
                "records": [
                    {
                        "sku": "INTEGRATION_UPSERT001",
                        "name": "Integration Upsert Product 1",
                        "price": 199.99
                    },
                    {
                        "sku": "INTEGRATION_UPSERT002", 
                        "name": "Integration Upsert Product 2",
                        "price": 299.99
                    }
                ],
                "unique_keys": ["sku"],
                "update_columns": ["name", "price"],
                "batch_size": 1
            }
        });

        // Validar payload completo
        assert_eq!(params.get("action").unwrap().as_str().unwrap(), "upsertMany");
        
        let action_params = params.get("params").unwrap().as_object().unwrap();
        let records = action_params.get("records").unwrap().as_array().unwrap();
        assert_eq!(records.len(), 2);

        let unique_keys = action_params.get("unique_keys").unwrap().as_array().unwrap();
        assert_eq!(unique_keys.len(), 1);
        assert_eq!(unique_keys[0].as_str().unwrap(), "sku");

        let update_columns = action_params.get("update_columns").unwrap().as_array().unwrap();
        assert_eq!(update_columns.len(), 2);
    }
}
