use super::*;
use crate::schema::SchemaInspector;
use serde_json::json;

#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn test_validation_schema_retrieval() {
        let schema_inspector = SchemaInspector::new("test_db");
        let table_name = "users";

        // Simular esquema de validación
        let fake_validation_schema = json!({
            "name": {
                "is_required": true,
                "is_nullable": false,
                "max_length": 255,
                "data_type": "varchar",
                "validation_rules": ["required"]
            },
            "email": {
                "is_required": true,
                "is_nullable": false,
                "max_length": 255,
                "data_type": "varchar",
                "validation_rules": ["required", "email"]
            },
            "age": {
                "is_required": false,
                "is_nullable": true,
                "data_type": "int"
            }
        });

        // Recuperar esquema (ficticio para este test)
        let result = schema_inspector.validate_schema(table_name);

        assert_eq!(result, fake_validation_schema);
    }

    #[test]
    fn test_invalid_validation_schema_handling() {
        let schema_inspector = SchemaInspector::new("test_db");
        let table_name = "unknown_table";

        // Simular error de esquema vacío o no válido
        let result = schema_inspector.validate_schema(table_name);
        assert!(result.is_empty(), "Schema should be empty or invalid");
    }
}
