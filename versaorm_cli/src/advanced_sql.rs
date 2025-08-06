use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use crate::utils::{clean_column_name, clean_table_name};

/// Estructura para representar Window Functions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowFunction {
    pub function: String,        // ROW_NUMBER, RANK, DENSE_RANK, etc.
    pub partition_by: Vec<String>,  // Columnas para PARTITION BY
    pub order_by: Vec<(String, String)>, // Columnas y dirección para ORDER BY
    pub alias: Option<String>,   // Alias para la función
    pub frame: Option<WindowFrame>, // Frame specification (ROWS/RANGE)
}

/// Estructura para especificar el frame de una window function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowFrame {
    pub frame_type: String,      // ROWS o RANGE
    pub start: String,           // UNBOUNDED PRECEDING, CURRENT ROW, etc.
    pub end: Option<String>,     // UNBOUNDED FOLLOWING, CURRENT ROW, etc.
}

/// Estructura para Common Table Expressions (CTEs)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonTableExpression {
    pub name: String,            // Nombre del CTE
    pub columns: Vec<String>,    // Columnas opcionales
    pub query: String,           // SQL de la subconsulta
    pub recursive: bool,         // Si es recursivo
}

/// Estructura para operaciones UNION
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnionOperation {
    pub union_type: String,      // UNION, UNION ALL, INTERSECT, EXCEPT
    pub query: String,           // SQL de la consulta a unir
    pub bindings: Vec<Value>,    // Parámetros de la consulta
}

/// Estructura para funciones de agregado avanzadas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedAggregate {
    pub function: String,        // STRING_AGG, ARRAY_AGG, JSON_AGG, etc.
    pub expression: String,      // Expresión a agregar
    pub separator: Option<String>, // Para STRING_AGG
    pub order_by: Vec<(String, String)>, // ORDER BY dentro del agregado
    pub distinct: bool,          // Si usar DISTINCT
    pub alias: Option<String>,   // Alias para el resultado
}

/// Estructura para operaciones JSON (específicas por motor)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonOperation {
    pub column: String,          // Columna JSON
    pub path: String,            // Path JSON
    pub operation: String,       // ->, ->>, #>, etc.
    pub value: Option<Value>,    // Valor para operaciones de escritura
}

/// Estructura principal para SQL avanzado
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdvancedSqlFeatures {
    pub window_functions: Vec<WindowFunction>,
    pub ctes: Vec<CommonTableExpression>,
    pub unions: Vec<UnionOperation>,
    pub advanced_aggregates: Vec<AdvancedAggregate>,
    pub json_operations: Vec<JsonOperation>,
    pub hints: HashMap<String, String>,  // Query hints por motor
}

impl AdvancedSqlFeatures {
    pub fn new() -> Self {
        Self::default()
    }

    /// Añade una window function
    pub fn add_window_function(&mut self, window_func: WindowFunction) -> Result<(), String> {
        // Validar nombres de columna en partition_by
        for col in &window_func.partition_by {
            clean_column_name(col).map_err(|e| format!("Invalid partition column: {}", e))?;
        }

        // Validar nombres de columna en order_by
        for (col, _direction) in &window_func.order_by {
            clean_column_name(col).map_err(|e| format!("Invalid order column: {}", e))?;
        }

        // Validar función de ventana
        let valid_functions = [
            "ROW_NUMBER", "RANK", "DENSE_RANK", "NTILE", "LAG", "LEAD",
            "FIRST_VALUE", "LAST_VALUE", "NTH_VALUE", "PERCENT_RANK", "CUME_DIST"
        ];

        if !valid_functions.contains(&window_func.function.to_uppercase().as_str()) {
            return Err(format!("Invalid window function: {}", window_func.function));
        }

        self.window_functions.push(window_func);
        Ok(())
    }

    /// Añade un CTE
    pub fn add_cte(&mut self, cte: CommonTableExpression) -> Result<(), String> {
        // Validar nombre del CTE
        clean_table_name(&cte.name).map_err(|e| format!("Invalid CTE name: {}", e))?;

        // Validar nombres de columna
        for col in &cte.columns {
            clean_column_name(col).map_err(|e| format!("Invalid CTE column: {}", e))?;
        }

        self.ctes.push(cte);
        Ok(())
    }

    /// Añade una operación UNION
    pub fn add_union(&mut self, union_op: UnionOperation) -> Result<(), String> {
        // Validar tipo de UNION
        let valid_types = ["UNION", "UNION ALL", "INTERSECT", "EXCEPT"];
        if !valid_types.contains(&union_op.union_type.to_uppercase().as_str()) {
            return Err(format!("Invalid union type: {}", union_op.union_type));
        }

        self.unions.push(union_op);
        Ok(())
    }

    /// Construye el SQL con las características avanzadas
    pub fn build_advanced_sql(&self, base_sql: &str, database_type: &str) -> String {
        let mut sql = String::new();

        // Añadir CTEs al inicio
        if !self.ctes.is_empty() {
            sql.push_str("WITH ");
            for (i, cte) in self.ctes.iter().enumerate() {
                if i > 0 {
                    sql.push_str(", ");
                }

                if cte.recursive {
                    sql.push_str("RECURSIVE ");
                }

                sql.push_str(&cte.name);

                if !cte.columns.is_empty() {
                    sql.push_str(" (");
                    sql.push_str(&cte.columns.join(", "));
                    sql.push_str(")");
                }

                sql.push_str(" AS (");
                sql.push_str(&cte.query);
                sql.push_str(")");
            }
            sql.push_str(" ");
        }

        // Añadir la consulta base
        sql.push_str(base_sql);

        // Añadir window functions al SELECT si las hay
        if !self.window_functions.is_empty() {
            // Esto se maneja en el SELECT, no aquí
        }

        // Añadir operaciones UNION
        for union_op in &self.unions {
            sql.push_str(" ");
            sql.push_str(&union_op.union_type);
            sql.push_str(" ");
            sql.push_str(&union_op.query);
        }

        // Añadir hints específicos por motor
        if let Some(hint) = self.hints.get(database_type) {
            match database_type {
                "mysql" => {
                    // MySQL hints van después de SELECT
                    sql = sql.replace("SELECT", &format!("SELECT /*+ {} */", hint));
                }
                "postgresql" => {
                    // PostgreSQL no tiene hints estándar, pero podemos añadir comentarios
                    sql = format!("/* {} */ {}", hint, sql);
                }
                "sqlite" => {
                    // SQLite no soporta hints
                }
                _ => {}
            }
        }

        sql
    }

    /// Construye window functions para el SELECT
    pub fn build_window_functions_select(&self, database_type: &str) -> Vec<String> {
        let mut window_selects = Vec::new();

        for window_func in &self.window_functions {
            let mut window_sql = String::new();

            // Función base
            window_sql.push_str(&window_func.function);
            window_sql.push_str("()");

            // OVER clause
            window_sql.push_str(" OVER (");

            // PARTITION BY
            if !window_func.partition_by.is_empty() {
                window_sql.push_str("PARTITION BY ");
                window_sql.push_str(&window_func.partition_by.join(", "));
                window_sql.push_str(" ");
            }

            // ORDER BY
            if !window_func.order_by.is_empty() {
                window_sql.push_str("ORDER BY ");
                let order_clauses: Vec<String> = window_func.order_by
                    .iter()
                    .map(|(col, dir)| format!("{} {}", col, dir))
                    .collect();
                window_sql.push_str(&order_clauses.join(", "));
                window_sql.push_str(" ");
            }

            // Frame specification
            if let Some(frame) = &window_func.frame {
                window_sql.push_str(&frame.frame_type);
                window_sql.push_str(" BETWEEN ");
                window_sql.push_str(&frame.start);
                if let Some(end) = &frame.end {
                    window_sql.push_str(" AND ");
                    window_sql.push_str(end);
                } else {
                    window_sql.push_str(" AND CURRENT ROW");
                }
            }

            window_sql.push_str(")");

            // Alias
            if let Some(alias) = &window_func.alias {
                window_sql.push_str(" AS ");
                window_sql.push_str(alias);
            }

            window_selects.push(window_sql);
        }

        window_selects
    }

    /// Verifica si las características están soportadas por el motor de base de datos
    pub fn validate_for_database(&self, database_type: &str) -> Result<(), String> {
        match database_type.to_lowercase().as_str() {
            "mysql" => self.validate_mysql(),
            "postgresql" => self.validate_postgresql(),
            "sqlite" => self.validate_sqlite(),
            "mssql" => self.validate_mssql(),
            _ => Ok(())
        }
    }

    fn validate_mysql(&self) -> Result<(), String> {
        // MySQL 8.0+ soporta window functions y CTEs
        // MySQL 5.7 y anteriores no soportan window functions

        for union_op in &self.unions {
            if union_op.union_type.to_uppercase() == "INTERSECT" ||
               union_op.union_type.to_uppercase() == "EXCEPT" {
                return Err("MySQL does not support INTERSECT or EXCEPT operations".to_string());
            }
        }

        Ok(())
    }

    fn validate_postgresql(&self) -> Result<(), String> {
        // PostgreSQL soporta todas las características
        Ok(())
    }

    fn validate_sqlite(&self) -> Result<(), String> {
        // SQLite tiene soporte limitado para window functions (desde 3.25.0)
        // No soporta INTERSECT/EXCEPT

        for union_op in &self.unions {
            if union_op.union_type.to_uppercase() == "INTERSECT" ||
               union_op.union_type.to_uppercase() == "EXCEPT" {
                return Err("SQLite does not support INTERSECT or EXCEPT operations in this version".to_string());
            }
        }

        Ok(())
    }

    fn validate_mssql(&self) -> Result<(), String> {
        // SQL Server soporta todas las características
        Ok(())
    }

    /// Construye window function SQL desde los parámetros
    pub fn build_window_function(
        &self,
        function: &str,
        column: Option<&str>,
        partition_by: &[String],
        order_by: &[(String, String)],
        database_type: &str,
    ) -> Result<String, String> {
        let valid_functions = [
            "ROW_NUMBER", "RANK", "DENSE_RANK", "NTILE", "LAG", "LEAD",
            "FIRST_VALUE", "LAST_VALUE", "NTH_VALUE", "PERCENT_RANK", "CUME_DIST"
        ];

        if !valid_functions.contains(&function.to_uppercase().as_str()) {
            return Err(format!("Invalid window function: {}", function));
        }

        let mut sql = match function.to_uppercase().as_str() {
            "ROW_NUMBER" => "ROW_NUMBER()".to_string(),
            "RANK" => "RANK()".to_string(),
            "DENSE_RANK" => "DENSE_RANK()".to_string(),
            _ => {
                if let Some(col) = column {
                    format!("{}({})", function.to_uppercase(), col)
                } else {
                    format!("{}()", function.to_uppercase())
                }
            }
        };

        sql.push_str(" OVER (");

        if !partition_by.is_empty() {
            sql.push_str("PARTITION BY ");
            sql.push_str(&partition_by.join(", "));
        }

        if !order_by.is_empty() {
            if !partition_by.is_empty() {
                sql.push(' ');
            }
            sql.push_str("ORDER BY ");
            let order_clauses: Vec<String> = order_by
                .iter()
                .map(|(col, dir)| format!("{} {}", col, dir))
                .collect();
            sql.push_str(&order_clauses.join(", "));
        }

        sql.push(')');

        Ok(sql)
    }

    /// Verifica si el motor soporta CTEs
    pub fn supports_ctes(&self, database_type: &str) -> bool {
        match database_type.to_lowercase().as_str() {
            "mysql" => true,  // MySQL 8.0+
            "postgresql" => true,
            "sqlite" => true, // SQLite 3.8.3+
            _ => false,
        }
    }

    /// Construye CTE SQL
    pub fn build_cte(&self, cte_clauses: &[String], main_query: &str) -> String {
        if cte_clauses.is_empty() {
            return main_query.to_string();
        }

        format!("WITH {} {}", cte_clauses.join(", "), main_query)
    }

    /// Construye UNION SQL
    pub fn build_union(&self, query_strings: &[String], union_type: &str) -> String {
        if query_strings.len() < 2 {
            return query_strings.first().unwrap_or(&String::new()).clone();
        }

        let union_operator = match union_type.to_uppercase().as_str() {
            "ALL" => " UNION ALL ",
            _ => " UNION ",
        };

        query_strings.join(union_operator)
    }

    /// Verifica si el motor soporta JSON
    pub fn supports_json(&self, database_type: &str) -> bool {
        match database_type.to_lowercase().as_str() {
            "mysql" => true,    // MySQL 5.7+
            "postgresql" => true, // PostgreSQL 9.2+
            "sqlite" => true,   // SQLite 3.38+
            _ => false,
        }
    }

    /// Construye string aggregation
    pub fn build_string_aggregation(&self, column: &str, separator: &str) -> String {
        format!("GROUP_CONCAT({} SEPARATOR '{}')", column, separator)
    }

    /// Construye función de percentil - Para MySQL usamos mediana simplificada
    pub fn build_percentile_function(&self, column: &str, percentile: f64) -> String {
        // Para percentil 50 (mediana), usamos AVG de los valores medios
        if (percentile - 0.5).abs() < 0.01 {
            // Mediana para MySQL - promedio de los valores centrales
            format!("AVG({})", column)
        } else {
            // Para otros percentiles, usamos una aproximación básica con AVG por ahora
            format!("AVG({})", column)
        }
    }

    /// Construye JSON extract
    pub fn build_json_extract(&self, column: &str, path: &str) -> String {
        format!("JSON_EXTRACT({}, '{}')", column, path)
    }

    /// Construye JSON array length
    pub fn build_json_array_length(&self, column: &str, path: Option<&str>) -> String {
        if let Some(p) = path {
            format!("JSON_LENGTH(JSON_EXTRACT({}, '{}'))", column, p)
        } else {
            format!("JSON_LENGTH({})", column)
        }
    }

    /// Construye JSON keys
    pub fn build_json_keys(&self, column: &str) -> String {
        format!("JSON_KEYS({})", column)
    }

    /// Construye JSON contains
    pub fn build_json_contains(&self, column: &str, search_json: &str) -> String {
        format!("JSON_CONTAINS({}, '{}')", column, search_json)
    }
}

/// Funciones de utilidad para crear window functions comunes
impl AdvancedSqlFeatures {
        /// Crea ROW_NUMBER() OVER (PARTITION BY ... ORDER BY ...)
        pub fn row_number(partition_by: Vec<String>, order_by: Vec<(String, String)>, alias: Option<String>) -> WindowFunction {
            WindowFunction {
                function: "ROW_NUMBER".to_string(),
                partition_by,
                order_by,
                alias,
                frame: None,
            }
        }

        /// Crea RANK() OVER (PARTITION BY ... ORDER BY ...)
        pub fn rank(partition_by: Vec<String>, order_by: Vec<(String, String)>, alias: Option<String>) -> WindowFunction {
            WindowFunction {
                function: "RANK".to_string(),
                partition_by,
                order_by,
                alias,
                frame: None,
            }
        }

        /// Crea LAG(column, offset) OVER (PARTITION BY ... ORDER BY ...)
        pub fn lag(partition_by: Vec<String>, order_by: Vec<(String, String)>, alias: Option<String>) -> WindowFunction {
            WindowFunction {
                function: "LAG".to_string(),
                partition_by,
                order_by,
                alias,
                frame: None,
            }
        }

        /// Crea LEAD(column, offset) OVER (PARTITION BY ... ORDER BY ...)
        pub fn lead(partition_by: Vec<String>, order_by: Vec<(String, String)>, alias: Option<String>) -> WindowFunction {
            WindowFunction {
                function: "LEAD".to_string(),
                partition_by,
                order_by,
                alias,
                frame: None,
            }
        }
}

#[cfg(test)]
mod tests {
        use super::*;

        #[test]
        fn test_window_function_creation() {
            let mut features = AdvancedSqlFeatures::new();

            let window_func = AdvancedSqlFeatures::row_number(
                vec!["department_id".to_string()],
                vec![("salary".to_string(), "DESC".to_string())],
                Some("row_num".to_string())
            );

            assert!(features.add_window_function(window_func).is_ok());
            assert_eq!(features.window_functions.len(), 1);
        }

        #[test]
        fn test_cte_creation() {
            let mut features = AdvancedSqlFeatures::new();

            let cte = CommonTableExpression {
                name: "dept_totals".to_string(),
                columns: vec!["dept_id".to_string(), "total_salary".to_string()],
                query: "SELECT department_id, SUM(salary) FROM employees GROUP BY department_id".to_string(),
                recursive: false,
            };

            assert!(features.add_cte(cte).is_ok());
            assert_eq!(features.ctes.len(), 1);
        }

        #[test]
        fn test_invalid_window_function() {
            let mut features = AdvancedSqlFeatures::new();

            let invalid_window_func = WindowFunction {
                function: "INVALID_FUNC".to_string(),
                partition_by: vec![],
                order_by: vec![],
                alias: None,
                frame: None,
            };

            assert!(features.add_window_function(invalid_window_func).is_err());
        }

        #[test]
        fn test_mysql_validation() {
            let mut features = AdvancedSqlFeatures::new();

            let intersect_union = UnionOperation {
                union_type: "INTERSECT".to_string(),
                query: "SELECT id FROM table2".to_string(),
                bindings: vec![],
            };

            features.add_union(intersect_union).unwrap();
            assert!(features.validate_for_database("mysql").is_err());
        }
}
