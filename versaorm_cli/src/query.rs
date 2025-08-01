use crate::utils::{clean_column_name, clean_table_name};
use crate::RelationMetadata;
use serde_json::Value;
use std::collections::HashMap;

pub struct QueryBuilder {
    pub table: String,
    pub selects: Vec<String>,
    pub wheres: Vec<(String, String, Value, String)>,
    pub joins: Vec<(String, String, String, String, String)>,
    pub order: Option<(String, String)>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub insert_data: Option<HashMap<String, Value>>,
    pub update_data: Option<HashMap<String, Value>>,
    pub group_by: Vec<String>,
    pub havings: Vec<(String, String, Value, String)>,
    pub with: Vec<RelationMetadata>,
}

impl QueryBuilder {
    pub fn new(table: &str) -> Self {
        // Validate table name for security
        let validated_table = clean_table_name(table).unwrap_or_else(|_| {
            // If table name is invalid, use a safe fallback to prevent injection
            "invalid_table".to_string()
        });

        Self {
            table: validated_table,
            selects: Vec::new(),
            wheres: Vec::new(),
            joins: Vec::new(),
            order: None,
            limit: None,
            offset: None,
            insert_data: None,
            update_data: None,
            group_by: Vec::new(),
            havings: Vec::new(),
            with: Vec::new(),
        }
    }

    // ... (existing methods) ...

    pub fn with_relations(mut self, relations: Vec<crate::RelationMetadata>) -> Self {
        self.with = relations;
        self
    }

    pub fn insert(mut self, data: &HashMap<String, Value>) -> Self {
        // Validate all column names for security
        let mut safe_data = HashMap::new();
        for (key, value) in data {
            if let Ok(clean_key) = clean_column_name(key) {
                safe_data.insert(clean_key, value.clone());
            }
        }
        self.insert_data = Some(safe_data);
        self
    }

    pub fn select(mut self, columns: Vec<&str>) -> Self {
        // Validate all column names for security
        self.selects = columns
            .into_iter()
            .filter_map(|col| clean_column_name(col).ok())
            .collect();
        self
    }

    /* pub fn update(mut self, data: &HashMap<String, Value>) -> Self {
        // Validate all column names for security
        let mut safe_data = HashMap::new();
        for (key, value) in data {
            if let Ok(clean_key) = clean_column_name(key) {
                safe_data.insert(clean_key, value.clone());
            }
        }
        self.update_data = Some(safe_data);
        self
    } */

    pub fn r#where(mut self, column: &str, operator: &str, value: Value) -> Self {
        // Validate column name and operator for security - values are safely parameterized
        if let Ok(clean_col) = clean_column_name(column) {
            if is_safe_sql_operator(operator) {
                let conjunction = if self.wheres.is_empty() { "" } else { "AND" };
                self.wheres.push((
                    clean_col,
                    operator.to_string(),
                    value,
                    conjunction.to_string(),
                ));
            }
        }
        self
    }

    pub fn or_where(mut self, column: &str, operator: &str, value: Value) -> Self {
        // Validate column name and operator for security - values are safely parameterized
        if let Ok(clean_col) = clean_column_name(column) {
            if is_safe_sql_operator(operator) {
                let conjunction = if self.wheres.is_empty() { "" } else { "OR" };
                self.wheres.push((
                    clean_col,
                    operator.to_string(),
                    value,
                    conjunction.to_string(),
                ));
            }
        }
        self
    }

    #[allow(dead_code)]
    pub fn join(mut self, table: &str, first_col: &str, operator: &str, second_col: &str) -> Self {
        // Validate all join components for security
        if let (Ok(clean_table), Ok(clean_first_col), Ok(clean_second_col)) = (
            clean_table_name(table),
            clean_column_name(first_col),
            clean_column_name(second_col),
        ) {
            if is_safe_sql_operator(operator) {
                self.joins.push((
                    clean_table,
                    clean_first_col,
                    operator.to_string(),
                    clean_second_col,
                    "INNER".to_string(),
                ));
            }
        }
        self
    }

    #[allow(dead_code)]
    pub fn left_join(
        mut self,
        table: &str,
        first_col: &str,
        operator: &str,
        second_col: &str,
    ) -> Self {
        // Validate all join components for security
        if let (Ok(clean_table), Ok(clean_first_col), Ok(clean_second_col)) = (
            clean_table_name(table),
            clean_column_name(first_col),
            clean_column_name(second_col),
        ) {
            if is_safe_sql_operator(operator) {
                self.joins.push((
                    clean_table,
                    clean_first_col,
                    operator.to_string(),
                    clean_second_col,
                    "LEFT".to_string(),
                ));
            }
        }
        self
    }

    pub fn order_by(mut self, column: &str, direction: &str) -> Self {
        // Validate column name and direction for security
        if let Ok(clean_col) = clean_column_name(column) {
            let safe_direction = match direction.to_uppercase().as_str() {
                "ASC" | "DESC" => direction.to_uppercase(),
                _ => "ASC".to_string(), // Default to ASC if invalid
            };
            self.order = Some((clean_col, safe_direction));
        }
        self
    }

    pub fn limit(mut self, count: i64) -> Self {
        // Ensure limit is non-negative and reasonable to prevent numeric injection
        if (0..=1000000).contains(&count) {
            self.limit = Some(count);
        }
        self
    }

    pub fn offset(mut self, count: i64) -> Self {
        // Ensure offset is non-negative and reasonable to prevent numeric injection
        if (0..=1000000).contains(&count) {
            self.offset = Some(count);
        }
        self
    }

    pub fn group_by(mut self, columns: Vec<&str>) -> Self {
        self.group_by = columns
            .into_iter()
            .filter_map(|col| clean_column_name(col).ok())
            .collect();
        self
    }

    pub fn having(mut self, column: &str, operator: &str, value: Value) -> Self {
        if let Ok(clean_col) = clean_column_name(column) {
            if is_safe_sql_operator(operator) {
                let conjunction = if self.havings.is_empty() { "" } else { "AND" };
                self.havings.push((
                    clean_col,
                    operator.to_string(),
                    value,
                    conjunction.to_string(),
                ));
            }
        }
        self
    }

    pub fn build_sql(&self) -> (String, Vec<Value>) {
        let mut query = String::new();
        let mut params = Vec::new();

        if let Some(data) = &self.insert_data {
            // INSERT query
            let columns: Vec<String> = data.keys().cloned().collect();
            let placeholders: Vec<&str> = vec!["?"; data.len()];
            query = format!(
                "INSERT INTO {} ({}) VALUES ({})",
                self.table,
                columns.join(", "),
                placeholders.join(", ")
            );
            params = data.values().cloned().collect();
            return (query, params);
        } else if let Some(data) = &self.update_data {
            // UPDATE query
            let setters: Vec<String> = data.keys().map(|k| format!("{} = ?", k)).collect();
            query = format!("UPDATE {} SET {}", self.table, setters.join(", "));
            params = data.values().cloned().collect();
        } else {
            // SELECT query (default for reads)
            query.push_str("SELECT ");
            if !self.selects.is_empty() {
                query.push_str(&self.selects.join(", "));
            } else {
                query.push('*');
            }
            query.push_str(&format!(" FROM {}", self.table));
        } // JOIN clause
        for (table, first_col, operator, second_col, join_type) in self.joins.iter() {
            query.push_str(&format!(
                " {} JOIN {} ON {} {} {}",
                join_type, table, first_col, operator, second_col
            ));
        }

        // WHERE clause
        if !self.wheres.is_empty() {
            query.push_str(" WHERE ");
            let mut where_clauses = Vec::new();

            for (i, (col, op, value, conjunction)) in self.wheres.iter().enumerate() {
                let mut clause_text = String::new();

                if op == "RAW" {
                    if let Some(value_obj) = value.as_object() {
                        if let Some(sql) = value_obj.get("sql").and_then(|s| s.as_str()) {
                            if let Some(bindings) =
                                value_obj.get("bindings").and_then(|b| b.as_array())
                            {
                                if is_safe_raw_sql(sql) {
                                    let mut temp_sql = sql.to_string();
                                    for binding in bindings {
                                        params.push(binding.clone());
                                        // No reemplazar los `?` aquí, se manejarán como parámetros preparados
                                    }
                                    clause_text = format!("({})", temp_sql);
                                }
                            }
                        }
                    }
                } else {
                    // Manejar operadores especiales
                    match op.to_uppercase().as_str() {
                        "IN" | "NOT IN" => {
                            if let Some(array) = value.as_array() {
                                // Aplanar el array si es un array anidado (e.g., [[1, 2, 3]])
                                let items_to_bind = if array.len() == 1 && array[0].is_array() {
                                    array[0].as_array().unwrap().to_vec()
                                } else {
                                    array.to_vec()
                                };

                                if items_to_bind.is_empty() {
                                    // Manejar el caso de un array vacío para la cláusula IN.
                                    // Esto genera una condición que siempre es falsa para evitar errores de sintaxis SQL.
                                    clause_text = "1 = 0".to_string();
                                } else {
                                    let placeholders = vec!["?"; items_to_bind.len()].join(", ");
                                    clause_text = format!("{} {} ({})", col, op, placeholders);
                                    for item in items_to_bind {
                                        params.push(item);
                                    }
                                }
                            } else {
                                // Fallback para valores que no son un array.
                                clause_text = format!("{} {} ?", col, op);
                                params.push(value.clone());
                            }
                        }
                        "BETWEEN" => {
                            if let Some(array) = value.as_array() {
                                if array.len() >= 2 {
                                    clause_text = format!("{} BETWEEN ? AND ?", col);
                                    params.push(array[0].clone());
                                    params.push(array[1].clone());
                                } else {
                                    // Fallback si no hay suficientes valores
                                    clause_text = format!("{} {} ?", col, op);
                                    params.push(value.clone());
                                }
                            } else {
                                clause_text = format!("{} {} ?", col, op);
                                params.push(value.clone());
                            }
                        }
                        "IS NULL" => {
                            clause_text = format!("{} IS NULL", col);
                            // No se agrega parámetro para IS NULL
                        }
                        "IS NOT NULL" => {
                            clause_text = format!("{} IS NOT NULL", col);
                            // No se agrega parámetro para IS NOT NULL
                        }
                        _ => {
                            // Operadores normales (=, >, <, >=, <=, !=, LIKE, etc.)
                            clause_text = format!("{} {} ?", col, op);
                            params.push(value.clone());
                        }
                    }
                }

                // Solo agregar si tenemos texto de cláusula
                if !clause_text.is_empty() {
                    if i == 0 {
                        where_clauses.push(clause_text);
                    } else {
                        let conj = if conjunction.is_empty() {
                            "AND"
                        } else {
                            conjunction
                        };
                        where_clauses.push(format!("{} {}", conj, clause_text));
                    }
                }
            }

            query.push_str(&where_clauses.join(" "));
        }

        // GROUP BY clause
        if !self.group_by.is_empty() {
            query.push_str(&format!(" GROUP BY {}", self.group_by.join(", ")));
        }

        // HAVING clause
        if !self.havings.is_empty() {
            query.push_str(" HAVING ");
            let mut having_clauses = Vec::new();
            for (i, (col, op, value, conjunction)) in self.havings.iter().enumerate() {
                let clause_text = format!("{} {} ?", col, op);
                params.push(value.clone());

                if i == 0 {
                    having_clauses.push(clause_text);
                } else {
                    let conj = if conjunction.is_empty() {
                        "AND"
                    } else {
                        conjunction
                    };
                    having_clauses.push(format!("{} {}", conj, clause_text));
                }
            }
            query.push_str(&having_clauses.join(" "));
        }

        // ORDER BY clause
        if let Some((col, dir)) = &self.order {
            query.push_str(&format!(" ORDER BY {} {}", col, dir));
        }

        // LIMIT clause
        if let Some(limit) = self.limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }

        // OFFSET clause
        if let Some(offset) = self.offset {
            query.push_str(&format!(" OFFSET {}", offset));
        }

        (query, params)
    }
}

// Helper function to validate SQL operators
pub fn is_safe_sql_operator(operator: &str) -> bool {
    matches!(
        operator.to_uppercase().as_str(),
        "=" | "!="
            | "<>"
            | ">"
            | "<"
            | ">="
            | "<="
            | "LIKE"
            | "NOT LIKE"
            | "ILIKE"
            | "NOT ILIKE"
            | "IN"
            | "NOT IN"
            | "BETWEEN"
            | "NOT BETWEEN"
            | "IS"
            | "IS NOT"
            | "IS NULL"
            | "IS NOT NULL"
            | "RAW"
    )
}

// Helper function to validate RAW SQL clauses for security
pub fn is_safe_raw_sql(sql: &str) -> bool {
    let sql_upper = sql.to_uppercase();

    // List of dangerous SQL keywords that could be used for injection
    let dangerous_keywords = [
        "UNION", "DELETE", "DROP", "INSERT", "UPDATE", "CREATE", "ALTER", "TRUNCATE", "EXEC",
        "EXECUTE", "DECLARE", "SCRIPT", "SHUTDOWN", "GRANT", "REVOKE", "BACKUP", "RESTORE", "--",
        "/*", "*/", ";",
    ];

    // Check if the SQL contains any dangerous keywords
    for keyword in &dangerous_keywords {
        if sql_upper.contains(keyword) {
            return false;
        }
    }

    // Additional check for suspicious patterns
    if sql_upper.contains("''") || sql_upper.contains("0X") {
        return false;
    }

    true
}

// Tests movidos a tests.rs para centralización
