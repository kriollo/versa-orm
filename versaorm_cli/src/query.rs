use serde_json::Value;
use sqlx::Database;
use std::collections::HashMap;

pub struct QueryBuilder {
    pub table: String,
    pub selects: Vec<String>,
    pub wheres: Vec<(String, String, Value, String)>, // Añadido cuarto campo para conjunción (AND/OR)
    pub joins: Vec<(String, String, String, String, String)>, // Añadido quinto campo para tipo de JOIN
    pub order: Option<(String, String)>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub insert_data: Option<HashMap<String, Value>>,
    pub update_data: Option<HashMap<String, Value>>,
}

impl QueryBuilder {
    pub fn new(table: &str) -> Self {
        Self {
            table: table.to_string(),
            selects: Vec::new(),
            wheres: Vec::new(),
            joins: Vec::new(),
            order: None,
            limit: None,
            offset: None,
            insert_data: None,
            update_data: None,
        }
    }

    pub fn insert(mut self, data: HashMap<String, Value>) -> Self {
        self.insert_data = Some(data);
        self
    }

    pub fn select(mut self, columns: Vec<&str>) -> Self {
        self.selects = columns.into_iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn r#where(mut self, column: &str, operator: &str, value: Value) -> Self {
        let conjunction = if self.wheres.is_empty() { "" } else { "AND" };
        self.wheres.push((column.to_string(), operator.to_string(), value, conjunction.to_string()));
        self
    }

    pub fn or_where(mut self, column: &str, operator: &str, value: Value) -> Self {
        let conjunction = if self.wheres.is_empty() { "" } else { "OR" };
        self.wheres.push((column.to_string(), operator.to_string(), value, conjunction.to_string()));
        self
    }

    #[allow(dead_code)]
    pub fn join(mut self, table: &str, first_col: &str, operator: &str, second_col: &str) -> Self {
        self.joins.push((table.to_string(), first_col.to_string(), operator.to_string(), second_col.to_string(), "INNER".to_string()));
        self
    }

    #[allow(dead_code)]
    pub fn left_join(mut self, table: &str, first_col: &str, operator: &str, second_col: &str) -> Self {
        self.joins.push((table.to_string(), first_col.to_string(), operator.to_string(), second_col.to_string(), "LEFT".to_string()));
        self
    }

    pub fn order_by(mut self, column: &str, direction: &str) -> Self {
        self.order = Some((column.to_string(), direction.to_string()));
        self
    }

    pub fn limit(mut self, count: i64) -> Self {
        self.limit = Some(count);
        self
    }

    pub fn offset(mut self, count: i64) -> Self {
        self.offset = Some(count);
        self
    }

    pub fn build_sql<D: Database>(self) -> (String, Vec<Value>) {
        let mut query = String::new();
        let mut params = Vec::new();

        // SELECT clause
        query.push_str("SELECT ");
        if !self.selects.is_empty() {
            query.push_str(&self.selects.join(", "));
        } else {
            query.push_str("*");
        }

        // FROM clause
        query.push_str(&format!(" FROM {}", self.table));

        // JOIN clause
        for (table, first_col, operator, second_col, join_type) in self.joins.iter() {
            query.push_str(&format!(" {} JOIN {} ON {} {} {}", join_type, table, first_col, operator, second_col));
        }

        // WHERE clause
        if !self.wheres.is_empty() {
            query.push_str(" WHERE ");
            let mut where_clauses = Vec::new();

            for (i, (col, op, value, conjunction)) in self.wheres.iter().enumerate() {
                let mut clause_text = String::new();
                
                if op == "RAW" {
                    if let Some(sql) = value.get("sql").and_then(|s| s.as_str()) {
                        if let Some(bindings) = value.get("bindings").and_then(|b| b.as_array()) {
                            for binding in bindings {
                                params.push(binding.clone());
                            }
                            clause_text = format!("({})", sql);
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
                                    clause_text = format!("1 = 0");
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
                        let conj = if conjunction.is_empty() { "AND" } else { conjunction };
                        where_clauses.push(format!("{} {}", conj, clause_text));
                    }
                }
            }
            
            query.push_str(&where_clauses.join(" "));
        }

        // ORDER BY clause
        if let Some((col, dir)) = self.order {
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

