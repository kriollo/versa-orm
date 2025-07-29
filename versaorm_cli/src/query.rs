use serde_json::Value;
use sqlx::Database;

pub struct QueryBuilder {
    pub table: String,
    pub selects: Vec<String>,
    pub wheres: Vec<(String, String, Value)>,
    pub joins: Vec<(String, String, String, String)>,
    pub order: Option<(String, String)>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
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
        }
    }

    pub fn select(mut self, columns: Vec<&str>) -> Self {
        self.selects = columns.into_iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn r#where(mut self, column: &str, operator: &str, value: Value) -> Self {
        self.wheres.push((column.to_string(), operator.to_string(), value));
        self
    }

    #[allow(dead_code)]
    pub fn join(mut self, table: &str, first_col: &str, operator: &str, second_col: &str) -> Self {
        self.joins.push((table.to_string(), first_col.to_string(), operator.to_string(), second_col.to_string()));
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
        for (table, first_col, operator, second_col) in self.joins.iter() {
            query.push_str(&format!(" JOIN {} ON {} {} {}", table, first_col, operator, second_col));
        }

        // WHERE clause
        if !self.wheres.is_empty() {
            query.push_str(" WHERE ");
let mut where_clauses = Vec::new();

            for (col, op, value) in self.wheres.iter() {
                if op == "RAW" {
                    if let Some(sql) = value.get("sql").and_then(|s| s.as_str()) {
                        if let Some(bindings) = value.get("bindings").and_then(|b| b.as_array()) {
                            for binding in bindings {
                                params.push(binding.clone());
                            }
                            where_clauses.push(format!("({})", sql));
                        }
                    }
                } else {
                    params.push(value.clone());
                    where_clauses.push(format!("{} {} ?", col, op));
                }
            }
            
            query.push_str(&where_clauses.join(" AND "));
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

