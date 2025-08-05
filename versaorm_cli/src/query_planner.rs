use crate::RelationMetadata;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Operación individual en el plan de consulta
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryOperation {
    pub operation_type: String,
    pub table: String,
    pub columns: Vec<String>,
    pub conditions: Vec<QueryCondition>,
    pub join_conditions: Vec<JoinCondition>,
    pub ordering: Vec<OrderBy>,
    pub grouping: Vec<String>,
    pub having: Vec<QueryCondition>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub relations: Vec<RelationMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryCondition {
    pub column: String,
    pub operator: String,
    pub value: Value,
    pub connector: String, // AND, OR
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinCondition {
    pub table: String,
    pub join_type: String,
    pub local_column: String,
    pub foreign_column: String,
    pub operator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderBy {
    pub column: String,
    pub direction: String,
}

/// Plan de ejecución de consulta optimizado
#[derive(Debug, Clone)]
pub struct QueryPlan {
    pub operations: Vec<QueryOperation>,
    pub estimated_cost: f64,
    pub optimization_notes: Vec<String>,
    pub is_lazy: bool,
    pub can_combine: bool,
}

/// Optimizador de consultas
pub struct QueryOptimizer {
    pub enable_join_optimization: bool,
    pub enable_where_combination: bool,
    pub enable_subquery_elimination: bool,
    pub max_operations_to_combine: usize,
}

impl Default for QueryOptimizer {
    fn default() -> Self {
        Self {
            enable_join_optimization: true,
            enable_where_combination: true,
            enable_subquery_elimination: true,
            max_operations_to_combine: 5,
        }
    }
}

impl QueryOptimizer {
    /// Crea un plan de consulta optimizado a partir de operaciones individuales
    pub fn create_plan(&self, operations: Vec<QueryOperation>) -> QueryPlan {
        let mut plan = QueryPlan {
            operations: operations.clone(),
            estimated_cost: 0.0,
            optimization_notes: Vec::new(),
            is_lazy: true,
            can_combine: false,
        };

        // Verificar si las operaciones se pueden combinar
        if self.can_combine_operations(&operations) {
            plan.can_combine = true;
            plan = self.optimize_operations(plan);
        }

        // Calcular costo estimado
        plan.estimated_cost = self.estimate_cost(&plan.operations);

        plan
    }

    /// Verifica si las operaciones se pueden combinar en una sola consulta
    fn can_combine_operations(&self, operations: &[QueryOperation]) -> bool {
        if operations.len() <= 1 {
            return false;
        }

        // Verificar que todas las operaciones sean SELECT de la misma tabla base
        let first_table = &operations[0].table;
        operations.iter().all(|op| {
            op.operation_type == "SELECT"
                && op.table == *first_table
                && operations.len() <= self.max_operations_to_combine
        })
    }

    /// Optimiza el plan combinando operaciones compatibles
    fn optimize_operations(&self, mut plan: QueryPlan) -> QueryPlan {
        if !plan.can_combine || plan.operations.len() <= 1 {
            return plan;
        }

        // Combinar todas las operaciones en una sola
        let combined = self.combine_operations(&plan.operations);
        plan.operations = vec![combined];
        plan.optimization_notes
            .push("Combined multiple operations into single query".to_string());

        // Optimizar JOINs si está habilitado
        if self.enable_join_optimization {
            plan = self.optimize_joins(plan);
        }

        // Combinar condiciones WHERE si está habilitado
        if self.enable_where_combination {
            plan = self.optimize_where_conditions(plan);
        }

        plan
    }

    /// Combina múltiples operaciones en una sola
    fn combine_operations(&self, operations: &[QueryOperation]) -> QueryOperation {
        let first = &operations[0];
        let mut combined = first.clone();

        // Combinar columnas (sin duplicados)
        for op in operations.iter().skip(1) {
            for column in &op.columns {
                if !combined.columns.contains(column) {
                    combined.columns.push(column.clone());
                }
            }

            // Combinar condiciones WHERE
            combined.conditions.extend(op.conditions.clone());

            // Combinar JOINs
            combined.join_conditions.extend(op.join_conditions.clone());

            // Combinar relaciones
            combined.relations.extend(op.relations.clone());
        }

        // Eliminar duplicados en columnas
        combined.columns.sort();
        combined.columns.dedup();

        combined
    }

    /// Optimiza los JOINs eliminando redundancias
    fn optimize_joins(&self, mut plan: QueryPlan) -> QueryPlan {
        for operation in &mut plan.operations {
            // Eliminar JOINs duplicados
            operation
                .join_conditions
                .sort_by(|a, b| a.table.cmp(&b.table));
            operation.join_conditions.dedup_by(|a, b| {
                a.table == b.table
                    && a.local_column == b.local_column
                    && a.foreign_column == b.foreign_column
            });

            // Convertir INNER JOINs redundantes
            let mut optimized_joins = Vec::new();
            for join in &operation.join_conditions {
                // Si ya existe un JOIN con la misma tabla, usar el más restrictivo
                if let Some(existing) = optimized_joins
                    .iter()
                    .find(|j: &&JoinCondition| j.table == join.table)
                {
                    if join.join_type == "INNER" && existing.join_type == "LEFT" {
                        // Reemplazar LEFT JOIN con INNER JOIN más restrictivo
                        continue;
                    }
                }
                optimized_joins.push(join.clone());
            }
            operation.join_conditions = optimized_joins;
        }

        plan.optimization_notes
            .push("Optimized JOIN operations".to_string());
        plan
    }

    /// Optimiza las condiciones WHERE combinando y simplificando
    fn optimize_where_conditions(&self, mut plan: QueryPlan) -> QueryPlan {
        for operation in &mut plan.operations {
            // Agrupar condiciones por columna
            let mut column_conditions: HashMap<String, Vec<QueryCondition>> = HashMap::new();

            for condition in &operation.conditions {
                column_conditions
                    .entry(condition.column.clone())
                    .or_default()
                    .push(condition.clone());
            }

            // Optimizar condiciones para cada columna
            let mut optimized_conditions = Vec::new();
            for (column, conditions) in column_conditions {
                if conditions.len() == 1 {
                    optimized_conditions.extend(conditions);
                } else {
                    // Combinar múltiples condiciones para la misma columna
                    let combined = self.combine_conditions_for_column(&column, &conditions);
                    optimized_conditions.extend(combined);
                }
            }

            operation.conditions = optimized_conditions;
        }

        plan.optimization_notes
            .push("Optimized WHERE conditions".to_string());
        plan
    }

    /// Combina condiciones para una columna específica
    fn combine_conditions_for_column(
        &self,
        _column: &str,
        conditions: &[QueryCondition],
    ) -> Vec<QueryCondition> {
        // Para simplificar, por ahora devolvemos las condiciones originales
        // En una implementación completa, aquí iríamos:
        // - Detectar condiciones redundantes (e.g., age > 18 AND age > 16)
        // - Combinar rangos (e.g., age > 18 AND age < 65)
        // - Eliminar contradicciones (e.g., age > 50 AND age < 30)
        conditions.to_vec()
    }

    /// Estima el costo de ejecución del plan
    fn estimate_cost(&self, operations: &[QueryOperation]) -> f64 {
        let mut total_cost = 0.0;

        for operation in operations {
            let mut operation_cost = 1.0; // Costo base

            // Costo por JOINs
            operation_cost += operation.join_conditions.len() as f64 * 2.0;

            // Costo por condiciones WHERE
            operation_cost += operation.conditions.len() as f64 * 0.5;

            // Costo por ORDER BY
            operation_cost += operation.ordering.len() as f64 * 1.5;

            // Costo por GROUP BY
            operation_cost += operation.grouping.len() as f64 * 2.5;

            // Penalización por LIMIT alto
            if let Some(limit) = operation.limit {
                if limit > 1000 {
                    operation_cost += (limit as f64 / 1000.0) * 0.5;
                }
            }

            total_cost += operation_cost;
        }

        total_cost
    }

    /// Genera SQL optimizado a partir del plan
    pub fn generate_optimized_sql(&self, plan: &QueryPlan) -> (String, Vec<Value>) {
        if plan.operations.is_empty() {
            return ("".to_string(), Vec::new());
        }

        // Si solo hay una operación, generar SQL directamente
        if plan.operations.len() == 1 {
            return self.generate_sql_for_operation(&plan.operations[0]);
        }

        // Para múltiples operaciones, usar UNION o subconsultas según sea apropiado
        let mut sql_parts = Vec::new();
        let mut all_params = Vec::new();

        for operation in &plan.operations {
            let (sql, params) = self.generate_sql_for_operation(operation);
            sql_parts.push(sql);
            all_params.extend(params);
        }

        (sql_parts.join(" UNION "), all_params)
    }

    /// Genera SQL para una operación individual
    fn generate_sql_for_operation(&self, operation: &QueryOperation) -> (String, Vec<Value>) {
        let mut sql = String::new();
        let mut params = Vec::new();

        // SELECT clause
        sql.push_str("SELECT ");
        if operation.columns.is_empty() {
            sql.push('*');
        } else {
            sql.push_str(&operation.columns.join(", "));
        }

        // FROM clause
        sql.push_str(&format!(" FROM {}", operation.table));

        // JOIN clauses
        for join in &operation.join_conditions {
            sql.push_str(&format!(
                " {} JOIN {} ON {} {} {}",
                join.join_type, join.table, join.local_column, join.operator, join.foreign_column
            ));
        }

        // WHERE clause
        if !operation.conditions.is_empty() {
            sql.push_str(" WHERE ");
            let where_parts: Vec<String> = operation
                .conditions
                .iter()
                .enumerate()
                .map(|(i, condition)| {
                    params.push(condition.value.clone());
                    let connector = if i == 0 {
                        ""
                    } else {
                        &format!(" {} ", condition.connector)
                    };
                    format!("{}{} {} ?", connector, condition.column, condition.operator)
                })
                .collect();
            sql.push_str(&where_parts.join(""));
        }

        // GROUP BY clause
        if !operation.grouping.is_empty() {
            sql.push_str(&format!(" GROUP BY {}", operation.grouping.join(", ")));
        }

        // HAVING clause
        if !operation.having.is_empty() {
            sql.push_str(" HAVING ");
            let having_parts: Vec<String> = operation
                .having
                .iter()
                .enumerate()
                .map(|(i, condition)| {
                    params.push(condition.value.clone());
                    let connector = if i == 0 {
                        ""
                    } else {
                        &format!(" {} ", condition.connector)
                    };
                    format!("{}{} {} ?", connector, condition.column, condition.operator)
                })
                .collect();
            sql.push_str(&having_parts.join(""));
        }

        // ORDER BY clause
        if !operation.ordering.is_empty() {
            sql.push_str(" ORDER BY ");
            let order_parts: Vec<String> = operation
                .ordering
                .iter()
                .map(|order| format!("{} {}", order.column, order.direction))
                .collect();
            sql.push_str(&order_parts.join(", "));
        }

        // LIMIT clause
        if let Some(limit) = operation.limit {
            sql.push_str(&format!(" LIMIT {}", limit));

            if let Some(offset) = operation.offset {
                sql.push_str(&format!(" OFFSET {}", offset));
            }
        }

        (sql, params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_plan_creation() {
        let optimizer = QueryOptimizer::default();
        let operations = vec![QueryOperation {
            operation_type: "SELECT".to_string(),
            table: "users".to_string(),
            columns: vec!["id".to_string(), "name".to_string()],
            conditions: vec![],
            join_conditions: vec![],
            ordering: vec![],
            grouping: vec![],
            having: vec![],
            limit: None,
            offset: None,
            relations: vec![],
        }];

        let plan = optimizer.create_plan(operations);
        assert!(plan.estimated_cost > 0.0);
        assert_eq!(plan.operations.len(), 1);
    }

    #[test]
    fn test_operation_combination() {
        let optimizer = QueryOptimizer::default();
        let operations = vec![
            QueryOperation {
                operation_type: "SELECT".to_string(),
                table: "users".to_string(),
                columns: vec!["id".to_string()],
                conditions: vec![],
                join_conditions: vec![],
                ordering: vec![],
                grouping: vec![],
                having: vec![],
                limit: None,
                offset: None,
                relations: vec![],
            },
            QueryOperation {
                operation_type: "SELECT".to_string(),
                table: "users".to_string(),
                columns: vec!["name".to_string()],
                conditions: vec![],
                join_conditions: vec![],
                ordering: vec![],
                grouping: vec![],
                having: vec![],
                limit: None,
                offset: None,
                relations: vec![],
            },
        ];

        let plan = optimizer.create_plan(operations);
        assert!(plan.can_combine);
    }

    #[test]
    fn test_sql_generation() {
        let optimizer = QueryOptimizer::default();
        let operation = QueryOperation {
            operation_type: "SELECT".to_string(),
            table: "users".to_string(),
            columns: vec!["id".to_string(), "name".to_string()],
            conditions: vec![QueryCondition {
                column: "active".to_string(),
                operator: "=".to_string(),
                value: Value::Bool(true),
                connector: "AND".to_string(),
            }],
            join_conditions: vec![],
            ordering: vec![OrderBy {
                column: "name".to_string(),
                direction: "ASC".to_string(),
            }],
            grouping: vec![],
            having: vec![],
            limit: Some(10),
            offset: None,
            relations: vec![],
        };

        let (sql, params) = optimizer.generate_sql_for_operation(&operation);
        assert!(sql.contains("SELECT id, name"));
        assert!(sql.contains("FROM users"));
        assert!(sql.contains("WHERE active = ?"));
        assert!(sql.contains("ORDER BY name ASC"));
        assert!(sql.contains("LIMIT 10"));
        assert_eq!(params.len(), 1);
    }
}
