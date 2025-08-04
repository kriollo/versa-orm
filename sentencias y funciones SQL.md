# 📘 Sentencias y funciones SQL necesarias para VersaORM (MySQL, PostgreSQL, SQLite, MSSQL)

Este documento enumera todas las sentencias SQL y funciones relevantes que **VersaORM** debería soportar para trabajar correctamente en los siguientes motores:

* MySQL / MariaDB
* PostgreSQL
* SQLite
* Microsoft SQL Server (MSSQL)

Organizado por categoría, incluye diferencias y consideraciones especiales para cada motor.

---

## 🧱 1. Sentencias Básicas (DML)

| Operación           | Ejemplo                                                                                                          | Compatibilidad        |
| ------------------- | ---------------------------------------------------------------------------------------------------------------- | --------------------- |
| `SELECT`            | `SELECT col FROM table`                                                                                          | ✔️ Todos              |
| `INSERT`            | `INSERT INTO table (...) VALUES (...)`                                                                           | ✔️ Todos              |
| `UPDATE`            | `UPDATE table SET col = val WHERE ...`                                                                           | ✔️ Todos              |
| `DELETE`            | `DELETE FROM table WHERE ...`                                                                                    | ✔️ Todos              |
| `UPSERT`            | MySQL: `ON DUPLICATE KEY UPDATE`<br>PG: `ON CONFLICT DO UPDATE`<br>SQLite: `INSERT OR REPLACE`<br>MSSQL: `MERGE` | ⚠️ Sintaxis por motor |
| `INSERT ... SELECT` | `INSERT INTO t1 SELECT ... FROM t2`                                                                              | ✔️ Todos              |
| `UPDATE ... JOIN`   | MySQL: `JOIN`<br>PG/MSSQL: `FROM`                                                                                | ⚠️ SQLite limitado    |

---

## 📎 2. WHERE, JOIN, LIMIT, ORDER, GROUP

| Cláusula             | Ejemplo                                           | Compatibilidad       |          |
| -------------------- | ------------------------------------------------- | -------------------- | -------- |
| `WHERE`              | `WHERE col = ?`                                   | ✔️ Todos             |          |
| `JOIN`               | `INNER`, `LEFT`, `RIGHT`, `FULL`                  | ⚠️ SQLite sin `FULL` |          |
| `ORDER BY`           | \`ORDER BY col ASC                                | DESC\`               | ✔️ Todos |
| `LIMIT/OFFSET`       | `LIMIT 10 OFFSET 5` / `OFFSET ... FETCH NEXT ...` | ⚠️ MSSQL diferente   |          |
| `GROUP BY`, `HAVING` | Standard                                          | ✔️ Todos             |          |
| `DISTINCT`           | `SELECT DISTINCT col`                             | ✔️ Todos             |          |

---

## 🏗️ 3. DDL – Data Definition

| Acción         | Ejemplo                          | Compatibilidad            |
| -------------- | -------------------------------- | ------------------------- |
| `CREATE TABLE` | `CREATE TABLE users (...)`       | ✔️ Todos                  |
| `ALTER TABLE`  | Add/drop/modify columns          | ✔️ Todos (sintaxis varía) |
| `RENAME TABLE` | `ALTER TABLE ... RENAME TO ...`  | ⚠️ Cambia por motor       |
| `DROP TABLE`   | `DROP TABLE IF EXISTS ...`       | ✔️ Todos                  |
| `CREATE INDEX` | `CREATE INDEX ...`               | ✔️ Todos                  |
| `DROP INDEX`   | `DROP INDEX ...`                 | ⚠️ PG requiere `ON` tabla |
| `TRUNCATE`     | `TRUNCATE TABLE ...`             | ⚠️ SQLite no lo soporta   |
| `CREATE VIEW`  | `CREATE VIEW name AS SELECT ...` | ✔️ Todos                  |
| `DROP VIEW`    | `DROP VIEW name`                 | ✔️ Todos                  |

---

## 🔐 4. Transacciones

| Acción        | SQL                     | Compatibilidad    |
| ------------- | ----------------------- | ----------------- |
| `BEGIN`       | `BEGIN TRANSACTION`     | ✔️ Todos          |
| `COMMIT`      | `COMMIT`                | ✔️ Todos          |
| `ROLLBACK`    | `ROLLBACK`              | ✔️ Todos          |
| `SAVEPOINT`   | `SAVEPOINT name`        | ⚠️ MySQL limitado |
| `ROLLBACK TO` | `ROLLBACK TO SAVEPOINT` | ⚠️ MySQL parcial  |

---

## 📊 5. Funciones SQL comunes

| Categoría      | Ejemplos                                      | Compatibilidad     |
| -------------- | --------------------------------------------- | ------------------ |
| Agregación     | `COUNT()`, `SUM()`, `AVG()`, `MAX()`, `MIN()` | ✔️ Todos           |
| Texto          | `CONCAT()`, `UPPER()`, `LOWER()`, `REPLACE()` | ✔️ Todos           |
| Números/Fechas | `ROUND()`, `NOW()`, `DATE_ADD()`              | ✔️ con diferencias |
| Nulos          | `COALESCE()`, `IFNULL()`, `NULLIF()`          | ✔️ Todos           |
| Condicionales  | `CASE WHEN ... THEN ... END`                  | ✔️ Todos           |
| Conversión     | `CAST(x AS type)`, `CONVERT()`                | ⚠️ Sintaxis varía  |

---

## 🧠 6. Subconsultas y CTEs

| Tipo               | Ejemplo                                 | Compatibilidad                 |
| ------------------ | --------------------------------------- | ------------------------------ |
| Subquery en SELECT | `(SELECT COUNT(*) FROM orders)`         | ✔️ Todos                       |
| Subquery en WHERE  | `WHERE id IN (SELECT ...)`              | ✔️ Todos                       |
| Subquery en JOIN   | `JOIN (SELECT ...) x ON ...`            | ✔️ Todos                       |
| CTE / `WITH`       | `WITH temp AS (...) SELECT * FROM temp` | ✔️ Todos (MySQL ≥ 8)           |
| `WITH RECURSIVE`   | Consultas jerárquicas                   | ✔️ PG, MySQL 8+, SQLite, MSSQL |

---

## 🔁 7. `UNION`, `INTERSECT`, `EXCEPT`

| Operación   | Compatibilidad      |
| ----------- | ------------------- |
| `UNION`     | ✔️ Todos            |
| `UNION ALL` | ✔️ Todos            |
| `INTERSECT` | ❌ SQLite no soporta |
| `EXCEPT`    | ❌ SQLite no soporta |

---

## 📚 8. Metadata e introspección

| Acción          | SQL Ejemplo                                                   | Notas                |
| --------------- | ------------------------------------------------------------- | -------------------- |
| Listar tablas   | `SHOW TABLES`, `sqlite_master`, `pg_catalog`                  | Específico por motor |
| Describir tabla | `DESCRIBE`, `PRAGMA table_info`, `information_schema.columns` | ORM debe adaptarse   |
| Ver índices     | `SHOW INDEX`, `pg_indexes`, `sys.indexes`                     | ⚠️ Depende del motor |

---

## ⚙️ 9. Capacidades avanzadas

| Función            | Compatibilidad                          |
| ------------------ | --------------------------------------- |
| JSON (`->`, `->>`) | ✔️ PG y MySQL <br> MSSQL: `JSON_VALUE`  |
| Arrays             | ✔️ PostgreSQL                           |
| ENUM / SET         | ✔️ MySQL, parcial en PG                 |
| Window functions   | ✔️ PG, MSSQL, MySQL ≥ 8, SQLite parcial |
| FULLTEXT search    | ✔️ MySQL (InnoDB), PG (`tsvector`)      |
| Generated columns  | ✔️ PG, MySQL, SQLite ≥ 3.31             |

---

## ✅ Recomendaciones para VersaORM

* Adaptar DSL generador de SQL por motor (abstracción interna)
* Normalizar API: `select()`, `where()`, `insertFrom()`, `updateFrom()`
* Soportar subconsultas en `SELECT`, `FROM`, `WHERE`, `JOIN`
* Documentar funciones específicas por motor
* Implementar introspección para migraciones y scaffolding

---

📆 Última actualización: `2025-08-01`
