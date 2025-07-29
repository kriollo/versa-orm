# Estándares de Código y Contribución

Para mantener la calidad, consistencia y legibilidad del código base de VersaORM, pedimos a todos los contribuidores que sigan los estándares y directrices que se detallan a continuación.

## Estándares de Código PHP

El código PHP de VersaORM sigue el estándar **PSR-12 (Extended Coding Style)**. Este estándar define un conjunto de reglas sobre cómo formatear el código PHP, incluyendo espaciado, llaves, declaración de clases, etc.

### Verificación Automática

Para facilitar el cumplimiento de este estándar, el proyecto utiliza `PHP_CodeSniffer` (`phpcs`). Puedes verificar si tu código cumple con las reglas ejecutando el siguiente comando desde la raíz del proyecto:

```bash
vendor/bin/phpcs src/
```

Este comando analizará el directorio `src/` y te mostrará cualquier violación del estándar.

### Corrección Automática

Mejor aún, puedes usar `phpcbf` (PHP Code Beautifier and Fixer) para corregir automáticamente la mayoría de los problemas de estilo:

```bash
vendor/bin/phpcbf src/
```

**Recomendación:** Antes de hacer un commit de tus cambios en archivos PHP, ejecuta `phpcbf` para asegurarte de que tu código está correctamente formateado.

### Análisis Estático

Además del estilo, utilizamos `PHPStan` para el análisis estático de código, lo que nos ayuda a encontrar errores potenciales sin tener que ejecutar el código. Puedes ejecutarlo con:

```bash
vendor/bin/phpstan analyse src --level=8
```

El código debe pasar el análisis de PHPStan sin errores.

## Estándares de Código Rust

Para el código del núcleo en Rust, seguimos los estándares de formato oficiales de la comunidad de Rust. La herramienta estándar para esto es `rustfmt`.

`rustfmt` se instala generalmente junto con Rust a través de `rustup`. Antes de hacer un commit de tus cambios en archivos `.rs`, asegúrate de formatear tu código ejecutando el siguiente comando dentro del directorio `versaorm_cli/`:

```bash
cd versaorm_cli
cargo fmt
```

Esto formateará automáticamente todo el código Rust del proyecto para que sea consistente.

También utilizamos `clippy`, el linter oficial de Rust, para detectar errores comunes y código no idiomático. Puedes ejecutarlo con:

```bash
cd versaorm_cli
cargo clippy
```

## Mensajes de Commit

Seguimos la especificación de **Conventional Commits**. Esto hace que el historial de cambios sea más legible y nos permite automatizar la generación de changelogs.

El formato de un mensaje de commit debe ser:

```
<tipo>[ámbito opcional]: <descripción>

[cuerpo opcional]

[pie opcional]
```

-   **`<tipo>`:** Debe ser uno de los siguientes:
    -   `feat`: Una nueva característica (corresponde a una `MINOR` en versionado semántico).
    -   `fix`: Una corrección de un bug (corresponde a una `PATCH`).
    -   `docs`: Cambios en la documentación.
    -   `style`: Cambios que no afectan el significado del código (espacios, formato, etc.).
    -   `refactor`: Un cambio en el código que no corrige un bug ni añade una característica.
    -   `perf`: Un cambio que mejora el rendimiento.
    -   `test`: Añadir pruebas faltantes o corregir pruebas existentes.
    -   `chore`: Cambios en el proceso de build o herramientas auxiliares.

-   **`<descripción>`:** Un resumen conciso del cambio en minúsculas y sin punto final.

**Ejemplos de buenos mensajes de commit:**

```
feat(query-builder): añadir soporte para whereBetween
```

```
fix(rust-core): corregir el parseo de tipos decimales en postgres
```

```
docs(readme): actualizar la sección de instalación
```

## Proceso de Pull Request (PR)

1.  **Haz un Fork del Repositorio:** Crea tu propia copia del repositorio en GitHub.
2.  **Crea una Nueva Rama:** Crea una rama descriptiva para tus cambios (p. ej., `feature/add-json-support` o `fix/connection-timeout`).
    ```bash
    git checkout -b feature/mi-nueva-caracteristica
    ```
3.  **Realiza tus Cambios:** Haz tus cambios en el código, siguiendo los estándares mencionados.
4.  **Asegúrate de que las Pruebas Pasan:** Ejecuta `vendor/bin/phpunit` y `cargo test` (si aplica) para confirmar que no has roto nada.
5.  **Haz Commit de tus Cambios:** Usa mensajes de commit claros y convencionales.
6.  **Envía tus Cambios a tu Fork:**
    ```bash
    git push origin feature/mi-nueva-caracteristica
    ```
7.  **Abre un Pull Request:** Ve a la página del repositorio original de VersaORM y abre un PR desde tu fork. En la descripción del PR, explica claramente **qué** problema resuelve tu cambio y **cómo** lo has hecho. Si resuelve un issue existente, menciónalo (p. ej., `Closes #123`).

Un miembro del equipo revisará tu PR. Podemos pedirte algunos cambios antes de fusionarlo. ¡Agradecemos de antemano todas las contribuciones!
