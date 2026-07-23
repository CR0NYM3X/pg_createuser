# pg_createuser

## 📋 Descripción
Script en bloque anónimo `PL/pgSQL` (`DO $$`) para automatizar la creación de usuarios en PostgreSQL. Genera una contraseña aleatoria basada en las reglas de la extensión `credcheck` y ejecuta el comando `CREATE USER` de forma segura mediante la función `format()`.

---

## ⚙️ Parámetros Configurables

Los parámetros se modifican directamente en la sección `DECLARE` del script:

| Variable | Tipo | Valor Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `v_username` | `TEXT` | `'user_test'` | Nombre del usuario a crear. |
| `p_password_min_length` | `INT` | `30` | Longitud total mínima de la contraseña. |
| `p_password_min_upper` | `INT` | `2` | Cantidad mínima de mayúsculas. |
| `p_password_min_lower` | `INT` | `2` | Cantidad mínima de minúsculas. |
| `p_password_min_digit` | `INT` | `2` | Cantidad mínima de números. |
| `p_password_min_special` | `INT` | `2` | Cantidad mínima de caracteres especiales. |
| `p_contain_username` | `BOOLEAN` | `FALSE` | `FALSE` para evitar que la clave contenga el nombre de usuario. |
| `p_password_valid_max` | `INT` | `120` | Días de vigencia del usuario. |
| `p_password_valid_until` | `INT` | `1` | `1` para aplicar expiración (`VALID UNTIL`), `0` para no aplicar. |

---

## 🛠️ ¿Qué hace el script?

1. **Valida la longitud:** Asegura que la longitud mínima especificada sea suficiente para cubrir las reglas de mayúsculas, minúsculas, números y especiales.
2. **Genera la contraseña:** Selecciona caracteres al azar por cada categoría requerida y rellena el resto hasta cumplir la longitud total.
3. **Mezcla la contraseña:** Aplica `ORDER BY random()` para barajar los caracteres generados.
4. **Valida el usuario en la clave:** Si `p_contain_username` es `FALSE` y la clave contiene el nombre de usuario, reemplaza esa coincidencia.
5. **Calcula la fecha de expiración:** Suma los días de `p_password_valid_max` a la fecha actual si `p_password_valid_until = 1`.
6. **Ejecuta la creación:** Ejecuta `CREATE USER` sanitizando variables con `format()`.
7. **Muestra el resultado:** Imprime la contraseña y los datos del usuario creado a través de `RAISE NOTICE`.

---

## 🚀 Modo de Uso

1. Activa la visibilidad de mensajes en tu cliente SQL (opcional):
   ```sql
   SET client_min_messages = notice;
