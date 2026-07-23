# pg_createuser
 
### **¿Qué es?**

Es una herramienta en `PL/pgSQL` para PostgreSQL (v10+) que automatiza la **creación masiva de usuarios, la renovación de accesos y la auditoría de contraseñas** sin detener procesos ni poner en riesgo la base de datos.

 

### **¿En qué te ayuda?**

* **Cero interrupciones:** Si un usuario de la lista falla o no cumple las reglas, el script lo omite, lanza una alerta y **continúa procesando a los demás**.
* **Evita cambios innecesarios:** Revisa los hashes reales (`SCRAM-SHA-256` y `MD5`). Si el usuario ya existe y su clave es la misma, **no la sobrescribe ni ensucia el historial**.
* **Limpio y automático:** Instala la extensión `pgcrypto` de forma temporal si la necesita y **la borra sola al terminar**.
* **Renovación rápida:** Permite extender la vigencia (`VALID UNTIL`) de varios usuarios a la vez sin modificar sus contraseñas.
* **Control total:** Administra permisos de `LOGIN` / `NOLOGIN`, contraseñas manuales o generadas al azar cumpliendo políticas **`credcheck`**.
---

## 🛠️ Cómo usarlo (Parámetros Clave)

Modifica las variables al inicio del bloque `DECLARE`:

```sql
-- Listado de usuarios a procesar
v_usernames := ARRAY['jose', 'maria', 'roberto'];

-- Contraseñas manuales (deja '' para generar una aleatoria Credcheck-Compliant)
v_custom_passwords := ARRAY['jose123', 'Passwd55#B', ''];

-- Opciones de operación
p_only_renew_validity := FALSE;  -- TRUE = Solo extienda vigencia, NO toca contraseñas
p_can_login           := TRUE;   -- TRUE = LOGIN | FALSE = NOLOGIN
p_password_encryption := 'scram-sha-256'; -- 'scram-sha-256' o 'md5'

-- Políticas de complejidad (credcheck)
p_password_min_length := 32;     -- Longitud mínima total
p_password_valid_max   := 90;     -- Días de vigencia a sumar

```

---

## 🖥️ Muestra de Resultados (`RAISE NOTICE`)

Al ejecutar el script en consola `psql`, pgAdmin o DBeaver, obtendrás un reporte claro por cada usuario:

```text
SET
NOTICE:  ================================================================
NOTICE:  ALERTA DE SEGURIDAD: Usuario "jose" OMITIDO.
NOTICE:  MOTIVO: La contraseña manual ingresada no cumple con las políticas Credcheck.
NOTICE:  ACCION: Se salta este usuario y se continua con el resto del lote.
NOTICE:  ================================================================
NOTICE:  ================================================================
NOTICE:  AUDITORÍA: El usuario "maria" ya existe en el sistema.
NOTICE:  ALERTA:    La contraseña ingresada ES LA MISMA almacenada actualmente (Hash: SCRAM-SHA-256).
NOTICE:  ACCION:    Se omite la actualización de credenciales pero se aplica permiso LOGIN.
NOTICE:  ================================================================
NOTICE:  ================================================================
NOTICE:  USUARIO CREADO EXITOSAMENTE (CREDCHECK COMPLIANT)
NOTICE:  ================================================================
NOTICE:  Usuario:              roberto
NOTICE:  Contraseña Aplicada:  k9#mP2$xL1!vR8%qT0&wA7@bC3*dE4#z
NOTICE:  Tipo Contraseña:      GENERADA ALEATORIA
NOTICE:  Estado Login:         LOGIN
NOTICE:  Válido Hasta:         2026-10-21
NOTICE:  ================================================================
DO

```
