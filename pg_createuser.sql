-- ============================================================================
-- DBA SQUAD: VANGUARD BLACK-OPS
-- AUTOMATIZACIÓN DE CREACIÓN/ACTUALIZACIÓN DE USUARIOS CON VERIFICACIÓN CRIPTOGRÁFICA
-- ============================================================================
-- Mapeo: Credcheck compliant | Multi-User Resilient | SCRAM-SHA-256 & MD5 Inspector
-- ============================================================================

DO $$ 
DECLARE
    -- ========================================================================
    -- 1. CONFIGURACIÓN DE USUARIOS, CONTRASEÑAS Y ENCRIPTACIÓN DE SESIÓN
    -- ========================================================================
    v_usernames                     TEXT[]  := ARRAY['jose'   , 'maria'     , 'roberto','pepe'];
    v_custom_passwords              TEXT[]  := ARRAY['jose123', 'passwd55#B', ''       ,'weJF79,*ZtI+4)KJ3.9bH}2)|;rwOY[P123c']; 
    -- NOTA: Si v_custom_passwords tiene solo 1 elemento, se aplica a TODOS los usuarios.
    -- Si el elemento viene vacío '', se generará una clave aleatoria para ese usuario.

    p_password_encryption           TEXT    := 'scram-sha-256'; -- 'scram-sha-256' o 'md5'
    p_validate_custom_passwords     BOOLEAN := TRUE;            -- Validar reglas de políticas en claves manuales
    p_only_renew_validity           BOOLEAN := FALSE;           -- TRUE = SOLO renueva la vigencia (VALID UNTIL), NO toca la contraseña
    p_can_login                     BOOLEAN := TRUE;            -- TRUE = LOGIN, FALSE = NOLOGIN
    p_show_password                 BOOLEAN := TRUE;            -- TRUE = Muestra la contraseña en el NOTICE, FALSE = Enmascara la clave

    -- ========================================================================
    -- 2. MATRIZ DE POLÍTICAS CREDCHECK
    -- ========================================================================
    p_password_min_length           INT     := 32;     -- credcheck.password_min_length
    p_password_min_upper            INT     := 2;      -- credcheck.password_min_upper
    p_password_min_lower            INT     := 2;      -- credcheck.password_min_lower
    p_password_min_digit            INT     := 2;      -- credcheck.password_min_digit
    p_password_min_special          INT     := 2;      -- credcheck.password_min_special
    p_contain_username              BOOLEAN := FALSE;  -- FALSE = Prohibido contener username
    p_password_valid_max            INT     := 90;     -- Días de vigencia
    p_password_valid_until          INT     := 1;      -- 1 = Aplicar VALID UNTIL

    -- Alfabetos de caracteres
    c_lowercase                     TEXT := 'abcdefghijklmnopqrstuvwxyz';
    c_uppercase                     TEXT := 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    c_digits                        TEXT := '0123456789';
    c_specials                      TEXT := '!@#$%^&*()_+-=[]{}|;:,.<>?';
    c_all_chars                     TEXT;

    -- Variables de control interno
    v_created_pgcrypto              BOOLEAN := FALSE;
    v_pgcrypto_was_installed        BOOLEAN := FALSE;
    v_curr_user                     TEXT;
    v_raw_pass                      TEXT;
    v_generated_pass                TEXT;
    v_pass_display                  TEXT;
    v_expiration_date               TEXT;
    v_is_custom                     BOOLEAN;
    v_user_exists                   BOOLEAN;
    v_stored_hash                   TEXT;
    v_is_same_password              BOOLEAN;
    v_hash_type                     TEXT;
    v_login_clause                  TEXT;
    v_sql                           TEXT;
    v_i                             INT;
    v_sum_required                  INT;

    -- Variables para verificación criptográfica manual de hashes
    v_parts                         TEXT[];
    v_iters_salt                    TEXT[];
    v_keys                          TEXT[];
    v_iterations                    INT;
    v_salt_bin                      BYTEA;
    v_stored_key_db                 TEXT;
    v_server_key_db                 TEXT;
    v_salted_pw                     BYTEA;
    v_client_key                    BYTEA;
    v_server_key_calc               BYTEA;
    v_stored_key_calc               BYTEA;
    v_u                             BYTEA;
    v_t                             BYTEA;
    v_j                             INT;
    v_k                             INT;

    -- Variables de validación de contraseña manual
    v_count_upper                   INT;
    v_count_lower                   INT;
    v_count_digit                   INT;
    v_count_spec                    INT;
BEGIN
    SET client_min_messages = notice;

    -- Cláusula de Login / No Login
    IF p_can_login THEN
        v_login_clause := 'LOGIN';
    ELSE
        v_login_clause := 'NOLOGIN';
    END IF;

    -- ------------------------------------------------------------------------
    -- PASO A: GESTIÓN DE EXTENSIÓN PGCRYPTO (INSTALACIÓN EFÍMERA)
    -- ------------------------------------------------------------------------
    SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto') INTO v_pgcrypto_was_installed;

    IF NOT v_pgcrypto_was_installed THEN
        EXECUTE 'CREATE EXTENSION IF NOT EXISTS pgcrypto';
        v_created_pgcrypto := TRUE;
    END IF;

    -- ------------------------------------------------------------------------
    -- PASO B: CONFIGURACIÓN DE ENCRIPTACIÓN A NIVEL SESIÓN
    -- ------------------------------------------------------------------------
    EXECUTE format('SET LOCAL password_encryption = %L', p_password_encryption);

    -- Ajuste de consistencia de longitud mínima
    v_sum_required := p_password_min_upper + p_password_min_lower + p_password_min_digit + p_password_min_special;
    IF p_password_min_length < v_sum_required THEN
        p_password_min_length := v_sum_required;
    END IF;
    c_all_chars := c_lowercase || c_uppercase || c_digits || c_specials;

    -- Cálculo de expiración global
    IF p_password_valid_until = 1 THEN
        v_expiration_date := (current_date + (p_password_valid_max || ' days')::interval)::date::text;
    ELSE
        v_expiration_date := NULL;
    END IF;

    -- ------------------------------------------------------------------------
    -- PASO C: BUCLE PRINCIPAL DE PROCESAMIENTO DE USUARIOS CON RESILIENCIA
    -- ------------------------------------------------------------------------
    FOR v_i IN 1..coalesce(array_length(v_usernames, 1), 0) LOOP
        -- BLOQUE SUB-TRANSACCIONAL DE RESILIENCIA (Evita que el fallo de un usuario detenga el proceso)
        BEGIN
            v_curr_user := v_usernames[v_i];
            v_raw_pass  := NULL;
            v_is_custom := FALSE;

            -- Si no es solo renovación de vigencia, procesamos contraseñas
            IF NOT p_only_renew_validity THEN
                -- Determinación de contraseña manual vs aleatoria
                IF array_length(v_custom_passwords, 1) = 1 THEN
                    v_raw_pass := v_custom_passwords[1];
                ELSIF v_i <= coalesce(array_length(v_custom_passwords, 1), 0) THEN
                    v_raw_pass := v_custom_passwords[v_i];
                END IF;

                IF v_raw_pass IS NOT NULL AND trim(v_raw_pass) <> '' THEN
                    v_is_custom := TRUE;
                    v_generated_pass := v_raw_pass;

                    -- Validar políticas Credcheck en contraseña manual si está activado
                    IF p_validate_custom_passwords THEN
                        v_count_upper := length(regexp_replace(v_generated_pass, '[^A-Z]', '', 'g'));
                        v_count_lower := length(regexp_replace(v_generated_pass, '[^a-z]', '', 'g'));
                        v_count_digit := length(regexp_replace(v_generated_pass, '[^0-9]', '', 'g'));
                        v_count_spec  := length(v_generated_pass) - (v_count_upper + v_count_lower + v_count_digit);

                        IF length(v_generated_pass) < p_password_min_length OR
                           v_count_upper < p_password_min_upper OR
                           v_count_lower < p_password_min_lower OR
                           v_count_digit < p_password_min_digit OR
                           v_count_spec  < p_password_min_special OR
                           (NOT p_contain_username AND position(lower(v_curr_user) IN lower(v_generated_pass)) > 0) THEN
                            
                            -- NOTIFICACIÓN DE OMISIÓN Y SALTO AL SIGUIENTE USUARIO
                            RAISE NOTICE '================================================================';
                            RAISE NOTICE 'ALERTA DE SEGURIDAD: Usuario "%" OMITIDO.', v_curr_user;
                            RAISE NOTICE 'MOTIVO: La contraseña manual ingresada no cumple con las políticas Credcheck.';
                            RAISE NOTICE 'ACCION: Se salta este usuario y se continua con el resto del lote.';
                            RAISE NOTICE '================================================================';
                            
                            -- Forzamos la salida de este bloque iterativo para continuar con el siguiente
                            CONTINUE;
                        END IF;
                    END IF;
                ELSE
                    -- Generación aleatoria Credcheck Compliant
                    v_generated_pass := '';
                    FOR v_j IN 1..p_password_min_lower LOOP
                        v_generated_pass := v_generated_pass || substr(c_lowercase, floor(random() * length(c_lowercase) + 1)::int, 1);
                    END LOOP;
                    FOR v_j IN 1..p_password_min_upper LOOP
                        v_generated_pass := v_generated_pass || substr(c_uppercase, floor(random() * length(c_uppercase) + 1)::int, 1);
                    END LOOP;
                    FOR v_j IN 1..p_password_min_digit LOOP
                        v_generated_pass := v_generated_pass || substr(c_digits, floor(random() * length(c_digits) + 1)::int, 1);
                    END LOOP;
                    FOR v_j IN 1..p_password_min_special LOOP
                        v_generated_pass := v_generated_pass || substr(c_specials, floor(random() * length(c_specials) + 1)::int, 1);
                    END LOOP;
                    WHILE length(v_generated_pass) < p_password_min_length LOOP
                        v_generated_pass := v_generated_pass || substr(c_all_chars, floor(random() * length(c_all_chars) + 1)::int, 1);
                    END LOOP;

                    -- Shuffle de la contraseña aleatoria
                    SELECT string_agg(ch, '') INTO v_generated_pass
                    FROM (SELECT regexp_split_to_table(v_generated_pass, '') AS ch ORDER BY random()) AS shuffled;

                    IF NOT p_contain_username AND position(lower(v_curr_user) IN lower(v_generated_pass)) > 0 THEN
                        v_generated_pass := replace(lower(v_generated_pass), lower(v_curr_user), 'xK9#');
                    END IF;
                END IF;
            END IF;

            -- Determinación de la contraseña visible según el parámetro p_show_password
            IF p_show_password THEN
                v_pass_display := v_generated_pass;
            ELSE
                v_pass_display := '******** [OCULTA POR CONFIGURACIÓN]';
            END IF;

            -- ----------------------------------------------------------------
            -- PASO D: AUDITORÍA DE EXISTENCIA DE USUARIO Y HASH EN CATÁLOGO
            -- ----------------------------------------------------------------
            SELECT EXISTS(SELECT 1 FROM pg_authid WHERE rolname = v_curr_user) INTO v_user_exists;
            v_is_same_password := FALSE;
            v_hash_type := 'DESCONOCIDO';

            IF v_user_exists AND NOT p_only_renew_validity THEN
                SELECT rolpassword FROM pg_authid WHERE rolname = v_curr_user INTO v_stored_hash;

                IF v_stored_hash IS NOT NULL AND v_is_custom THEN
                    -- Verificación Criptográfica MD5
                    IF v_stored_hash LIKE 'md5%' THEN
                        v_hash_type := 'MD5';
                        IF ('md5' || pg_catalog.md5(v_generated_pass || v_curr_user)) = v_stored_hash THEN
                            v_is_same_password := TRUE;
                        END IF;

                    -- Verificación Criptográfica SCRAM-SHA-256
                    ELSIF v_stored_hash LIKE 'SCRAM-SHA-256$%' THEN
                        v_hash_type := 'SCRAM-SHA-256';
                        BEGIN
                            v_parts      := string_to_array(v_stored_hash, '$');
                            v_iters_salt := string_to_array(v_parts[2], ':');
                            v_keys       := string_to_array(v_parts[3], ':');

                            v_iterations    := v_iters_salt[1]::integer;
                            v_salt_bin      := decode(v_iters_salt[2], 'base64');
                            v_stored_key_db := v_keys[1];
                            v_server_key_db := v_keys[2];

                            v_u := public.hmac(v_salt_bin || E'\\x00000001'::bytea, v_generated_pass::bytea, 'sha256');
                            v_t := v_u;
                            FOR v_j IN 2..v_iterations LOOP
                                v_u := public.hmac(v_u, v_generated_pass::bytea, 'sha256');
                                FOR v_k IN 0..31 LOOP
                                    v_t := set_byte(v_t, v_k, get_byte(v_t, v_k) # get_byte(v_u, v_k));
                                END LOOP;
                            END LOOP;
                            v_salted_pw := v_t;

                            v_client_key      := public.hmac('Client Key'::bytea, v_salted_pw, 'sha256');
                            v_stored_key_calc := public.digest(v_client_key, 'sha256');
                            v_server_key_calc := public.hmac('Server Key'::bytea, v_salted_pw, 'sha256');

                            IF (v_stored_key_db = regexp_replace(encode(v_stored_key_calc, 'base64'), E'\\s', '', 'g')) AND
                               (v_server_key_db = regexp_replace(encode(v_server_key_calc, 'base64'), E'\\s', '', 'g')) THEN
                                v_is_same_password := TRUE;
                            END IF;
                        EXCEPTION WHEN OTHERS THEN
                            v_is_same_password := FALSE;
                        END;
                    END IF;
                END IF;
            END IF;

            -- ----------------------------------------------------------------
            -- PASO E: EJECUCIÓN DE DDL (CREATE / ALTER USER)
            -- ----------------------------------------------------------------
            IF v_user_exists THEN
                IF p_only_renew_validity THEN
                    -- MODO SOLO RENOVACIÓN DE VIGENCIA
                    IF v_expiration_date IS NOT NULL THEN
                        v_sql := format('ALTER USER %I %s VALID UNTIL %L', v_curr_user, v_login_clause, v_expiration_date);
                    ELSE
                        v_sql := format('ALTER USER %I %s', v_curr_user, v_login_clause);
                    END IF;
                    EXECUTE v_sql;

                    RAISE NOTICE '================================================================';
                    RAISE NOTICE 'VIGENCIA RENOVADA EXITOSAMENTE (CONTRASEÑA NO TOCADA)';
                    RAISE NOTICE '================================================================';
                    RAISE NOTICE 'Usuario:              %', v_curr_user;
                    RAISE NOTICE 'Estado Login:         %', v_login_clause;
                    RAISE NOTICE 'Nueva Fecha Validez:  %', COALESCE(v_expiration_date, 'SIN EXPIRACIÓN');
                    RAISE NOTICE '================================================================';
                ELSIF v_is_same_password THEN
                    -- MODO ACTUALIZACIÓN - MISMA CONTRASEÑA DETECTADA
                    -- Aun si la clave es la misma, actualizamos permiso de LOGIN si corresponde
                    EXECUTE format('ALTER USER %I %s', v_curr_user, v_login_clause);

                    RAISE NOTICE '================================================================';
                    RAISE NOTICE 'AUDITORÍA: El usuario "%" ya existe en el sistema.', v_curr_user;
                    RAISE NOTICE 'ALERTA:    La contraseña ingresada ES LA MISMA almacenada actualmente (Hash: %).', v_hash_type;
                    RAISE NOTICE 'ACCION:    Se omite la actualización de credenciales pero se aplica permiso %.', v_login_clause;
                    RAISE NOTICE '================================================================';
                ELSE
                    -- MODO ACTUALIZACIÓN COMPLETA
                    IF v_expiration_date IS NOT NULL THEN
                        v_sql := format('ALTER USER %I %s VALID UNTIL %L PASSWORD %L', v_curr_user, v_login_clause, v_expiration_date, v_generated_pass);
                    ELSE
                        v_sql := format('ALTER USER %I %s PASSWORD %L', v_curr_user, v_login_clause, v_generated_pass);
                    END IF;
                    EXECUTE v_sql;

                    RAISE NOTICE '================================================================';
                    RAISE NOTICE 'USUARIO ACTUALIZADO EXITOSAMENTE';
                    RAISE NOTICE '================================================================';
                    RAISE NOTICE 'Usuario:              %', v_curr_user;                    
                    RAISE NOTICE 'Estado Login:         %', v_login_clause;
                    RAISE NOTICE 'Válido Hasta:         %', COALESCE(v_expiration_date, 'SIN EXPIRACIÓN');
                    RAISE NOTICE 'Tipo Contraseña:      %', CASE WHEN v_is_custom THEN 'MANUAL' ELSE 'GENERADA ALEATORIA' END;
                    RAISE NOTICE 'Encriptación Sesión:  %', p_password_encryption;
                    RAISE NOTICE 'Contraseña Aplicada:  %', v_pass_display;
                    RAISE NOTICE '================================================================';
                END IF;
            ELSE
                -- SI NO EXISTE Y SE SOLICITÓ SOLO RENOVAR, SE AVISA QUE NO EXISTE
                IF p_only_renew_validity THEN
                    RAISE NOTICE '================================================================';
                    RAISE NOTICE 'ALERTA: No se puede renovar vigencia. El usuario "%" NO existe.', v_curr_user;
                    RAISE NOTICE '================================================================';
                ELSE
                    -- MODO CREACIÓN NUEVO USUARIO
                    IF v_expiration_date IS NOT NULL THEN
                        v_sql := format('CREATE USER %I %s VALID UNTIL %L PASSWORD %L', v_curr_user, v_login_clause, v_expiration_date, v_generated_pass);
                    ELSE
                        v_sql := format('CREATE USER %I %s PASSWORD %L', v_curr_user, v_login_clause, v_generated_pass);
                    END IF;
                    EXECUTE v_sql;

                    RAISE NOTICE '================================================================';
                    RAISE NOTICE 'USUARIO CREADO EXITOSAMENTE (CREDCHECK COMPLIANT)';
                    RAISE NOTICE '================================================================';
                    RAISE NOTICE 'Usuario:              %', v_curr_user;                    
                    RAISE NOTICE 'Estado Login:         %', v_login_clause;                    
                    RAISE NOTICE 'Válido Hasta:         %', COALESCE(v_expiration_date, 'SIN EXPIRACIÓN');
                    RAISE NOTICE 'Tipo Contraseña:      %', CASE WHEN v_is_custom THEN 'MANUAL' ELSE 'GENERADA ALEATORIA' END;
                    RAISE NOTICE 'Encriptación Sesión:  %', p_password_encryption;
                    RAISE NOTICE 'Contraseña Aplicada:  %', v_pass_display;
                    RAISE NOTICE '================================================================';
                END IF;
            END IF;

        EXCEPTION
            WHEN OTHERS THEN
                -- CAPTURA DE ERROR INDIVIDUAL: Reporta la falla del usuario y continúa con los demás
                RAISE NOTICE '================================================================';
                RAISE NOTICE 'ERROR EN PROCESAMIENTO DE USUARIO "%": %', v_curr_user, SQLERRM;
                RAISE NOTICE 'ACCION: Se omite a este usuario y se continua with el lote.';
                RAISE NOTICE '================================================================';
        END;

    END LOOP;

    -- ------------------------------------------------------------------------
    -- PASO F: LIMPIEZA AUTOMÁTICA DE EXTENSIONES EFÍMERAS (AL FINALIZAR TODO EL LOTE)
    -- ------------------------------------------------------------------------
    IF v_created_pgcrypto THEN
        EXECUTE 'DROP EXTENSION IF EXISTS pgcrypto';
    END IF;

EXCEPTION
    WHEN OTHERS THEN
        -- Garantizar la eliminación de pgcrypto si ocurrió un fallo crítico general
        IF v_created_pgcrypto THEN
            EXECUTE 'DROP EXTENSION IF EXISTS pgcrypto';
        END IF;
        RAISE EXCEPTION 'ERROR CRÍTICO EN PROCESO DE APROVISIONAMIENTO: %', SQLERRM;
END $$;
