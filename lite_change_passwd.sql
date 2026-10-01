DO $$
DECLARE
    -------------------------------------------------------------------------
    -- 1. PARAMETRIZACIÓN: LISTA DE USUARIOS EXISTENTES A ROTAR
    --    >>> AGREGAR AQUÍ LOS NOMBRES DE LOS USUARIOS A ROTAR ENTRE COMILLAS <<<
    -------------------------------------------------------------------------
    p_rotate_users          TEXT[]  := ARRAY['usr_etl_batch']::text[];

    -------------------------------------------------------------------------
    -- 2. PROPIEDADES DE ACCESO Y VIGENCIA A ACTUALIZAR
    -------------------------------------------------------------------------
    p_can_login             BOOLEAN := TRUE;   -- TRUE = Conservar/Asignar LOGIN, FALSE = NOLOGIN
    p_password_valid_until INT     := 1;      -- 1 = Aplicar fecha de expiración, 0 = Sin expiración
    p_password_valid_max   INT     := 90;     -- Días de vigencia desde hoy

    -------------------------------------------------------------------------
    -- 3. POLÍTICA DE COMPLEJIDAD (Alineada estrictamente con credcheck)
    -------------------------------------------------------------------------
    p_password_min_length   INT     := 32;     -- Longitud total de la contraseña
    p_password_min_upper    INT     := 2;      -- Mínimo de caracteres en Mayúscula
    p_password_min_lower    INT     := 2;      -- Mínimo de caracteres en Minúscula
    p_password_min_digit    INT     := 2;      -- Mínimo de Números
    p_password_min_special  INT     := 2;      -- Mínimo de Caracteres Especiales
    p_contain_username      BOOLEAN := FALSE;  -- FALSE = Prohibido que contenga el nombre del usuario

    -------------------------------------------------------------------------
    -- 4. DICCIÓN DE ALFABETOS
    -------------------------------------------------------------------------
    c_lowercase             TEXT := 'abcdefghijklmnopqrstuvwxyz';
    c_uppercase             TEXT := 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    c_digits                TEXT := '0123456789';
    c_specials              TEXT := '!@#$%^&*()_+-=[]{}|;:,.<>?';
    c_all_chars             TEXT;

    -------------------------------------------------------------------------
    -- 5. VARIABLES INTERNAS DE OPERACIÓN (RAM)
    -------------------------------------------------------------------------
    v_user                  TEXT;
    v_password              TEXT;
    v_char                  CHAR(1);
    v_arr_chars             TEXT[];
    v_valid_until_date      TIMESTAMPTZ;
    v_sql                   TEXT;
    v_idx                   INT;
    v_len_all               INT;
    v_remaining_len         INT;
    v_attempts              INT;
    v_valid_pass            BOOLEAN;
    v_role_exists           BOOLEAN;
BEGIN
    -------------------------------------------------------------------------
    -- PROTOCOLO BLINDAJE DE LOGS EN DISCO (Diego & Valeria Protocol)
    -- Mantiene la alerta en PANTALLA (NOTICE) pero la SUPRIME
    -- del archivo postgresql.log en disco (WARNING) por seguridad.
    -------------------------------------------------------------------------
    PERFORM set_config('log_min_messages', 'warning', true);
    PERFORM set_config('client_min_messages', 'notice', true);

    c_all_chars := c_lowercase || c_uppercase || c_digits || c_specials;
    v_len_all   := length(c_all_chars);

    RAISE NOTICE '====================================================================';
    RAISE NOTICE ' DBA SQUAD: VANGUARD BLACK-OPS - ROTACIÓN DE CLAVES (MODO NATIVO)   ';
    RAISE NOTICE '====================================================================';

    IF p_rotate_users IS NULL OR array_length(p_rotate_users, 1) IS NULL THEN
        RAISE NOTICE '[AVISO]: La lista p_rotate_users está vacía. No hay contraseñas que rotar.';
        RETURN;
    END IF;

    FOREACH v_user IN ARRAY p_rotate_users LOOP
        -- Verificar existencia previa en el catálogo global de roles
        SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_user) INTO v_role_exists;

        IF NOT v_role_exists THEN
            RAISE NOTICE '-> OMITIDO: El usuario [%] NO EXISTE en la BD. Si desea crearlo, use el Script de Creación.', v_user;
        ELSE
            -- Generación de contraseña segura nativa
            v_attempts := 0;
            v_valid_pass := FALSE;

            WHILE NOT v_valid_pass AND v_attempts < 100 LOOP
                v_attempts := v_attempts + 1;
                v_arr_chars := ARRAY[]::TEXT[];

                -- Inyección de Minúsculas
                FOR i IN 1..p_password_min_lower LOOP
                    v_arr_chars := array_append(v_arr_chars, substr(c_lowercase, floor(random() * length(c_lowercase) + 1)::INT, 1));
                END LOOP;

                -- Inyección de Mayúsculas
                FOR i IN 1..p_password_min_upper LOOP
                    v_arr_chars := array_append(v_arr_chars, substr(c_uppercase, floor(random() * length(c_uppercase) + 1)::INT, 1));
                END LOOP;

                -- Inyección de Números
                FOR i IN 1..p_password_min_digit LOOP
                    v_arr_chars := array_append(v_arr_chars, substr(c_digits, floor(random() * length(c_digits) + 1)::INT, 1));
                END LOOP;

                -- Inyección de Caracteres Especiales
                FOR i IN 1..p_password_min_special LOOP
                    v_arr_chars := array_append(v_arr_chars, substr(c_specials, floor(random() * length(c_specials) + 1)::INT, 1));
                END LOOP;

                -- Relleno hasta completar la longitud mínima
                v_remaining_len := p_password_min_length - array_length(v_arr_chars, 1);
                FOR i IN 1..v_remaining_len LOOP
                    v_arr_chars := array_append(v_arr_chars, substr(c_all_chars, floor(random() * v_len_all + 1)::INT, 1));
                END LOOP;

                -- Mezcla aleatoria de la estructura (Fisher-Yates Shuffle)
                FOR i IN REVERSE array_length(v_arr_chars, 1)..2 LOOP
                    v_idx := floor(random() * i + 1)::INT;
                    v_char := v_arr_chars[i];
                    v_arr_chars[i] := v_arr_chars[v_idx];
                    v_arr_chars[v_idx] := v_char;
                END LOOP;

                v_password := array_to_string(v_arr_chars, '');

                -- Validación contra el nombre de usuario
                IF p_contain_username = FALSE THEN
                    IF position(lower(v_user) in lower(v_password)) = 0 THEN
                        v_valid_pass := TRUE;
                    END IF;
                ELSE
                    v_valid_pass := TRUE;
                END IF;
            END LOOP;

            IF NOT v_valid_pass THEN
                RAISE EXCEPTION 'ERROR CRÍTICO: No se pudo generar una contraseña válida para la rotación de %', v_user;
            END IF;

            -- Modificación física del ROL e instalación de la nueva contraseña
            v_sql := format('ALTER ROLE %I WITH %s PASSWORD %L', 
                            v_user, 
                            CASE WHEN p_can_login THEN 'LOGIN' ELSE 'NOLOGIN' END, 
                            v_password);

            IF p_password_valid_until = 1 THEN
                v_valid_until_date := clock_timestamp() + (p_password_valid_max || ' days')::INTERVAL;
                v_sql := v_sql || format(' VALID UNTIL %L', v_valid_until_date);
            END IF;

            EXECUTE v_sql;

            -- Despliegue seguro de la nueva credencial al operador en pantalla
            RAISE NOTICE '--------------------------------------------------------------------';
            RAISE NOTICE '[ROTACIÓN EXITOSA] USUARIO: %', v_user;
            RAISE NOTICE 'NUEVO PASSWORD GENERADO: %', v_password;
            RAISE NOTICE 'ESTADO DE ACCESO:        %', CASE WHEN p_can_login THEN 'LOGIN ACTIVADO' ELSE 'NOLOGIN' END;
            IF p_password_valid_until = 1 THEN
                RAISE NOTICE 'FECHA DE VIGENCIA:       % días (Expira: %)', p_password_valid_max, to_char(v_valid_until_date, 'YYYY-MM-DD HH24:MI:SS');
            ELSE
                RAISE NOTICE 'FECHA DE VIGENCIA:       SIN FECHA LÍMITE';
            END IF;
        END IF;
    END LOOP;

    RAISE NOTICE '====================================================================';
    RAISE NOTICE ' PROCESO FINALIZADO: NINGUNA CREDENCIAL FUE PERSISTIDA EN EL LOG.';
    RAISE NOTICE '====================================================================';
END $$;
