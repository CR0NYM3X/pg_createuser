DO $$
DECLARE
    -------------------------------------------------------------------------
    -- 1. PARAMETROS OPERATIVOS DEL CLIENTE
    -------------------------------------------------------------------------
    p_users                 TEXT[]  := ARRAY['usr_app_backend', 'usr_etl_batch', 'usr_analista_01'];
    p_can_login             BOOLEAN := TRUE;   -- TRUE = LOGIN, FALSE = NOLOGIN
    p_password_valid_until  INT     := 1;      -- 1 = Aplicar VALID UNTIL, 0 = Sin expiracion
    p_password_valid_max    INT     := 90;     -- Dias de vigencia (default 90)

    -------------------------------------------------------------------------
    -- 2. REGLAS DE COMPLEJIDAD (Alineadas con credcheck)
    -------------------------------------------------------------------------
    p_password_min_length   INT     := 32;     -- credcheck.password_min_length
    p_password_min_upper    INT     := 2;      -- credcheck.password_min_upper
    p_password_min_lower    INT     := 2;      -- credcheck.password_min_lower
    p_password_min_digit    INT     := 2;      -- credcheck.password_min_digit
    p_password_min_special  INT     := 2;      -- credcheck.password_min_special
    p_contain_username      BOOLEAN := FALSE;  -- FALSE = Prohibido contener username

    -------------------------------------------------------------------------
    -- 3. ALFABETOS DE CARACTERES
    -------------------------------------------------------------------------
    c_lowercase             TEXT := 'abcdefghijklmnopqrstuvwxyz';
    c_uppercase             TEXT := 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    c_digits                TEXT := '0123456789';
    c_specials              TEXT := '!@#$%^&*()_+-=[]{}|;:,.<>?';
    c_all_chars             TEXT;

    -------------------------------------------------------------------------
    -- 4. VARIABLES INTERNAS DE TRABAJO
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
BEGIN
    -------------------------------------------------------------------------
    -- PROTOCOLO BLINDAJE DE LOGS EN DISCO (Diego & Valeria Protocol)
    -- Fuerza a que las alertas salgan en la PANTALLA del cliente (NOTICE)
    -- pero las SUPRIME del archivo postgresql.log en disco (WARNING).
    -------------------------------------------------------------------------
    PERFORM set_config('log_min_messages', 'warning', true);
    PERFORM set_config('client_min_messages', 'notice', true);

    c_all_chars := c_lowercase || c_uppercase || c_digits || c_specials;
    v_len_all   := length(c_all_chars);

    RAISE NOTICE '====================================================================';
    RAISE NOTICE '  DBA SQUAD: VANGUARD BLACK-OPS - CREACION SEGURA DE CREDENCIALES   ';
    RAISE NOTICE '====================================================================';

    FOREACH v_user IN ARRAY p_users LOOP
        v_attempts := 0;
        v_valid_pass := FALSE;

        -- Bucle de generacion garantizada
        WHILE NOT v_valid_pass AND v_attempts < 100 LOOP
            v_attempts := v_attempts + 1;
            v_arr_chars := ARRAY[]::TEXT[];

            -- A. Inyeccion obligatoria de minimos por categoria (credcheck compliance)
            FOR i IN 1..p_password_min_lower LOOP
                v_arr_chars := array_append(v_arr_chars, substr(c_lowercase, floor(random() * length(c_lowercase) + 1)::INT, 1));
            END LOOP;

            FOR i IN 1..p_password_min_upper LOOP
                v_arr_chars := array_append(v_arr_chars, substr(c_uppercase, floor(random() * length(c_uppercase) + 1)::INT, 1));
            END LOOP;

            FOR i IN 1..p_password_min_digit LOOP
                v_arr_chars := array_append(v_arr_chars, substr(c_digits, floor(random() * length(c_digits) + 1)::INT, 1));
            END LOOP;

            FOR i IN 1..p_password_min_special LOOP
                v_arr_chars := array_append(v_arr_chars, substr(c_specials, floor(random() * length(c_specials) + 1)::INT, 1));
            END LOOP;

            -- B. Relleno de caracteres aleatorios hasta p_password_min_length
            v_remaining_len := p_password_min_length - array_length(v_arr_chars, 1);
            FOR i IN 1..v_remaining_len LOOP
                v_arr_chars := array_append(v_arr_chars, substr(c_all_chars, floor(random() * v_len_all + 1)::INT, 1));
            END LOOP;

            -- C. Algoritmo de Mezcla Fisher-Yates (Shuffling de posiciones)
            FOR i IN REVERSE array_length(v_arr_chars, 1)..2 LOOP
                v_idx := floor(random() * i + 1)::INT;
                v_char := v_arr_chars[i];
                v_arr_chars[i] := v_arr_chars[v_idx];
                v_arr_chars[v_idx] := v_char;
            END LOOP;

            v_password := array_to_string(v_arr_chars, '');

            -- D. Validacion de contencion de username
            IF p_contain_username = FALSE THEN
                IF position(lower(v_user) in lower(v_password)) = 0 THEN
                    v_valid_pass := TRUE;
                END IF;
            ELSE
                v_valid_pass := TRUE;
            END IF;
        END LOOP;

        IF NOT v_valid_pass THEN
            RAISE EXCEPTION 'Error critico: No se pudo generar una contraseña valida para % tras 100 intentos.', v_user;
        END IF;

        -- VERIFICACION / CREACION DEL ROL
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_user) THEN
            EXECUTE format('CREATE ROLE %I', v_user);
            RAISE NOTICE '-> Rol [%] no existia. Creado exitosamente.', v_user;
        ELSE
            RAISE NOTICE '-> Rol [%] detectado. Actualizando credenciales...', v_user;
        END IF;

        -- CONSTRUCCION DINAMICA DEL DDL (Se ejecuta dentro de la memoria del motor)
        v_sql := format('ALTER ROLE %I WITH %s PASSWORD %L', 
                        v_user, 
                        CASE WHEN p_can_login THEN 'LOGIN' ELSE 'NOLOGIN' END, 
                        v_password);

        IF p_password_valid_until = 1 THEN
            v_valid_until_date := clock_timestamp() + (p_password_valid_max || ' days')::INTERVAL;
            v_sql := v_sql || format(' VALID UNTIL %L', v_valid_until_date);
        END IF;

        -- EJECUCION
        EXECUTE v_sql;

        -- SALIDA EXCLUSIVA A LA TERMINAL DEL DBA (NO SE GRABA EN DISCO)
        RAISE NOTICE '--------------------------------------------------------------------';
        RAISE NOTICE 'USUARIO:    %', v_user;
        RAISE NOTICE 'PASSWORD:   %', v_password;
        RAISE NOTICE 'ESTADO:     %', CASE WHEN p_can_login THEN 'LOGIN ACTIVADO' ELSE 'NOLOGIN (DESACTIVADO)' END;
        IF p_password_valid_until = 1 THEN
            RAISE NOTICE 'EXPIRACION: % dias (Fecha limite: %)', p_password_valid_max, to_char(v_valid_until_date, 'YYYY-MM-DD HH24:MI:SS');
        ELSE
            RAISE NOTICE 'EXPIRACION: SIN FECHA LÍMITE (INDEFINIDO)';
        END IF;
    END LOOP;

    RAISE NOTICE '====================================================================';
    RAISE NOTICE ' PROCESO FINALIZADO: NINGUNA CONTRASEÑA FUE EXPUESTA EN EL LOG.';
    RAISE NOTICE '====================================================================';
END $$;
