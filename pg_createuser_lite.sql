DO $$
DECLARE
    -------------------------------------------------------------------------
    -- 1. CARRIL DE CREACIÓN: USUARIOS NUEVOS
    -------------------------------------------------------------------------
    p_create_users          TEXT[]  := ARRAY['usr_app_backend', 'usr_analista_01']::text[]; -- Solo se crearan si NO existen en pg_roles

    -------------------------------------------------------------------------
    -- 2. CARRIL DE ROTACIÓN: USUARIOS EXISTENTES
    -------------------------------------------------------------------------
    p_rotate_existing       BOOLEAN := TRUE;                                -- TRUE = Activar rotacion; FALSE = Bloquear rotacion
    p_rotate_users          TEXT[]  := ARRAY['usr_etl_batch']::text[];              -- Solo se rotaran si existen y p_rotate_existing = TRUE

    -------------------------------------------------------------------------
    -- 3. PROPIEDADES DE ACCESO Y VIGENCIA (Aplica a Creación y Rotación)
    -------------------------------------------------------------------------
    p_can_login             BOOLEAN := TRUE;   -- TRUE = LOGIN, FALSE = NOLOGIN
    p_password_valid_until  INT     := 1;      -- 1 = Aplicar VALID UNTIL, 0 = Sin expiracion
    p_password_valid_max    INT     := 90;     -- Dias de vigencia (default 90)

    -------------------------------------------------------------------------
    -- 4. REGLAS DE COMPLEJIDAD (Alineadas estrictamente con credcheck)
    -------------------------------------------------------------------------
    p_password_min_length   INT     := 32;     -- credcheck.password_min_length
    p_password_min_upper    INT     := 2;      -- credcheck.password_min_upper
    p_password_min_lower    INT     := 2;      -- credcheck.password_min_lower
    p_password_min_digit    INT     := 2;      -- credcheck.password_min_digit
    p_password_min_special  INT     := 2;      -- credcheck.password_min_special
    p_contain_username      BOOLEAN := FALSE;  -- FALSE = Prohibido contener username

    -------------------------------------------------------------------------
    -- 5. ALFABETOS DE CARACTERES
    -------------------------------------------------------------------------
    c_lowercase             TEXT := 'abcdefghijklmnopqrstuvwxyz';
    c_uppercase             TEXT := 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    c_digits                TEXT := '0123456789';
    c_specials              TEXT := '!@#$%^&*()_+-=[]{}|;:,.<>?';
    c_all_chars             TEXT;

    -------------------------------------------------------------------------
    -- 6. VARIABLES INTERNAS DE TRABAJO
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
    -- Fuerza a que las alertas salgan en la PANTALLA del cliente (NOTICE)
    -- pero las SUPRIME del archivo postgresql.log en disco (WARNING).
    -------------------------------------------------------------------------
    PERFORM set_config('log_min_messages', 'warning', true);
    PERFORM set_config('client_min_messages', 'notice', true);

    c_all_chars := c_lowercase || c_uppercase || c_digits || c_specials;
    v_len_all   := length(c_all_chars);

    RAISE NOTICE '====================================================================';
    RAISE NOTICE '  DBA SQUAD: VANGUARD BLACK-OPS - MÓDULO DE CREDENCIALES HERMÉTICAS ';
    RAISE NOTICE '====================================================================';

    -------------------------------------------------------------------------
    -- ETAPA 1: PROCESAMIENTO DE CREACIÓN DE USUARIOS NUEVOS
    -------------------------------------------------------------------------
    IF p_create_users IS NOT NULL AND array_length(p_create_users, 1) > 0 THEN
        RAISE NOTICE '>>> ETAPA 1: PROCESANDO CREACION DE USUARIOS NUEVOS...';
        
        FOREACH v_user IN ARRAY p_create_users LOOP
            SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_user) INTO v_role_exists;

            IF v_role_exists THEN
                RAISE NOTICE '-> OMITIDO EN CREACION: El rol [%] ya existe. Si desea rotar su clave, use p_rotate_users.', v_user;
            ELSE
                -- Generación de contraseña segura (credcheck compliance)
                v_attempts := 0;
                v_valid_pass := FALSE;

                WHILE NOT v_valid_pass AND v_attempts < 100 LOOP
                    v_attempts := v_attempts + 1;
                    v_arr_chars := ARRAY[]::TEXT[];

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

                    v_remaining_len := p_password_min_length - array_length(v_arr_chars, 1);
                    FOR i IN 1..v_remaining_len LOOP
                        v_arr_chars := array_append(v_arr_chars, substr(c_all_chars, floor(random() * v_len_all + 1)::INT, 1));
                    END LOOP;

                    FOR i IN REVERSE array_length(v_arr_chars, 1)..2 LOOP
                        v_idx := floor(random() * i + 1)::INT;
                        v_char := v_arr_chars[i];
                        v_arr_chars[i] := v_arr_chars[v_idx];
                        v_arr_chars[v_idx] := v_char;
                    END LOOP;

                    v_password := array_to_string(v_arr_chars, '');

                    IF p_contain_username = FALSE THEN
                        IF position(lower(v_user) in lower(v_password)) = 0 THEN
                            v_valid_pass := TRUE;
                        END IF;
                    ELSE
                        v_valid_pass := TRUE;
                    END IF;
                END LOOP;

                IF NOT v_valid_pass THEN
                    RAISE EXCEPTION 'Error critico: No se pudo generar una contraseña valida para %', v_user;
                END IF;

                -- Creación física e instalación de credenciales
                EXECUTE format('CREATE ROLE %I', v_user);
                
                v_sql := format('ALTER ROLE %I WITH %s PASSWORD %L', 
                                v_user, 
                                CASE WHEN p_can_login THEN 'LOGIN' ELSE 'NOLOGIN' END, 
                                v_password);

                IF p_password_valid_until = 1 THEN
                    v_valid_until_date := clock_timestamp() + (p_password_valid_max || ' days')::INTERVAL;
                    v_sql := v_sql || format(' VALID UNTIL %L', v_valid_until_date);
                END IF;

                EXECUTE v_sql;

                RAISE NOTICE '--------------------------------------------------------------------';
                RAISE NOTICE '[CREADO EXITOSAMENTE] USUARIO: %', v_user;
                RAISE NOTICE 'PASSWORD:   %', v_password;
                RAISE NOTICE 'ESTADO:     %', CASE WHEN p_can_login THEN 'LOGIN ACTIVADO' ELSE 'NOLOGIN (DESACTIVADO)' END;
                IF p_password_valid_until = 1 THEN
                    RAISE NOTICE 'EXPIRACION: % dias (Fecha limite: %)', p_password_valid_max, to_char(v_valid_until_date, 'YYYY-MM-DD HH24:MI:SS');
                ELSE
                    RAISE NOTICE 'EXPIRACION: SIN FECHA LÍMITE (INDEFINIDO)';
                END IF;
            END IF;
        END LOOP;
    END IF;

    -------------------------------------------------------------------------
    -- ETAPA 2: PROCESAMIENTO DE ROTACIÓN DE USUARIOS EXISTENTES
    -------------------------------------------------------------------------
    IF p_rotate_users IS NOT NULL AND array_length(p_rotate_users, 1) > 0 THEN
        RAISE NOTICE ' ';
        RAISE NOTICE '>>> ETAPA 2: PROCESANDO ROTACION DE USUARIOS EXISTENTES...';

        IF NOT p_rotate_existing THEN
            RAISE NOTICE '-> OMITIDO GLOBALMENTE: p_rotate_existing es FALSE. Ninguna clave sera modificada.';
        ELSE
            FOREACH v_user IN ARRAY p_rotate_users LOOP
                SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_user) INTO v_role_exists;

                IF NOT v_role_exists THEN
                    RAISE NOTICE '-> OMITIDO EN ROTACION: El rol [%] NO existe en la BD. Agreguelo a p_create_users para crearlo.', v_user;
                ELSE
                    -- Generación de contraseña segura (credcheck compliance)
                    v_attempts := 0;
                    v_valid_pass := FALSE;

                    WHILE NOT v_valid_pass AND v_attempts < 100 LOOP
                        v_attempts := v_attempts + 1;
                        v_arr_chars := ARRAY[]::TEXT[];

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

                        v_remaining_len := p_password_min_length - array_length(v_arr_chars, 1);
                        FOR i IN 1..v_remaining_len LOOP
                            v_arr_chars := array_append(v_arr_chars, substr(c_all_chars, floor(random() * v_len_all + 1)::INT, 1));
                        END LOOP;

                        FOR i IN REVERSE array_length(v_arr_chars, 1)..2 LOOP
                            v_idx := floor(random() * i + 1)::INT;
                            v_char := v_arr_chars[i];
                            v_arr_chars[i] := v_arr_chars[v_idx];
                            v_arr_chars[v_idx] := v_char;
                        END LOOP;

                        v_password := array_to_string(v_arr_chars, '');

                        IF p_contain_username = FALSE THEN
                            IF position(lower(v_user) in lower(v_password)) = 0 THEN
                                v_valid_pass := TRUE;
                            END IF;
                        ELSE
                            v_valid_pass := TRUE;
                        END IF;
                    END LOOP;

                    IF NOT v_valid_pass THEN
                        RAISE EXCEPTION 'Error critico: No se pudo generar una contraseña valida para %', v_user;
                    END IF;

                    -- Actualización de credencial y políticas
                    v_sql := format('ALTER ROLE %I WITH %s PASSWORD %L', 
                                    v_user, 
                                    CASE WHEN p_can_login THEN 'LOGIN' ELSE 'NOLOGIN' END, 
                                    v_password);

                    IF p_password_valid_until = 1 THEN
                        v_valid_until_date := clock_timestamp() + (p_password_valid_max || ' days')::INTERVAL;
                        v_sql := v_sql || format(' VALID UNTIL %L', v_valid_until_date);
                    END IF;

                    EXECUTE v_sql;

                    RAISE NOTICE '--------------------------------------------------------------------';
                    RAISE NOTICE '[ROTACION EXITOSA] USUARIO: %', v_user;
                    RAISE NOTICE 'NUEVO PASSWORD: %', v_password;
                    RAISE NOTICE 'ESTADO:         %', CASE WHEN p_can_login THEN 'LOGIN ACTIVADO' ELSE 'NOLOGIN (DESACTIVADO)' END;
                    IF p_password_valid_until = 1 THEN
                        RAISE NOTICE 'EXPIRACION:     % dias (Fecha limite: %)', p_password_valid_max, to_char(v_valid_until_date, 'YYYY-MM-DD HH24:MI:SS');
                    ELSE
                        RAISE NOTICE 'EXPIRACION:     SIN FECHA LÍMITE (INDEFINIDO)';
                    END IF;
                END IF;
            END LOOP;
        END IF;
    END IF;

    RAISE NOTICE '====================================================================';
    RAISE NOTICE ' PROCESO FINALIZADO: NINGUNA CONTRASEÑA FUE EXPUESTA EN EL LOG.';
    RAISE NOTICE '====================================================================';
END $$;
