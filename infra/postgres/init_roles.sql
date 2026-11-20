-- Osobni użytkownicy bazy dla aplikacji i Keycloaka (uruchamia usługa db-init jako
-- administrator bazy, przy każdym starcie stosu; skrypt jest idempotentny).
--
-- app_user     właściciel schematu public: tabele aplikacji, migracje Alembic.
-- keycloak_user właściciel schematu keycloak: tabele Keycloaka.
-- Żaden z nich nie ma uprawnień do schematu drugiego ani do tworzenia nowych schematów.
-- Administrator (POSTGRES_USER) służy tylko do tego skryptu; aplikacja i Keycloak go nie znają.
--
-- Zmienne psql: app_user, app_password, keycloak_user, keycloak_password, db_name.
\set ON_ERROR_STOP on

-- Role: utwórz albo ustaw hasło z .env (zmiana hasła w .env działa po restarcie).
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT', :'app_user')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_user') \gexec
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT', :'keycloak_user')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'keycloak_user') \gexec
SELECT format('ALTER ROLE %I WITH PASSWORD %L', :'app_user', :'app_password') \gexec
SELECT format('ALTER ROLE %I WITH PASSWORD %L', :'keycloak_user', :'keycloak_password') \gexec

-- Baza: tylko połączenie, bez tworzenia schematów i tabel tymczasowych dla wszystkich.
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'db_name') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I, %I', :'db_name', :'app_user', :'keycloak_user') \gexec

-- Schemat aplikacji.
SELECT format('ALTER SCHEMA public OWNER TO %I', :'app_user') \gexec
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Schemat Keycloaka.
CREATE SCHEMA IF NOT EXISTS keycloak;
SELECT format('ALTER SCHEMA keycloak OWNER TO %I', :'keycloak_user') \gexec
REVOKE ALL ON SCHEMA keycloak FROM PUBLIC;

-- Instalacje sprzed rozdzielenia: obiekty utworzone przez administratora przechodzą na
-- właściciela schematu (tabele z sekwencjami i widoki, typy, funkcje).
SELECT format('ALTER TABLE %I.%I OWNER TO %I', n.nspname, c.relname,
              CASE n.nspname WHEN 'public' THEN :'app_user' ELSE :'keycloak_user' END)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname IN ('public', 'keycloak') AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND pg_get_userbyid(c.relowner) NOT IN (:'app_user', :'keycloak_user') \gexec
SELECT format('ALTER SEQUENCE %I.%I OWNER TO %I', n.nspname, c.relname,
              CASE n.nspname WHEN 'public' THEN :'app_user' ELSE :'keycloak_user' END)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_depend d ON d.objid = c.oid AND d.deptype IN ('a', 'i')
WHERE n.nspname IN ('public', 'keycloak') AND c.relkind = 'S' AND d.objid IS NULL
  AND pg_get_userbyid(c.relowner) NOT IN (:'app_user', :'keycloak_user') \gexec
SELECT format('ALTER TYPE %I.%I OWNER TO %I', n.nspname, t.typname,
              CASE n.nspname WHEN 'public' THEN :'app_user' ELSE :'keycloak_user' END)
FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
WHERE n.nspname IN ('public', 'keycloak') AND t.typtype IN ('e', 'd', 'c')
  AND (t.typtype <> 'c' OR (SELECT relkind FROM pg_class WHERE oid = t.typrelid) = 'c')
  AND pg_get_userbyid(t.typowner) NOT IN (:'app_user', :'keycloak_user') \gexec
SELECT format('ALTER FUNCTION %s OWNER TO %I', p.oid::regprocedure,
              CASE n.nspname WHEN 'public' THEN :'app_user' ELSE :'keycloak_user' END)
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('public', 'keycloak')
  AND pg_get_userbyid(p.proowner) NOT IN (:'app_user', :'keycloak_user') \gexec
