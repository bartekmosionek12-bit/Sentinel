-- Moduł 19: wyniki testu bezpieczeństwa agenta zapisuje wyłącznie harness.
--
-- Uruchamia usługa db-harden (administrator bazy) PO migracjach, przy każdym starcie stosu
-- (idempotentnie). Tabele wyników przechodzą na własność harness_user; użytkownik aplikacji
-- (API, agent, workery) ma do nich tylko odczyt, więc ani agent, ani API nie zmienią wyniku.
-- Harness dostaje poza tym tylko to, czego potrzebuje bramka zmian: odczyt i zmianę stanu
-- wersji konfiguracji i zdolności, flagę kill switcha i dopisywanie do dziennika audytu.
--
-- Uwaga: migracja Alembica zmieniająca tabele agent_test_* musi wcześniej oddać je
-- użytkownikowi aplikacji (db-harden przy następnym starcie zabierze je z powrotem).
--
-- Zmienne psql: app_user, harness_user.
\set ON_ERROR_STOP on

SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'harness_user') \gexec

SELECT format('ALTER TABLE public.%I OWNER TO %I', t, :'harness_user')
FROM unnest(ARRAY['agent_test_run', 'agent_test_case_result']) AS t
WHERE to_regclass('public.' || t) IS NOT NULL \gexec
SELECT format('REVOKE ALL ON TABLE public.%I FROM %I', t, :'app_user')
FROM unnest(ARRAY['agent_test_run', 'agent_test_case_result']) AS t
WHERE to_regclass('public.' || t) IS NOT NULL \gexec
SELECT format('GRANT SELECT ON TABLE public.%I TO %I', t, :'app_user')
FROM unnest(ARRAY['agent_test_run', 'agent_test_case_result']) AS t
WHERE to_regclass('public.' || t) IS NOT NULL \gexec

-- Bramka zmian: harness aktywuje wersję po zaliczonym teście albo ją odrzuca.
SELECT format('GRANT SELECT, UPDATE ON TABLE public.%I TO %I', t, :'harness_user')
FROM unnest(ARRAY['agent_config_version', 'agent_capability', 'agent_switch']) AS t
WHERE to_regclass('public.' || t) IS NOT NULL \gexec
-- Dziennik audytu: tylko odczyt ostatniego skrótu i dopisywanie (łańcuch skrótów).
SELECT format('GRANT SELECT, INSERT ON TABLE public.audit_log TO %I', :'harness_user')
WHERE to_regclass('public.audit_log') IS NOT NULL \gexec
SELECT format('GRANT USAGE ON SEQUENCE %s TO %I',
              pg_get_serial_sequence('public.audit_log', 'id'), :'harness_user')
WHERE to_regclass('public.audit_log') IS NOT NULL \gexec
