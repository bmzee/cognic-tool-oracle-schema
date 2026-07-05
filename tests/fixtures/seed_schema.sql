-- cognic-tool-oracle-schema — first-boot integration seed (DEV-ONLY data).
--
-- gvenzl runs every *.sql in /container-entrypoint-initdb.d once, on the first
-- boot of a fresh volume, AFTER the database and the APP_USER (cognic) are set
-- up (see docker-compose.oracle.yml). Per the gvenzl maintainer's documented
-- init pattern (oci-oracle-xe discussion #182, which uses ALTER SESSION SET
-- CONTAINER + CREATE USER), these init scripts run as an admin in the root
-- container — NOT as the APP_USER. So we ALTER SESSION INTO XEPDB1 and create
-- the objects explicitly in the cognic schema. cognic then owns them, and any
-- session that connects AS cognic sees them through the ALL_* data-dictionary
-- views the six tools query (a user always sees its OWN objects in ALL_*; no
-- extra catalog grants are needed for the self-owned case).
--
-- Schema shape (so all six tools return real metadata):
--   COGNIC.DEPARTMENTS  — parent table; PRIMARY KEY
--   COGNIC.EMPLOYEES    — child table; PRIMARY KEY + UNIQUE + CHECK + a
--                         FOREIGN KEY -> DEPARTMENTS; NUMBER / VARCHAR2 / DATE /
--                         TIMESTAMP columns; a table comment + a column comment
--
-- Simple, first-boot DDL (gvenzl applies it exactly once on a fresh volume).
-- SET DEFINE OFF so stray '&' is never treated as a substitution variable;
-- WHENEVER SQLERROR EXIT so any failure aborts loud (never a half-seeded DB).

SET DEFINE OFF
WHENEVER SQLERROR EXIT SQL.SQLCODE

ALTER SESSION SET CONTAINER = XEPDB1;

CREATE TABLE cognic.departments (
    department_id    NUMBER(6)       NOT NULL,
    department_name  VARCHAR2(120)   NOT NULL,
    created_at       TIMESTAMP       DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT pk_departments PRIMARY KEY (department_id)
);

CREATE TABLE cognic.employees (
    employee_id      NUMBER(10)      NOT NULL,
    full_name        VARCHAR2(200)   NOT NULL,
    email            VARCHAR2(320)   NOT NULL,
    salary           NUMBER(12, 2),
    hired_on         DATE            NOT NULL,
    created_at       TIMESTAMP       DEFAULT SYSTIMESTAMP NOT NULL,
    department_id    NUMBER(6)       NOT NULL,
    CONSTRAINT pk_employees PRIMARY KEY (employee_id),
    CONSTRAINT uq_employees_email UNIQUE (email),
    CONSTRAINT ck_employees_salary CHECK (salary >= 0),
    CONSTRAINT fk_employees_department
        FOREIGN KEY (department_id) REFERENCES cognic.departments (department_id)
);

COMMENT ON TABLE cognic.departments IS 'Demo department lookup for the cognic-tool-oracle-schema integration tests (DEV-ONLY, not real data).';
COMMENT ON TABLE cognic.employees IS 'Demo employee records for the cognic-tool-oracle-schema integration tests (DEV-ONLY, not real data).';
COMMENT ON COLUMN cognic.employees.full_name IS 'Employee full display name.';

-- A few representative rows so the schema is non-empty. The six metadata tools
-- NEVER read these rows (schema-metadata only); the v0.3.0 run_readonly_query
-- integration tests DO read them back through the governed view below.
INSERT INTO cognic.departments (department_id, department_name) VALUES (10, 'Engineering');
INSERT INTO cognic.departments (department_id, department_name) VALUES (20, 'Finance');
INSERT INTO cognic.employees (employee_id, full_name, email, salary, hired_on, department_id)
    VALUES (1001, 'Ada Lovelace', 'ada@example.invalid', 120000, DATE '2024-01-15', 10);
INSERT INTO cognic.employees (employee_id, full_name, email, salary, hired_on, department_id)
    VALUES (1002, 'Alan Turing', 'alan@example.invalid', 115000, DATE '2024-02-01', 20);
COMMIT;

-- ---------------------------------------------------------------------------
-- v0.3.0 (M8, ADR-027) — Oracle proxy-authentication substrate for the
-- governed run_readonly_query tool (ADDITIVE; the v0.2.0 objects above are
-- unchanged). NOTE: gvenzl applies this file once, on the FIRST boot of a
-- fresh volume — volumes seeded before v0.3.0 must be re-created
-- (`docker compose -f docker-compose.oracle.yml down -v`).
--
--   COGNIC.V_EMPLOYEE_DIRECTORY — the governed view (no salary/email).
--   AGENT_RO                    — the proxy DB identity the kernel-signed
--                                 query-context token names
--                                 (proxy_db_identity). The tool connects as
--                                 cognic[AGENT_RO]: the session RUNS AS
--                                 AGENT_RO, whose grants — CREATE SESSION +
--                                 SELECT on the governed view ONLY — are the
--                                 engine backstop (base tables raise
--                                 ORA-00942 even if a scope misnames them).
-- All values are DEV-ONLY throwaways.
-- ---------------------------------------------------------------------------

CREATE VIEW cognic.v_employee_directory AS
    SELECT employee_id, full_name, department_id
    FROM cognic.employees;

COMMENT ON TABLE cognic.v_employee_directory IS 'Governed employee directory view for the run_readonly_query integration tests (DEV-ONLY; no salary/email).';

CREATE USER agent_ro IDENTIFIED BY agent_ro_dev_only;
GRANT CREATE SESSION TO agent_ro;
ALTER USER agent_ro GRANT CONNECT THROUGH cognic;
GRANT SELECT ON cognic.v_employee_directory TO agent_ro;

EXIT
