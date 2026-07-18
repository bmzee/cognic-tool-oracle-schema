# Changelog

## 0.5.0 - 2026-07-18

- Replace the plaintext `COGNIC_ORACLE_PASSWORD` environment channel with the
  required `COGNIC_ORACLE_PASSWORD_FILE` contract; stale deployments fail loud.
- Read credentials from the injected file at pool startup and per governed query,
  with one fresh-read retry on `ORA-01017` rotation races.
- Stamp the verified query-context subject through
  `DBMS_SESSION.SET_IDENTIFIER` before user SQL; stamp failures return the new
  closed-enum `query_identity_stamp_failed` refusal.
- Add the non-secret `credential_rotation_ref` file-mtime marker to successful
  governed-query envelopes.
