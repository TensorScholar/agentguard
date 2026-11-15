from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

from decisionlock.domain import ExternalEffectBinding, ProviderReconciliationEvidence
from decisionlock.engine.canonical import digest
from decisionlock.engine.provider_contracts import external_effect_binding_digest
from decisionlock.security.files import ensure_private_file


class ProviderReconciliationStoreError(RuntimeError):
    pass


class SQLiteProviderEffectRepository:
    """Durable non-secret store for provider-effect bindings and reconciliation evidence."""

    _SCHEMA = """
    PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS provider_effect_bindings(
        execution_id TEXT PRIMARY KEY,
        binding_digest TEXT UNIQUE NOT NULL,
        binding_json TEXT NOT NULL,
        provider_identity_digest TEXT NOT NULL,
        operation_id TEXT NOT NULL,
        recorded_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS provider_reconciliation_evidence(
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        binding_digest TEXT NOT NULL,
        evidence_record_digest TEXT UNIQUE NOT NULL,
        evidence_digest TEXT NOT NULL,
        evidence_json TEXT NOT NULL,
        recorded_at TEXT NOT NULL,
        FOREIGN KEY(binding_digest) REFERENCES provider_effect_bindings(binding_digest)
    );
    CREATE INDEX IF NOT EXISTS idx_provider_evidence_binding
    ON provider_reconciliation_evidence(binding_digest, sequence);
    CREATE TABLE IF NOT EXISTS provider_reconciliation_schema(
        component TEXT PRIMARY KEY,
        version INTEGER NOT NULL
    );
    INSERT OR IGNORE INTO provider_reconciliation_schema(component, version)
    VALUES('provider_reconciliation', 1);
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        ensure_private_file(path)
        with self._connect() as connection:
            connection.executescript(self._SCHEMA)
            row = connection.execute(
                "SELECT version FROM provider_reconciliation_schema "
                "WHERE component = 'provider_reconciliation'"
            ).fetchone()
            version = int(row[0]) if row is not None else 0
            if version != 1:
                raise ProviderReconciliationStoreError(
                    "provider_reconciliation.schema_version_unsupported"
                )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA secure_delete=ON")
        return connection

    @staticmethod
    def _require_aware(value: datetime, code: str) -> None:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ProviderReconciliationStoreError(code)

    def store_external_effect_binding(
        self,
        execution_id: str,
        binding: ExternalEffectBinding,
        recorded_at: datetime,
    ) -> None:
        self._require_aware(recorded_at, "provider_binding.recorded_at_invalid")
        if execution_id != binding.attempt.execution_id:
            raise ProviderReconciliationStoreError("provider_binding.execution_id_mismatch")
        binding_digest = external_effect_binding_digest(binding)
        provider_digest = digest(binding.provider)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT binding_digest,binding_json FROM provider_effect_bindings "
                "WHERE execution_id = ?",
                (execution_id,),
            ).fetchone()
            if existing is not None:
                if str(existing["binding_digest"]) != binding_digest:
                    connection.execute("ROLLBACK")
                    raise ProviderReconciliationStoreError("provider_binding.execution_conflict")
                if (
                    ExternalEffectBinding.model_validate_json(str(existing["binding_json"]))
                    != binding
                ):
                    connection.execute("ROLLBACK")
                    raise ProviderReconciliationStoreError(
                        "provider_binding.serialization_conflict"
                    )
                connection.execute("COMMIT")
                return
            try:
                connection.execute(
                    """
                    INSERT INTO provider_effect_bindings(
                        execution_id,binding_digest,binding_json,provider_identity_digest,
                        operation_id,recorded_at
                    ) VALUES(?,?,?,?,?,?)
                    """,
                    (
                        execution_id,
                        binding_digest,
                        binding.model_dump_json(),
                        provider_digest,
                        binding.operation.operation_id,
                        recorded_at.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise ProviderReconciliationStoreError("provider_binding.digest_conflict") from exc
            connection.execute("COMMIT")

    def get_external_effect_binding(self, execution_id: str) -> ExternalEffectBinding | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT binding_json FROM provider_effect_bindings WHERE execution_id = ?",
                (execution_id,),
            ).fetchone()
        if row is None:
            return None
        return ExternalEffectBinding.model_validate_json(str(row["binding_json"]))

    def record_provider_reconciliation_evidence(
        self,
        evidence: ProviderReconciliationEvidence,
        recorded_at: datetime,
    ) -> None:
        self._require_aware(recorded_at, "provider_evidence.recorded_at_invalid")
        evidence_record_digest = digest(evidence)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            binding = connection.execute(
                "SELECT 1 FROM provider_effect_bindings WHERE binding_digest = ?",
                (evidence.binding_digest,),
            ).fetchone()
            if binding is None:
                connection.execute("ROLLBACK")
                raise ProviderReconciliationStoreError("provider_evidence.binding_missing")
            existing = connection.execute(
                "SELECT evidence_json FROM provider_reconciliation_evidence "
                "WHERE evidence_record_digest = ?",
                (evidence_record_digest,),
            ).fetchone()
            if existing is not None:
                if (
                    ProviderReconciliationEvidence.model_validate_json(
                        str(existing["evidence_json"])
                    )
                    != evidence
                ):
                    connection.execute("ROLLBACK")
                    raise ProviderReconciliationStoreError("provider_evidence.digest_conflict")
                connection.execute("COMMIT")
                return
            connection.execute(
                """
                INSERT INTO provider_reconciliation_evidence(
                    binding_digest,evidence_record_digest,evidence_digest,evidence_json,recorded_at
                ) VALUES(?,?,?,?,?)
                """,
                (
                    evidence.binding_digest,
                    evidence_record_digest,
                    evidence.evidence_digest,
                    evidence.model_dump_json(),
                    recorded_at.isoformat(),
                ),
            )
            connection.execute("COMMIT")

    def list_provider_reconciliation_evidence(
        self, binding_digest: str
    ) -> tuple[ProviderReconciliationEvidence, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT evidence_json FROM provider_reconciliation_evidence "
                "WHERE binding_digest = ? ORDER BY sequence",
                (binding_digest,),
            ).fetchall()
        return tuple(
            ProviderReconciliationEvidence.model_validate_json(str(row["evidence_json"]))
            for row in rows
        )
