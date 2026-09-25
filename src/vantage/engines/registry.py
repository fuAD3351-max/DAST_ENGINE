"""Engine registry: the authoritative list of engines Vantage may run.

Engines are declared as YAML manifests under ``engines/manifests/`` and pinned
to exact versions and image digests in ``engines/engine-lock.yaml``. The
registry loads both, cross-checks them against the license policy, and refuses
to enable any engine that is not license-approved or not pinned. The planner
then sees only enabled, approved, reproducible engines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from vantage.domain import (
    ApprovalStatus,
    Capability,
    EngineMetadata,
    IntegrationType,
    LicenseClass,
    ResourceLimits,
)
from vantage.engines.adapter import EngineAdapter
from vantage.governance.policy import LicensePolicy


class EngineManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    vendor: str
    homepage: str = ""
    license: str
    integration: IntegrationType
    capabilities: list[Capability] = Field(min_length=1)
    adapter: str = Field(description="Dotted path to the EngineAdapter subclass")
    image: str | None = None
    default_limits: ResourceLimits = Field(default_factory=ResourceLimits)
    enabled: bool = True
    options_schema: dict[str, object] = Field(default_factory=dict)


class EngineLockEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str
    image_digest: str | None = None
    license: str
    verified_date: str = ""


class EngineLock(BaseModel):
    model_config = ConfigDict(extra="forbid")

    engines: dict[str, EngineLockEntry] = Field(default_factory=dict)


@dataclass
class RegisteredEngine:
    manifest: EngineManifest
    lock: EngineLockEntry
    metadata: EngineMetadata
    adapter: EngineAdapter | None = None
    problems: list[str] = field(default_factory=list)  # blocking issues
    notes: list[str] = field(default_factory=list)  # informational (non-blocking)

    @property
    def usable(self) -> bool:
        return (
            not self.problems
            and self.manifest.enabled
            and self.metadata.approval_status == ApprovalStatus.APPROVED
        )


class EngineRegistry:
    def __init__(self, policy: LicensePolicy) -> None:
        self._policy = policy
        self._engines: dict[str, RegisteredEngine] = {}

    @classmethod
    def load(
        cls,
        manifests_dir: str | Path,
        lock_path: str | Path,
        policy: LicensePolicy,
    ) -> EngineRegistry:
        reg = cls(policy)
        lock = _load_lock(lock_path)
        for mpath in sorted(Path(manifests_dir).glob("*.yaml")):
            data = yaml.safe_load(mpath.read_text(encoding="utf-8"))
            manifest = EngineManifest.model_validate(data)
            reg._register_manifest(manifest, lock)
        return reg

    def _register_manifest(self, manifest: EngineManifest, lock: EngineLock) -> None:
        problems: list[str] = []
        lock_entry = lock.engines.get(manifest.id)

        # First-party NATIVE engines are Vantage's own code, not third-party
        # components, so the third-party license policy does not apply. They are
        # still version-pinned for reproducibility.
        if manifest.integration is IntegrationType.NATIVE:
            if lock_entry is None:
                lock_entry = EngineLockEntry(version=manifest.name, license=manifest.license)
            metadata = EngineMetadata(
                id=manifest.id,
                name=manifest.name,
                version=lock_entry.version,
                vendor=manifest.vendor,
                license_spdx=manifest.license,
                license_class=LicenseClass.GREEN,
                approval_status=ApprovalStatus.APPROVED,
                integration=manifest.integration,
                capabilities=manifest.capabilities,
                image=None,
                homepage=manifest.homepage or None,
            )
            self._engines[manifest.id] = RegisteredEngine(
                manifest=manifest, lock=lock_entry, metadata=metadata, problems=problems
            )
            return

        # EXTERNAL_SERVICE engines (e.g. a customer-hosted Burp Suite) are never
        # redistributed by Vantage - we ship only the API client. The customer
        # supplies and licenses the third-party software separately, so the
        # third-party redistribution policy does not gate our build. Such engines
        # are approved for distribution but carry a bring-your-own-license note
        # and stay disabled until the operator configures the connection.
        if manifest.integration is IntegrationType.EXTERNAL_SERVICE:
            if lock_entry is None:
                lock_entry = EngineLockEntry(version=manifest.name, license=manifest.license)
            notes = [
                "bring-your-own-license: requires a customer-provided, separately licensed "
                f"'{manifest.vendor}' instance; Vantage distributes only the API client"
            ]
            decision = self._policy.classify(manifest.license)
            metadata = EngineMetadata(
                id=manifest.id,
                name=manifest.name,
                version=lock_entry.version,
                vendor=manifest.vendor,
                license_spdx=manifest.license,
                license_class=decision.license_class,
                approval_status=ApprovalStatus.APPROVED,
                integration=manifest.integration,
                capabilities=manifest.capabilities,
                image=None,
                homepage=manifest.homepage or None,
            )
            self._engines[manifest.id] = RegisteredEngine(
                manifest=manifest,
                lock=lock_entry,
                metadata=metadata,
                problems=problems,
                notes=notes,
            )
            return

        if lock_entry is None:
            problems.append("not pinned in engine-lock.yaml")
            lock_entry = EngineLockEntry(version="UNPINNED", license=manifest.license)

        decision = self._policy.classify(manifest.license)
        approval = ApprovalStatus.APPROVED
        if decision.license_class == LicenseClass.UNKNOWN:
            problems.append(f"license '{manifest.license}' is UNKNOWN to policy")
            approval = ApprovalStatus.REJECTED
        elif decision.license_class == LicenseClass.RED:
            # RED is only permissible via arms-length isolated integration.
            if manifest.integration.value in self._policy.arms_length_integration_types:
                approval = ApprovalStatus.PENDING_REVIEW
                problems.append(
                    f"RED license '{manifest.license}' allowed only as isolated engine after "
                    "recorded legal approval"
                )
            else:
                approval = ApprovalStatus.REJECTED
                problems.append(
                    f"RED license '{manifest.license}' cannot be embedded ({manifest.integration})"
                )
        elif decision.license_class == LicenseClass.YELLOW:
            approval = ApprovalStatus.PENDING_REVIEW
            problems.append(f"YELLOW license '{manifest.license}' requires recorded review")

        if lock_entry.license and lock_entry.license != manifest.license:
            problems.append(
                f"license mismatch: manifest={manifest.license} lock={lock_entry.license}"
            )

        if manifest.integration in (IntegrationType.CONTAINER_CLI, IntegrationType.CONTAINER_API):
            if not manifest.image:
                problems.append("containerized engine has no image")
            elif lock_entry.image_digest and "@sha256:" not in (manifest.image or ""):
                # image should be referenced by digest for reproducibility
                problems.append("image is not pinned by digest")

        metadata = EngineMetadata(
            id=manifest.id,
            name=manifest.name,
            version=lock_entry.version,
            vendor=manifest.vendor,
            license_spdx=manifest.license,
            license_class=decision.license_class,
            approval_status=approval,
            integration=manifest.integration,
            capabilities=manifest.capabilities,
            image=manifest.image,
            homepage=manifest.homepage or None,
        )
        self._engines[manifest.id] = RegisteredEngine(
            manifest=manifest, lock=lock_entry, metadata=metadata, problems=problems
        )

    def bind_adapter(self, engine_id: str, adapter: EngineAdapter) -> None:
        eng = self._engines[engine_id]
        eng.adapter = adapter

    def enable(self, engine_id: str, enabled: bool = True) -> None:
        """Flip an engine's enabled flag (e.g. after detecting it on the host).

        Only affects planner visibility; license/approval gating is unchanged, so
        a RED/YELLOW engine stays unusable until separately approved.
        """
        eng = self._engines[engine_id]
        eng.manifest = eng.manifest.model_copy(update={"enabled": enabled})

    def approve(self, engine_id: str, reference: str) -> None:
        """Record legal/compliance approval for a YELLOW/RED isolated engine."""
        eng = self._engines[engine_id]
        eng.metadata = eng.metadata.model_copy(update={"approval_status": ApprovalStatus.APPROVED})
        eng.problems = [p for p in eng.problems if "recorded" not in p and "legal" not in p]
        eng.problems.append(f"approved: {reference}")

    def all(self) -> list[RegisteredEngine]:
        return list(self._engines.values())

    def get(self, engine_id: str) -> RegisteredEngine | None:
        return self._engines.get(engine_id)

    # --- EngineCatalog protocol -------------------------------------------
    # The planner sees only engines that are policy-clean AND have a bound
    # adapter, so it never plans an engine that cannot actually run.
    def enabled_engines(self) -> list[EngineMetadata]:
        return [e.metadata for e in self._engines.values() if e.usable and e.adapter is not None]

    def engines_for(self, capability: Capability) -> list[EngineMetadata]:
        matches = [
            e
            for e in self._engines.values()
            if e.usable and e.adapter is not None and capability in e.metadata.capabilities
        ]
        # Preference order: first-party NATIVE engines first (reliable, no
        # external dependency), then others. This makes Vantage use its own
        # engines by default and reach for an isolated OSS engine only for a
        # capability the native ones do not cover (e.g. browser crawl, template
        # checks, active audit). Stable within each group.
        matches.sort(key=lambda e: 0 if e.metadata.integration is IntegrationType.NATIVE else 1)
        return [e.metadata for e in matches]

    def adapter_for(self, engine_id: str) -> EngineAdapter | None:
        eng = self._engines.get(engine_id)
        return eng.adapter if eng and eng.usable else None


def _load_lock(lock_path: str | Path) -> EngineLock:
    p = Path(lock_path)
    if not p.exists():
        return EngineLock()
    return EngineLock.model_validate(yaml.safe_load(p.read_text(encoding="utf-8")) or {})
