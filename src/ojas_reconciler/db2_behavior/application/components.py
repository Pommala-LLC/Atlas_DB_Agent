"""Application composition contracts and default component wiring."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..analysis.models import (
    CallerTransactionContract,
    DynamicResolutionCatalog,
    QuerySemanticsCatalog,
    TenantIsolationCatalog,
)
from ..analysis.service import Phase1SemanticAnalyzer
from ..bdd.authority import AuthorityRequirementsExporter, AuthoritySnapshotValidator
from ..bdd.fixture_authority import FixtureAuthorityBuilder
from ..compiler import BddCompiler, ScenarioSpecCompiler
from ..contracts.compiler import BddCompilerPort, ScenarioSpecCompilerPort
from ..contracts.inventory import ProcedureInventoryPort
from ..contracts.parser import Db2ProcedureParserPort
from ..governance.adapters.sqlite import GovernanceStore
from ..parsing.adapters.lark_sqlpl.parser import LarkSqlPlSpikeParser
from ..parsing.inventory import InventoryAnalyzer
from ..runtime.plan import RuntimeVerificationPlanner
from ..runtime.safety import RuntimeSafetyAssessor

SemanticAnalyzerFactory = Callable[
    [
        DynamicResolutionCatalog | None,
        TenantIsolationCatalog | None,
        QuerySemanticsCatalog | None,
        CallerTransactionContract | None,
    ],
    Phase1SemanticAnalyzer,
]
GovernanceStoreFactory = Callable[[Path], GovernanceStore]


@dataclass(frozen=True, slots=True)
class PipelineComponents:
    """Replaceable services used by the end-to-end application orchestrator."""

    inventory_analyzer: ProcedureInventoryPort
    procedure_parser: Db2ProcedureParserPort
    semantic_analyzer_factory: SemanticAnalyzerFactory
    scenario_compiler: ScenarioSpecCompilerPort
    authority_requirements_exporter: AuthorityRequirementsExporter
    fixture_authority_builder: FixtureAuthorityBuilder
    authority_validator: AuthoritySnapshotValidator
    bdd_compiler: BddCompilerPort
    runtime_safety_assessor: RuntimeSafetyAssessor
    runtime_planner: RuntimeVerificationPlanner
    governance_store_factory: GovernanceStoreFactory

    @classmethod
    def defaults(cls) -> "PipelineComponents":
        return cls(
            inventory_analyzer=InventoryAnalyzer(),
            procedure_parser=LarkSqlPlSpikeParser(),
            semantic_analyzer_factory=lambda dynamic, tenant, query, caller: Phase1SemanticAnalyzer(
                dynamic,
                tenant,
                query,
                caller,
            ),
            scenario_compiler=ScenarioSpecCompiler(),
            authority_requirements_exporter=AuthorityRequirementsExporter(),
            fixture_authority_builder=FixtureAuthorityBuilder(),
            authority_validator=AuthoritySnapshotValidator(),
            bdd_compiler=BddCompiler(),
            runtime_safety_assessor=RuntimeSafetyAssessor(),
            runtime_planner=RuntimeVerificationPlanner(),
            governance_store_factory=GovernanceStore,
        )
