from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from ipaddress import ip_address
from urllib.parse import urlsplit
from typing import Annotated, Any, Callable, Mapping

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from ..commercial.models import (
    CompositionAssessment,
    OrganicPauseDisposition,
    PauseCause,
    PauseDispositionDecision,
    PauseResponsibility,
    ProcedureCompositionContract,
    ProcedureKnowledgeGraph,
    OrganicReviewBatch, SupportCaseClassification, SupportSeverity, CommercialDeletionRequest, DeletionScope,
)
from ..commercial.service import CommercialReadinessService, CommercialValidationError, OrganicValidationService
from ..commercial.workflows import (
    CommercialOperationsService,
    CommercialWorkflowError,
    CompositionContractService,
    ImmutableArtifactStore,
    OrganicPauseDispositionService,
    ProcedureCheckService,
    ProcedureKnowledgeGraphService, RelationalFixturePlanningService, CommercialDataLifecycleService,
)
from ..core.canonical_json import canonical_digest, canonical_json_bytes
from ..bdd.models import VocabularySnapshot, ClassificationSnapshot
from ..bdd.authority import AuthoritySnapshotValidator
from ..type_system.models import RelationDefinition
from ..runtime.models import RuntimeVerificationBatch
from ..governance.adapters.sqlite import GovernanceStore
from .review_dashboard import ReviewDashboardError, build_review_dashboard, discover_runs
from .control_summary import build_commercial_control_summary
from .procedure_analysis import (
    DATABASES,
    ProcedureAnalysisError,
    ProcedureAnalysisService,
    SourceInput,
    database_descriptor,
    decode_upload,
)
from ..catalog import CatalogLineageResolver, DdlCatalogProvider, JsonCatalogProvider
from ..composition import DirectCallCompositionInferenceService
from ..decision import (
    DecisionEvaluationRequest,
    ExtractedDecisionModelBuilder,
    ModelDrivenDecisionEvaluator,
    TruthValue,
)
from ..dialects import DialectAdapterRegistry, DialectId
from ..graph import PersistentKnowledgeGraphStore
from ..runtime.reconcile import RuntimeReconciliationService
from ..testkit.fixture_compiler import ApprovedFixtureValue, ExecutableRelationalFixtureCompiler
from ..identity import (
    EnterpriseRole,
    FixedIdentityProvider,
    IdentityVerificationError,
    OidcIdentityConfig,
    OidcJwtIdentityProvider,
    SignedTrustedHeaderIdentityProvider,
    TrustedHeaderIdentityConfig,
)


class UiRole(StrEnum):
    VIEWER = "VIEWER"
    ANALYST = "ANALYST"
    REVIEWER = "REVIEWER"
    ADMIN = "ADMIN"


ROLE_LEVEL = {UiRole.VIEWER: 0, UiRole.ANALYST: 1, UiRole.REVIEWER: 2, UiRole.ADMIN: 3}


@dataclass(frozen=True)
class CommercialUiSettings:
    workspace: Path
    tenant_ref: str = "tenant:local"
    actor_ref: str = "actor:local-ui"
    role: UiRole = UiRole.ADMIN
    trust_identity_headers: bool = False
    identity_config: Path | None = None
    title: str = "Commercial Behavior Analysis Console"
    allowed_origins: tuple[str, ...] = ()
    trust_proxy_headers: bool = False

    @classmethod
    def from_env(cls) -> "CommercialUiSettings":
        role_value = os.environ.get("ATLAS_UI_ROLE", os.environ.get("OJAS_COMMERCIAL_UI_ROLE", UiRole.ADMIN.value))
        try:
            role = UiRole(role_value)
        except ValueError:
            role = UiRole.VIEWER
        return cls(
            workspace=Path(os.environ.get("ATLAS_UI_WORKSPACE", os.environ.get("OJAS_COMMERCIAL_UI_WORKSPACE", "reports/atlas"))),
            tenant_ref=os.environ.get("ATLAS_UI_TENANT", os.environ.get("OJAS_COMMERCIAL_UI_TENANT", "tenant:local")),
            actor_ref=os.environ.get("ATLAS_UI_ACTOR", os.environ.get("OJAS_COMMERCIAL_UI_ACTOR", "actor:local-ui")),
            role=role,
            trust_identity_headers=os.environ.get("ATLAS_UI_TRUST_HEADERS", os.environ.get("OJAS_COMMERCIAL_UI_TRUST_HEADERS", "")).strip() == "1",
            identity_config=(Path(os.environ.get("ATLAS_UI_IDENTITY_CONFIG", os.environ.get("OJAS_COMMERCIAL_UI_IDENTITY_CONFIG", ""))) if os.environ.get("ATLAS_UI_IDENTITY_CONFIG", os.environ.get("OJAS_COMMERCIAL_UI_IDENTITY_CONFIG")) else None),
            title=os.environ.get("ATLAS_UI_TITLE", os.environ.get("OJAS_COMMERCIAL_UI_TITLE", "Atlas Procedure Intelligence")),
            allowed_origins=tuple(
                value.strip().rstrip("/")
                for value in os.environ.get("ATLAS_UI_ALLOWED_ORIGINS", "").split(",")
                if value.strip()
            ),
            trust_proxy_headers=os.environ.get("ATLAS_UI_TRUST_PROXY_HEADERS", "").strip() == "1",
        )


class UiIdentity(BaseModel):
    actor_ref: str
    role: UiRole
    source: str


class DecisionWhatIfPayload(BaseModel):
    predicate_values: dict[str, TruthValue] = Field(default_factory=dict)


class DdlCatalogPayload(BaseModel):
    paths: list[str]
    platform: str = "DB2_LUW"
    provider_ref: str = "ui-ddl-catalog"


class CatalogLineagePayload(BaseModel):
    catalog_path: str
    relation_refs: list[str]
    max_depth: int = Field(default=8, ge=1, le=64)


class FixtureCompilePayload(BaseModel):
    catalog_path: str
    procedure_ref: str
    relation_refs: list[str]
    approved_values: list[ApprovedFixtureValue] = Field(default_factory=list)
    acknowledged_check_constraints: list[str] = Field(default_factory=list)


class CompositionInferencePayload(BaseModel):
    run_names: list[str]


class RuntimeReconcilePayload(BaseModel):
    plan_batch_path: str
    execution_record_paths: list[str]


class GraphSearchPayload(BaseModel):
    query: str
    limit: int = Field(default=100, ge=1, le=1000)


class GraphNeighborhoodPayload(BaseModel):
    node_id: str
    depth: int = Field(default=1, ge=0, le=8)
    limit: int = Field(default=500, ge=1, le=5000)


class DialectInventoryPayload(BaseModel):
    source_path: str
    dialect: DialectId


class UiState:
    def __init__(self, settings: CommercialUiSettings) -> None:
        self.settings = settings
        self.workspace = settings.workspace.resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.store = ImmutableArtifactStore(self.workspace, tenant_ref=settings.tenant_ref)
        self.procedure_analysis = ProcedureAnalysisService(self.store.tenant_root / "procedure-analyses")
        self.identity_provider = self._identity_provider(settings)
        self.templates_dir = self.workspace / "templates"
        if not self.templates_dir.exists():
            CommercialReadinessService().export_templates(self.templates_dir)

    @staticmethod
    def _identity_provider(settings: CommercialUiSettings):
        if settings.identity_config is not None:
            payload = json.loads(settings.identity_config.resolve().read_text(encoding="utf-8"))
            mode = str(payload.get("mode", ""))
            if mode == "OIDC_JWT":
                return OidcJwtIdentityProvider(OidcIdentityConfig.model_validate(payload))
            if mode == "SIGNED_TRUSTED_HEADERS":
                return SignedTrustedHeaderIdentityProvider(TrustedHeaderIdentityConfig.model_validate(payload))
            raise RuntimeError(f"Unsupported identity mode: {mode}")
        return FixedIdentityProvider(
            actor_ref=settings.actor_ref,
            tenant_ref=settings.tenant_ref,
            roles=(EnterpriseRole(settings.role.value),),
        )


def _json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _origin_endpoint(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return parsed.scheme, parsed.hostname.rstrip(".").lower(), port
    except ValueError:
        return None


def _host_endpoint(scheme: str, host: str) -> tuple[str, str, int] | None:
    return _origin_endpoint(f"{scheme}://{host}") if host else None


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def _browser_same_site_write(request: Request) -> bool:
    """Accept Chromium same-origin/same-site form posts to a loopback Atlas target.

    `Sec-Fetch-Site` is a browser-controlled Fetch Metadata header. It avoids
    false rejections caused by local proxies or origin rewriting while still
    rejecting cross-site browser submissions.
    """
    fetch_site = request.headers.get("sec-fetch-site", "").strip().lower()
    if fetch_site not in {"same-origin", "same-site"}:
        return False
    scheme = request.url.scheme
    target = _host_endpoint(scheme, request.headers.get("host", ""))
    return target is not None and _is_loopback_host(target[1])


def _write_origin_allowed(request: Request, origin: str, settings: CommercialUiSettings) -> bool:
    origin_value = origin.rstrip("/")
    if origin_value in settings.allowed_origins:
        return True
    actual = _origin_endpoint(origin_value)
    if actual is None:
        return False
    schemes = {request.url.scheme}
    hosts = {request.headers.get("host", "")}
    if settings.trust_proxy_headers:
        forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip()
        forwarded_host = request.headers.get("x-forwarded-host", "").split(",", 1)[0].strip()
        if forwarded_proto in {"http", "https"}:
            schemes.add(forwarded_proto)
        if forwarded_host:
            hosts.add(forwarded_host)
    candidates = {
        endpoint
        for scheme in schemes
        for host in hosts
        if (endpoint := _host_endpoint(scheme, host)) is not None
    }
    if actual in candidates:
        return True
    # Atlas Console is commonly opened through localhost, 127.0.0.1, ::1,
    # IDE port forwarding, or a browser-selected loopback alias. Treat a
    # loopback UI posting to a loopback Atlas host as local same-site traffic.
    # Non-loopback origins remain rejected unless explicitly configured.
    if _is_loopback_host(actual[1]) and any(_is_loopback_host(candidate[1]) for candidate in candidates):
        return True
    return False


def create_app(settings: CommercialUiSettings | None = None) -> FastAPI:
    resolved_settings = settings or CommercialUiSettings.from_env()
    state = UiState(resolved_settings)
    package_root = Path(__file__).resolve().parent
    templates = Jinja2Templates(directory=str(package_root / "templates"))

    app = FastAPI(
        title=resolved_settings.title,
        version="2.0.0rc5",
        docs_url="/api/docs",
        redoc_url=None,
    )
    app.state.commercial = state

    @app.middleware("http")
    async def commercial_security_boundary(request: Request, call_next):
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = request.headers.get("origin")
            if origin and not (
                _write_origin_allowed(request, origin, resolved_settings)
                or _browser_same_site_write(request)
            ):
                return JSONResponse(
                    {
                        "detail": (
                            "Cross-origin commercial write rejected. Submit from the same Atlas URL "
                            "or configure ATLAS_UI_ALLOWED_ORIGINS for the trusted UI origin."
                        )
                    },
                    status_code=403,
                )
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"
        response.headers["Cache-Control"] = "no-store"
        return response

    app.mount("/static", StaticFiles(directory=str(package_root / "static")), name="static")

    def identity(request: Request) -> UiIdentity:
        # The unsigned header mode is preserved only as a compatibility path.
        if resolved_settings.trust_identity_headers and resolved_settings.identity_config is None:
            actor = request.headers.get("x-ojas-actor")
            role = request.headers.get("x-ojas-role")
            if actor and role:
                try:
                    return UiIdentity(actor_ref=actor, role=UiRole(role), source="UNSIGNED_TRUSTED_HEADER_COMPATIBILITY")
                except ValueError as exc:
                    raise HTTPException(status_code=403, detail="Invalid Atlas role header.") from exc
        try:
            principal = state.identity_provider.authenticate(headers=dict(request.headers))
        except IdentityVerificationError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        if principal.tenant_ref != resolved_settings.tenant_ref:
            raise HTTPException(status_code=403, detail="Authenticated tenant does not match the active workspace.")
        role = max((UiRole(value.value) for value in principal.roles), key=lambda value: ROLE_LEVEL[value])
        return UiIdentity(actor_ref=principal.actor_ref, role=role, source=principal.mode.value)

    def require(minimum: UiRole) -> Callable[[UiIdentity], UiIdentity]:
        def dependency(current: UiIdentity = Depends(identity)) -> UiIdentity:
            if ROLE_LEVEL[current.role] < ROLE_LEVEL[minimum]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"{minimum.value} role required.")
            return current
        return dependency

    def render(request: Request, template: str, **context: Any) -> HTMLResponse:
        current = identity(request)
        common = {
            "request": request,
            "title": resolved_settings.title,
            "identity": current,
            "tenant_ref": resolved_settings.tenant_ref,
            "identity_mode": current.source,
            "workspace": state.workspace.as_posix(),
            "message": request.query_params.get("message"),
            "error": request.query_params.get("error"),
        }
        return templates.TemplateResponse(request, template, {**common, **context})

    def redirect(path: str, *, message: str | None = None, error: str | None = None) -> RedirectResponse:
        from urllib.parse import urlencode
        query = urlencode({key: value for key, value in {"message": message, "error": error}.items() if value})
        separator = "&" if "?" in path else "?"
        return RedirectResponse(path + (f"{separator}{query}" if query else ""), status_code=303)

    @app.get("/health", response_class=JSONResponse)
    def health() -> dict[str, object]:
        return {
            "status": "UP",
            "release": "2.0.0rc5",
            "tenant_ref": resolved_settings.tenant_ref,
            "workspace": state.workspace.as_posix(),
            "identity_adapter": ("CONFIGURED_ENTERPRISE" if resolved_settings.identity_config else ("UNSIGNED_TRUSTED_HEADERS_COMPATIBILITY" if resolved_settings.trust_identity_headers else "FIXED_LOCAL")),
            "commercial_maturity": "COMMERCIALIZATION_CANDIDATE",
        }

    @app.get("/", response_class=HTMLResponse)
    def procedure_home(request: Request) -> RedirectResponse:
        return RedirectResponse("/runs", status_code=307)

    @app.get("/review", response_class=HTMLResponse)
    def review_index(request: Request) -> HTMLResponse:
        runs = discover_runs(state.workspace)
        return render(request, "review_index.html", runs=runs)

    @app.get("/review/{run_name}", response_class=HTMLResponse)
    def review_dashboard(request: Request, run_name: str, group: str = "decision", tab: str = "decision") -> HTMLResponse:
        run_root = (state.workspace / "runs").resolve()
        candidate = (run_root / run_name).resolve()
        try:
            candidate.relative_to(run_root)
        except ValueError as exc:
            raise HTTPException(status_code=403, detail="Analysis-run path escapes workspace.") from exc
        try:
            review = build_review_dashboard(candidate)
        except ReviewDashboardError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        selected_group = group if group in {"entry", "decision", "escalation", "persistence"} else "decision"
        selected_tab = tab if tab in {"decision", "scenarios", "lineage", "effects", "audit", "controls"} else "decision"
        controls = build_commercial_control_summary(
            store=state.store,
            templates_dir=state.templates_dir,
            run_dir=candidate,
            review=review,
        )
        return render(
            request,
            "review_dashboard.html",
            review=review,
            controls=controls,
            runs=discover_runs(state.workspace),
            selected_group=selected_group,
            selected_tab=selected_tab,
        )

    @app.get("/api/review/{run_name}")
    def review_api(run_name: str) -> dict[str, Any]:
        run_root = (state.workspace / "runs").resolve()
        candidate = (run_root / run_name).resolve()
        try:
            candidate.relative_to(run_root)
        except ValueError as exc:
            raise HTTPException(status_code=403, detail="Analysis-run path escapes workspace.") from exc
        try:
            review = build_review_dashboard(candidate)
            review["commercial_controls"] = build_commercial_control_summary(
                store=state.store,
                templates_dir=state.templates_dir,
                run_dir=candidate,
                review=review,
            )
            return review
        except ReviewDashboardError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/review/{run_name}/decision-model")
    def review_decision_model(run_name: str) -> dict[str, Any]:
        run_root = (state.workspace / "runs").resolve()
        candidate = (run_root / run_name).resolve()
        try:
            candidate.relative_to(run_root)
            return ExtractedDecisionModelBuilder().build(candidate).model_dump(mode="json")
        except ValueError as exc:
            raise HTTPException(status_code=403, detail="Analysis-run path escapes workspace.") from exc
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/review/{run_name}/decision-evaluate")
    def review_decision_evaluate(
        run_name: str,
        payload: DecisionWhatIfPayload,
        current: UiIdentity = Depends(require(UiRole.ANALYST)),
    ) -> dict[str, Any]:
        run_root = (state.workspace / "runs").resolve()
        candidate = (run_root / run_name).resolve()
        try:
            candidate.relative_to(run_root)
            model = ExtractedDecisionModelBuilder().build(candidate)
            request_value = DecisionEvaluationRequest(
                model_digest=model.content_digest,
                predicate_values=payload.predicate_values,
            )
            result = ModelDrivenDecisionEvaluator().evaluate(model=model, request=request_value)
            state.store.audit(
                actor_ref=current.actor_ref,
                role=current.role.value,
                action="MODEL_DRIVEN_DECISION_EVALUATED",
                artifact_ref=model.model_id,
                artifact_digest=result.content_digest,
                details={"run_name": run_name, "status": result.status},
            )
            return result.model_dump(mode="json")
        except ValueError as exc:
            raise HTTPException(status_code=403, detail="Analysis-run path escapes workspace.") from exc
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/enterprise/catalog/ddl")
    def enterprise_catalog_ddl(
        payload: DdlCatalogPayload,
        current: UiIdentity = Depends(require(UiRole.ANALYST)),
    ) -> dict[str, Any]:
        try:
            snapshot = DdlCatalogProvider(
                [Path(value) for value in payload.paths],
                platform=payload.platform,
                provider_ref=payload.provider_ref,
            ).load()
            state.store.put(category="catalog-snapshots", artifact_id=snapshot.snapshot_id, payload=snapshot, actor_ref=current.actor_ref, role=current.role.value, action="DDL_CATALOG_SNAPSHOT_BUILT")
            return snapshot.model_dump(mode="json")
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/enterprise/catalog/lineage")
    def enterprise_catalog_lineage(
        payload: CatalogLineagePayload,
        current: UiIdentity = Depends(require(UiRole.ANALYST)),
    ) -> dict[str, Any]:
        try:
            report = CatalogLineageResolver(JsonCatalogProvider(Path(payload.catalog_path)).load(), max_depth=payload.max_depth).resolve(payload.relation_refs)
            state.store.put(category="catalog-lineage", artifact_id=report.report_id, payload=report, actor_ref=current.actor_ref, role=current.role.value, action="CATALOG_LINEAGE_RESOLVED")
            return report.model_dump(mode="json")
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/enterprise/fixtures/compile")
    def enterprise_fixture_compile(
        payload: FixtureCompilePayload,
        current: UiIdentity = Depends(require(UiRole.REVIEWER)),
    ) -> JSONResponse:
        try:
            result = ExecutableRelationalFixtureCompiler().compile(
                procedure_ref=payload.procedure_ref,
                catalog=JsonCatalogProvider(Path(payload.catalog_path)).load(),
                relation_refs=payload.relation_refs,
                approved_values=payload.approved_values,
                acknowledged_check_constraints=payload.acknowledged_check_constraints,
            )
            state.store.put(category="executable-fixtures", artifact_id=result.bundle_id, payload=result, actor_ref=current.actor_ref, role=current.role.value, action="EXECUTABLE_FIXTURE_COMPILATION_COMPLETED")
            return JSONResponse(result.model_dump(mode="json"), status_code=(200 if result.status.value == "EXECUTABLE" else 409))
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/enterprise/composition/infer")
    def enterprise_composition_infer(
        payload: CompositionInferencePayload,
        current: UiIdentity = Depends(require(UiRole.ANALYST)),
    ) -> dict[str, Any]:
        try:
            run_root = (state.workspace / "runs").resolve()
            run_dirs = []
            for name in payload.run_names:
                candidate = (run_root / name).resolve()
                candidate.relative_to(run_root)
                run_dirs.append(candidate)
            result = DirectCallCompositionInferenceService().infer(run_dirs)
            state.store.put(category="composition-candidates", artifact_id=result.batch_id, payload=result, actor_ref=current.actor_ref, role=current.role.value, action="DIRECT_CALL_COMPOSITION_INFERRED")
            return result.model_dump(mode="json")
        except ValueError as exc:
            raise HTTPException(status_code=403, detail="Analysis-run path escapes workspace.") from exc
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/enterprise/runtime/reconcile")
    def enterprise_runtime_reconcile(
        payload: RuntimeReconcilePayload,
        current: UiIdentity = Depends(require(UiRole.ANALYST)),
    ) -> dict[str, Any]:
        try:
            service = RuntimeReconciliationService()
            batch, report = service.reconcile(
                plan_batch=service.load_plan_batch(Path(payload.plan_batch_path)),
                execution_records=service.load_execution_records(Path(value) for value in payload.execution_record_paths),
            )
            state.store.put(category="runtime-reconciliation", artifact_id=f"reconcile-{report.content_digest[-16:]}", payload=report, actor_ref=current.actor_ref, role=current.role.value, action="RUNTIME_RECONCILIATION_COMPLETED")
            return {"verification_batch": batch.model_dump(mode="json"), "reconciliation_report": report.model_dump(mode="json")}
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/enterprise/graph/ingest")
    def enterprise_graph_ingest(
        graph_payload: dict[str, Any],
        current: UiIdentity = Depends(require(UiRole.ANALYST)),
    ) -> dict[str, Any]:
        try:
            graph = ProcedureKnowledgeGraph.model_validate(graph_payload, strict=False)
            db = state.store.tenant_root / "knowledge-graph.sqlite"
            result = PersistentKnowledgeGraphStore(db, tenant_ref=resolved_settings.tenant_ref).ingest(graph)
            state.store.audit(actor_ref=current.actor_ref, role=current.role.value, action="PERSISTENT_GRAPH_INGESTED", artifact_ref=graph.graph_id, artifact_digest=graph.content_digest, details=result)
            return result
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/enterprise/graph/search")
    def enterprise_graph_search(
        payload: GraphSearchPayload,
        current: UiIdentity = Depends(require(UiRole.VIEWER)),
    ) -> dict[str, Any]:
        db = state.store.tenant_root / "knowledge-graph.sqlite"
        return {"nodes": PersistentKnowledgeGraphStore(db, tenant_ref=resolved_settings.tenant_ref).search_nodes(payload.query, limit=payload.limit)}

    @app.post("/api/enterprise/graph/neighborhood")
    def enterprise_graph_neighborhood(
        payload: GraphNeighborhoodPayload,
        current: UiIdentity = Depends(require(UiRole.VIEWER)),
    ) -> dict[str, Any]:
        try:
            db = state.store.tenant_root / "knowledge-graph.sqlite"
            return PersistentKnowledgeGraphStore(db, tenant_ref=resolved_settings.tenant_ref).neighborhood(
                payload.node_id, depth=payload.depth, limit=payload.limit
            )
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/enterprise/dialects")
    def enterprise_dialect_registry(current: UiIdentity = Depends(require(UiRole.VIEWER))) -> dict[str, Any]:
        return DialectAdapterRegistry.default().snapshot().model_dump(mode="json")

    @app.post("/api/enterprise/dialects/inventory")
    def enterprise_dialect_inventory(
        payload: DialectInventoryPayload,
        current: UiIdentity = Depends(require(UiRole.ANALYST)),
    ) -> dict[str, Any]:
        try:
            result = DialectAdapterRegistry.default().adapter(payload.dialect).inventory(Path(payload.source_path))
            state.store.put(category="dialect-inventory", artifact_id=f"inventory-{result.dialect.value}-{result.source_digest[-12:]}", payload=result, actor_ref=current.actor_ref, role=current.role.value, action="NON_DB2_ROUTINE_INVENTORIED")
            return result.model_dump(mode="json")
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/review/{run_name}/controls/checks")
    def review_build_checks(
        run_name: str,
        current: UiIdentity = Depends(require(UiRole.ANALYST)),
    ) -> RedirectResponse:
        run_root = (state.workspace / "runs").resolve()
        candidate = (run_root / run_name).resolve()
        try:
            candidate.relative_to(run_root)
            report = ProcedureCheckService().build(candidate)
            state.store.put(
                category="procedure-checks",
                artifact_id=f"checks-{run_name}",
                payload=report,
                actor_ref=current.actor_ref,
                role=current.role.value,
                action="PROCEDURE_CHECKS_BUILT_FROM_REVIEW",
            )
            return redirect(f"/review/{run_name}?tab=controls", message="Procedure controls evaluated and stored.")
        except Exception as exc:
            return redirect(f"/review/{run_name}?tab=controls", error=str(exc))

    @app.post("/review/{run_name}/controls/graph")
    def review_build_graph(
        run_name: str,
        current: UiIdentity = Depends(require(UiRole.ANALYST)),
    ) -> RedirectResponse:
        run_root = (state.workspace / "runs").resolve()
        candidate = (run_root / run_name).resolve()
        try:
            candidate.relative_to(run_root)
            graph_value = ProcedureKnowledgeGraphService().build(candidate)
            state.store.put(
                category="graphs",
                artifact_id=graph_value.graph_id,
                payload=graph_value,
                actor_ref=current.actor_ref,
                role=current.role.value,
                action="KNOWLEDGE_GRAPH_BUILT_FROM_REVIEW",
            )
            return redirect(f"/review/{run_name}?tab=controls", message="Evidence graph generated and stored.")
        except Exception as exc:
            return redirect(f"/review/{run_name}?tab=controls", error=str(exc))

    @app.post("/review/{run_name}/controls/support-bundle")
    def review_support_bundle(
        run_name: str,
        current: UiIdentity = Depends(require(UiRole.ADMIN)),
    ) -> RedirectResponse:
        run_root = (state.workspace / "runs").resolve()
        candidate = (run_root / run_name).resolve()
        try:
            candidate.relative_to(run_root)
            output = state.store.tenant_root / "bundles" / f"support-{run_name}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.zip"
            CommercialOperationsService().build_support_bundle(run_dir=candidate, output=output, include_source=False)
            digest = "sha256:" + __import__("hashlib").sha256(output.read_bytes()).hexdigest()
            state.store.audit(
                actor_ref=current.actor_ref,
                role=current.role.value,
                action="SUPPORT_BUNDLE_GENERATED_FROM_REVIEW",
                artifact_ref=output.relative_to(state.store.tenant_root).as_posix(),
                artifact_digest=digest,
                details={"source_included": False, "run_name": run_name},
            )
            return redirect(f"/review/{run_name}?tab=controls", message=f"Source-free support bundle generated: {output.name}")
        except Exception as exc:
            return redirect(f"/review/{run_name}?tab=controls", error=str(exc))

    @app.get("/commercial", response_class=HTMLResponse)
    def dashboard(request: Request) -> HTMLResponse:
        categories = {
            category: len(state.store.list(category))
            for category in (
                "capabilities", "custody", "organic-reports", "reviews", "dispositions",
                "procedure-checks", "composition", "graphs", "readiness", "operations",
            )
        }
        latest_readiness = state.store.latest("readiness")
        readiness = _json(latest_readiness) if latest_readiness else None
        latest_organic = state.store.latest("organic-reports")
        organic = _json(latest_organic) if latest_organic else None
        return render(
            request,
            "dashboard.html",
            categories=categories,
            readiness=readiness,
            organic=organic,
            audit_events=state.store.audit_events(12),
        )

    @app.get("/artifacts", response_class=HTMLResponse)
    def artifacts(request: Request, category: str | None = None) -> HTMLResponse:
        values = state.store.list(category)
        records = [
            {
                "path": item.relative_to(state.store.tenant_root).as_posix(),
                "name": item.name,
                "category": item.parent.name,
                "size": item.stat().st_size,
                "mtime": datetime.fromtimestamp(item.stat().st_mtime, tz=timezone.utc).isoformat(),
            }
            for item in values
        ]
        return render(request, "artifacts.html", artifacts=records, category=category)

    @app.get("/artifact/{artifact_path:path}", response_class=HTMLResponse)
    def artifact_view(request: Request, artifact_path: str) -> HTMLResponse:
        candidate = (state.store.tenant_root / artifact_path).resolve()
        try:
            candidate.relative_to(state.store.tenant_root)
        except ValueError as exc:
            raise HTTPException(status_code=403, detail="Artifact path escapes tenant workspace.") from exc
        if not candidate.is_file():
            raise HTTPException(status_code=404, detail="Artifact not found.")
        raw = candidate.read_text(encoding="utf-8")
        try:
            pretty = json.dumps(json.loads(raw), indent=2, sort_keys=True)
        except json.JSONDecodeError:
            pretty = raw
        return render(request, "artifact_view.html", artifact_path=artifact_path, content=pretty)

    @app.get("/capabilities", response_class=HTMLResponse)
    def capabilities(request: Request) -> HTMLResponse:
        latest = state.store.latest("capabilities")
        payload = _json(latest) if latest else None
        template_path = state.templates_dir / "capability-manifest.json"
        initial = template_path.read_text(encoding="utf-8") if template_path.is_file() else "{}"
        return render(request, "capabilities.html", capability=payload, manifest_text=initial)

    @app.post("/capabilities/validate")
    def capabilities_validate(
        manifest_text: Annotated[str, Form()],
        current: UiIdentity = Depends(require(UiRole.ADMIN)),
    ) -> RedirectResponse:
        temp = state.workspace / "staging" / "capability-manifest.json"
        temp.parent.mkdir(parents=True, exist_ok=True)
        try:
            payload = json.loads(manifest_text)
            payload.pop("content_digest", None)
            payload["content_digest"] = canonical_digest(payload)
            temp.write_bytes(canonical_json_bytes(payload) + b"\n")
            manifest = CommercialReadinessService().load_capability_manifest(temp)
            state.store.put(category="capabilities", artifact_id=f"capability-{manifest.distribution_version}", payload=manifest, actor_ref=current.actor_ref, role=current.role.value)
            return redirect("/capabilities", message="Capability manifest validated and stored.")
        except Exception as exc:
            return redirect("/capabilities", error=str(exc))

    @app.get("/custody", response_class=HTMLResponse)
    def custody(request: Request) -> HTMLResponse:
        latest = state.store.latest("custody")
        payload = _json(latest) if latest else None
        template_path = state.templates_dir / "custody-agreement-draft.json"
        initial = template_path.read_text(encoding="utf-8") if template_path.is_file() else "{}"
        return render(request, "custody.html", custody=payload, agreement_text=initial)

    @app.post("/custody/validate")
    def custody_validate(
        agreement_text: Annotated[str, Form()],
        as_of: Annotated[str, Form()],
        current: UiIdentity = Depends(require(UiRole.ADMIN)),
    ) -> RedirectResponse:
        temp = state.workspace / "staging" / "custody-agreement.json"
        temp.parent.mkdir(parents=True, exist_ok=True)
        try:
            payload = json.loads(agreement_text)
            payload.pop("content_digest", None)
            payload["content_digest"] = canonical_digest(payload)
            temp.write_bytes(canonical_json_bytes(payload) + b"\n")
            agreement = CommercialReadinessService().load_custody_agreement(temp, as_of=as_of)
            state.store.put(category="custody", artifact_id=agreement.agreement_id, payload=agreement, actor_ref=current.actor_ref, role=current.role.value)
            return redirect("/custody", message="Custody agreement validated and stored.")
        except Exception as exc:
            return redirect("/custody", error=str(exc))

    @app.get("/organic", response_class=HTMLResponse)
    def organic(request: Request) -> HTMLResponse:
        reports = [_json(path) for path in state.store.list("organic-reports")]
        return render(request, "organic.html", reports=reports)

    @app.post("/organic/run")
    def organic_run(
        manifest_path: Annotated[str, Form()],
        custody_path: Annotated[str, Form()],
        reviews_path: Annotated[str | None, Form()] = None,
        as_of: Annotated[str, Form()] = "2026-07-29T00:00:00Z",
        current: UiIdentity = Depends(require(UiRole.ANALYST)),
    ) -> RedirectResponse:
        try:
            commercial = CommercialReadinessService()
            organic_service = OrganicValidationService()
            custody_model = commercial.load_custody_agreement(Path(custody_path), as_of=as_of)
            manifest = organic_service.load_manifest(Path(manifest_path))
            reviews = organic_service.load_reviews(Path(reviews_path)) if reviews_path else None
            output_dir = state.workspace / "runs" / manifest.validation_id
            report = organic_service.run(manifest=manifest, custody=custody_model, output_dir=output_dir, reviews=reviews)
            state.store.put(category="organic-reports", artifact_id=report.validation_id, payload=report, actor_ref=current.actor_ref, role=current.role.value, action="ORGANIC_VALIDATION_COMPLETED")
            return redirect("/organic", message=f"Organic validation completed: {report.status.value}")
        except Exception as exc:
            return redirect("/organic", error=str(exc))

    @app.get("/reviews", response_class=HTMLResponse)
    def reviews(request: Request) -> HTMLResponse:
        template_path = state.templates_dir / "organic-review-batch-template.json"
        initial = template_path.read_text(encoding="utf-8") if template_path.is_file() else "{}"
        return render(request, "reviews.html", reviews=[_json(path) for path in state.store.list("reviews")], review_text=initial)

    @app.post("/reviews/store")
    def reviews_store(
        review_text: Annotated[str, Form()],
        current: UiIdentity = Depends(require(UiRole.REVIEWER)),
    ) -> RedirectResponse:
        try:
            payload = json.loads(review_text)
            payload.pop("content_digest", None)
            payload["content_digest"] = canonical_digest(payload)
            batch = OrganicReviewBatch.model_validate(payload)
            state.store.put(category="reviews", artifact_id=f"review-{batch.validation_id}", payload=batch, actor_ref=current.actor_ref, role=current.role.value, action="SME_REVIEW_STORED")
            return redirect("/reviews", message="SME review batch validated and stored.")
        except Exception as exc:
            return redirect("/reviews", error=str(exc))

    @app.get("/authority", response_class=HTMLResponse)
    def authority(request: Request) -> HTMLResponse:
        return render(request, "authority.html", validations=[_json(path) for path in state.store.list("authority")])

    @app.post("/authority/validate")
    def authority_validate(
        vocabulary_path: Annotated[str, Form()],
        classification_path: Annotated[str, Form()],
        current: UiIdentity = Depends(require(UiRole.REVIEWER)),
    ) -> RedirectResponse:
        try:
            vocabulary = VocabularySnapshot.model_validate_json(Path(vocabulary_path).read_text(encoding="utf-8"))
            classification = ClassificationSnapshot.model_validate_json(Path(classification_path).read_text(encoding="utf-8"))
            result = AuthoritySnapshotValidator().validate(vocabulary, classification)
            state.store.put(category="authority", artifact_id=f"authority-{vocabulary.snapshot_id}-{classification.snapshot_id}", payload=result, actor_ref=current.actor_ref, role=current.role.value, action="AUTHORITY_SNAPSHOTS_VALIDATED")
            return redirect("/authority", message=f"Authority validation: {result.validation_status.value}")
        except Exception as exc:
            return redirect("/authority", error=str(exc))

    @app.get("/catalog", response_class=HTMLResponse)
    def catalog(request: Request) -> HTMLResponse:
        values = [_json(path) for path in state.store.list("catalog")]
        initial = '{\n  "schema_name": "CLAIMS",\n  "relation_name": "CLAIM",\n  "columns": [],\n  "primary_key": [],\n  "unique_constraints": [],\n  "foreign_keys": [],\n  "check_constraints": [],\n  "temporal_kind": "NONE",\n  "provider_ref": "CUSTOMER_INPUT_REQUIRED"\n}'
        return render(request, "catalog.html", relations=values, catalog_text=initial)

    @app.post("/catalog/store")
    def catalog_store(
        catalog_text: Annotated[str, Form()],
        current: UiIdentity = Depends(require(UiRole.REVIEWER)),
    ) -> RedirectResponse:
        try:
            payload = json.loads(catalog_text)
            payload.pop("content_digest", None)
            payload["content_digest"] = canonical_digest(payload)
            relation = RelationDefinition.model_validate(payload)
            state.store.put(category="catalog", artifact_id=f"relation-{relation.schema_name}-{relation.relation_name}", payload=relation, actor_ref=current.actor_ref, role=current.role.value, action="CUSTOMER_CATALOG_RELATION_STORED")
            return redirect("/catalog", message="Relation metadata validated and stored as customer input.")
        except Exception as exc:
            return redirect("/catalog", error=str(exc))

    @app.get("/runtime", response_class=HTMLResponse)
    def runtime(request: Request) -> HTMLResponse:
        return render(request, "runtime.html", batches=[_json(path) for path in state.store.list("runtime")])

    @app.post("/runtime/import")
    def runtime_import(
        runtime_path: Annotated[str, Form()],
        current: UiIdentity = Depends(require(UiRole.ANALYST)),
    ) -> RedirectResponse:
        try:
            batch = RuntimeVerificationBatch.model_validate_json(Path(runtime_path).read_text(encoding="utf-8"))
            state.store.put(category="runtime", artifact_id=f"runtime-{batch.plan_batch_digest[-12:]}", payload=batch, actor_ref=current.actor_ref, role=current.role.value, action="RUNTIME_OBSERVATION_IMPORTED")
            return redirect("/runtime", message="Runtime verification batch imported as evidence only.")
        except Exception as exc:
            return redirect("/runtime", error=str(exc))

    @app.get("/runs", response_class=HTMLResponse)
    def runs(request: Request) -> HTMLResponse:
        analyses = state.procedure_analysis.list_analyses()[:20]
        current_analysis = None
        if analyses:
            try:
                current_analysis = state.procedure_analysis.load_analysis(str(analyses[0]["analysis_id"]))
            except ProcedureAnalysisError:
                current_analysis = None
        return render(
            request,
            "runs.html",
            databases=DATABASES,
            analyses=analyses,
            current_analysis=current_analysis,
        )

    @app.post("/runs/analyze")
    async def analyze_procedures(
        database_type: Annotated[str, Form()],
        input_mode: Annotated[str, Form()] = "paste",
        sql_text: Annotated[str, Form()] = "",
        files: Annotated[list[UploadFile] | None, File()] = None,
        current: UiIdentity = Depends(require(UiRole.ANALYST)),
    ) -> RedirectResponse:
        try:
            database = database_descriptor(database_type)
            collected_sources: list[SourceInput] = []
            if sql_text.strip():
                collected_sources.append(SourceInput(name="pasted-input.sql", text=sql_text, intake_kind="PASTE"))
            for upload in files or []:
                payload = await upload.read()
                if payload:
                    collected_sources.append(decode_upload(upload.filename or "source.sql", payload))
            if not collected_sources:
                raise ProcedureAnalysisError("Paste a stored procedure/script or upload at least one SQL file.")
            sources = tuple(collected_sources)
            analysis_dir, analysis = state.procedure_analysis.create_analysis(
                run_name="Stored procedure analysis",
                database=database,
                sources=sources,
                actor_ref=current.actor_ref,
                tenant_ref=resolved_settings.tenant_ref,
            )
            manifest = analysis_dir / "analysis.json"
            state.store.audit(
                actor_ref=current.actor_ref,
                role=current.role.value,
                action="STORED_PROCEDURES_ANALYZED",
                artifact_ref=manifest.relative_to(state.store.tenant_root).as_posix(),
                artifact_digest=str(analysis["content_digest"]),
                details={
                    "analysis_id": analysis["analysis_id"],
                    "database_type": analysis["database_type"],
                    "declared_dialect": analysis["declared_dialect"],
                    "source_count": analysis["counts"]["sources"],
                    "routine_count": analysis["counts"]["routines"],
                },
            )
            return redirect(
                f"/runs/{analysis['analysis_id']}",
                message="Stored procedures analyzed using the selected database.",
            )
        except ProcedureAnalysisError as exc:
            return redirect("/runs", error=str(exc))
        except Exception as exc:
            return redirect("/runs", error=f"Analysis failed: {exc}")

    @app.get("/runs/{analysis_id}", response_class=HTMLResponse)
    def procedure_analysis_result(request: Request, analysis_id: str) -> HTMLResponse:
        try:
            analysis = state.procedure_analysis.load_analysis(analysis_id)
        except ProcedureAnalysisError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return render(request, "procedure_run.html", analysis=analysis, databases=DATABASES)

    @app.get("/baseline", response_class=HTMLResponse)
    def baseline(request: Request) -> HTMLResponse:
        return render(request, "baseline.html", comparisons=[_json(path) for path in state.store.list("baseline")])

    @app.post("/baseline/register")
    def baseline_register(
        db_path: Annotated[str, Form()], artifact_id: Annotated[str, Form()], authority_ref: Annotated[str, Form()],
        effective_from: Annotated[str, Form()], current: UiIdentity = Depends(require(UiRole.REVIEWER)),
    ) -> RedirectResponse:
        try:
            store = GovernanceStore(Path(db_path)); store.initialize(applied_at=_now())
            result = store.register_baseline(artifact_id=artifact_id, authority_ref=authority_ref, effective_from=effective_from, actor_ref=current.actor_ref)
            state.store.put(category="baseline", artifact_id=f"baseline-registration-{artifact_id}", payload=result, actor_ref=current.actor_ref, role=current.role.value, action="ASSERTED_BASELINE_CACHED")
            return redirect("/baseline", message="Externally asserted baseline cached; no approval was inferred.")
        except Exception as exc:
            return redirect("/baseline", error=str(exc))

    @app.post("/baseline/compare")
    def baseline_compare(
        db_path: Annotated[str, Form()], artifact_id: Annotated[str, Form()], compared_at: Annotated[str, Form()],
        current: UiIdentity = Depends(require(UiRole.REVIEWER)),
    ) -> RedirectResponse:
        try:
            result = GovernanceStore(Path(db_path)).compare_to_baseline(candidate_artifact_id=artifact_id, compared_at=compared_at, actor_ref=current.actor_ref)
            state.store.put(category="baseline", artifact_id=f"baseline-comparison-{artifact_id}", payload=result, actor_ref=current.actor_ref, role=current.role.value, action="BASELINE_CANDIDATE_COMPARED")
            return redirect("/baseline", message="Candidate compared; conflict remains non-authoritative.")
        except Exception as exc:
            return redirect("/baseline", error=str(exc))

    @app.get("/support", response_class=HTMLResponse)
    def support(request: Request) -> HTMLResponse:
        return render(request, "support.html", cases=[_json(path) for path in state.store.list("support")])

    @app.post("/support/case")
    def support_case(
        case_id: Annotated[str, Form()], severity: Annotated[str, Form()], category: Annotated[str, Form()],
        finding_code: Annotated[str, Form()], customer_impact: Annotated[str, Form()],
        dialect: Annotated[str | None, Form()] = None, source_digest: Annotated[str | None, Form()] = None,
        materially_false: Annotated[str | None, Form()] = None,
        current: UiIdentity = Depends(require(UiRole.REVIEWER)),
    ) -> RedirectResponse:
        try:
            value = SupportCaseClassification(
                case_id=case_id, severity=SupportSeverity(severity), category=category, source_digest=source_digest or None,
                dialect=dialect or None, product_version="2.0.0rc5", stable_finding_code=finding_code,
                customer_impact=customer_impact, materially_false_confident_behavior=materially_false == "true", status="OPEN",
            )
            state.store.put(category="support", artifact_id=case_id, payload=value, actor_ref=current.actor_ref, role=current.role.value, action="SUPPORT_CASE_CLASSIFIED")
            return redirect("/support", message="Support case classified.")
        except Exception as exc:
            return redirect("/support", error=str(exc))

    @app.get("/dispositions", response_class=HTMLResponse)
    def dispositions(request: Request) -> HTMLResponse:
        organic_reports = [path for path in state.store.list("organic-reports")]
        values = [_json(path) for path in state.store.list("dispositions")]
        return render(request, "dispositions.html", reports=organic_reports, dispositions=values, decisions=[value.value for value in PauseDispositionDecision], causes=[value.value for value in PauseCause], responsibilities=[value.value for value in PauseResponsibility])

    @app.post("/dispositions/create")
    def disposition_create(
        report_path: Annotated[str, Form()],
        decision: Annotated[str, Form()],
        cause: Annotated[str, Form()],
        responsibility: Annotated[str, Form()],
        rationale: Annotated[str, Form()],
        remediation_actions: Annotated[str, Form()],
        target_reassessment_at: Annotated[str | None, Form()] = None,
        current: UiIdentity = Depends(require(UiRole.REVIEWER)),
    ) -> RedirectResponse:
        try:
            disposition = OrganicPauseDispositionService().build(
                report_path=Path(report_path),
                decision=PauseDispositionDecision(decision),
                cause=PauseCause(cause),
                responsibility=PauseResponsibility(responsibility),
                rationale=rationale,
                remediation_actions=tuple(line.strip() for line in remediation_actions.splitlines()),
                owner_ref=current.actor_ref,
                approved_by_ref=current.actor_ref if current.role is UiRole.ADMIN else None,
                decided_at=_now(),
                target_reassessment_at=target_reassessment_at or None,
            )
            state.store.put(category="dispositions", artifact_id=disposition.disposition_id, payload=disposition, actor_ref=current.actor_ref, role=current.role.value, action="ORGANIC_PAUSE_DISPOSITION_CREATED")
            return redirect("/dispositions", message="Pause disposition created.")
        except Exception as exc:
            return redirect("/dispositions", error=str(exc))

    @app.get("/checks", response_class=HTMLResponse)
    def checks(request: Request) -> HTMLResponse:
        values = [_json(path) for path in state.store.list("procedure-checks")]
        return render(request, "checks.html", reports=values)

    @app.post("/checks/build")
    def checks_build(
        run_dir: Annotated[str, Form()],
        current: UiIdentity = Depends(require(UiRole.ANALYST)),
    ) -> RedirectResponse:
        try:
            report = ProcedureCheckService().build(Path(run_dir))
            state.store.put(category="procedure-checks", artifact_id=report.report_id, payload=report, actor_ref=current.actor_ref, role=current.role.value)
            return redirect("/checks", message="Procedure check report generated.")
        except Exception as exc:
            return redirect("/checks", error=str(exc))

    @app.get("/fixtures", response_class=HTMLResponse)
    def fixtures(request: Request) -> HTMLResponse:
        return render(request, "fixtures.html", plans=[_json(path) for path in state.store.list("fixture-plans")])

    @app.post("/fixtures/plan")
    def fixtures_plan(
        procedure_ref: Annotated[str, Form()], relation_refs: Annotated[str, Form()], catalog_paths: Annotated[str, Form()],
        current: UiIdentity = Depends(require(UiRole.ANALYST)),
    ) -> RedirectResponse:
        try:
            plan = RelationalFixturePlanningService().build(
                procedure_ref=procedure_ref,
                relation_refs=tuple(line.strip() for line in relation_refs.splitlines()),
                catalog_paths=tuple(Path(line.strip()) for line in catalog_paths.splitlines() if line.strip()),
            )
            state.store.put(category="fixture-plans", artifact_id=plan.plan_id, payload=plan, actor_ref=current.actor_ref, role=current.role.value, action="RELATIONAL_FIXTURE_PLAN_CREATED")
            return redirect("/fixtures", message=f"Fixture plan created: {plan.status.value}")
        except Exception as exc:
            return redirect("/fixtures", error=str(exc))

    @app.get("/composition", response_class=HTMLResponse)
    def composition(request: Request) -> HTMLResponse:
        values = [_json(path) for path in state.store.list("composition")]
        return render(request, "composition.html", assessments=values)

    @app.post("/composition/assess")
    def composition_assess(
        contract_path: Annotated[str, Form()],
        upstream_digest: Annotated[str, Form()],
        downstream_digest: Annotated[str, Form()],
        transaction_digest: Annotated[str | None, Form()] = None,
        orchestration_digest: Annotated[str | None, Form()] = None,
        current: UiIdentity = Depends(require(UiRole.REVIEWER)),
    ) -> RedirectResponse:
        try:
            contract = ProcedureCompositionContract.model_validate_json(Path(contract_path).read_text(encoding="utf-8"))
            without = contract.model_dump(mode="python", exclude={"content_digest"})
            if contract.content_digest != canonical_digest(without):
                raise CommercialWorkflowError("Composition contract digest mismatch.")
            assessment = CompositionContractService().assess(contract, upstream_semantic_digest=upstream_digest, downstream_semantic_digest=downstream_digest, transaction_contract_digest=transaction_digest or None, orchestration_definition_digest=orchestration_digest or None)
            state.store.put(category="composition", artifact_id=f"assessment-{contract.contract_id}", payload=assessment, actor_ref=current.actor_ref, role=current.role.value)
            return redirect("/composition", message=f"Composition assessed: {assessment.resolution.value}")
        except Exception as exc:
            return redirect("/composition", error=str(exc))

    @app.get("/graph", response_class=HTMLResponse)
    def graph(request: Request) -> HTMLResponse:
        latest = state.store.latest("graphs")
        payload = _json(latest) if latest else None
        return render(request, "graph.html", graph=payload)

    @app.post("/graph/build")
    def graph_build(
        run_dir: Annotated[str, Form()],
        current: UiIdentity = Depends(require(UiRole.ANALYST)),
    ) -> RedirectResponse:
        try:
            graph_value = ProcedureKnowledgeGraphService().build(Path(run_dir))
            state.store.put(category="graphs", artifact_id=graph_value.graph_id, payload=graph_value, actor_ref=current.actor_ref, role=current.role.value)
            return redirect("/graph", message="Knowledge graph generated from existing evidence.")
        except Exception as exc:
            return redirect("/graph", error=str(exc))

    @app.get("/readiness", response_class=HTMLResponse)
    def readiness(request: Request) -> HTMLResponse:
        latest = state.store.latest("readiness")
        payload = _json(latest) if latest else None
        return render(request, "readiness.html", readiness=payload)

    @app.post("/readiness/assess")
    def readiness_assess(
        capabilities_path: Annotated[str, Form()],
        as_of: Annotated[str, Form()],
        custody_path: Annotated[str | None, Form()] = None,
        organic_report_path: Annotated[str | None, Form()] = None,
        gate_evidence_path: Annotated[str | None, Form()] = None,
        current: UiIdentity = Depends(require(UiRole.ADMIN)),
    ) -> RedirectResponse:
        try:
            service = CommercialReadinessService()
            capability = service.load_capability_manifest(Path(capabilities_path))
            custody_model = service.load_custody_agreement(Path(custody_path), as_of=as_of) if custody_path else None
            organic_report = service.load_organic_report(Path(organic_report_path)) if organic_report_path else None
            gate_evidence = service.load_gate_evidence(Path(gate_evidence_path)) if gate_evidence_path else None
            report = service.assess(capabilities=capability, custody=custody_model, organic=organic_report, gate_evidence=gate_evidence, deployment_gates=(), customer_boundary_gates=())
            state.store.put(category="readiness", artifact_id=f"readiness-{capability.distribution_version}", payload=report, actor_ref=current.actor_ref, role=current.role.value, action="COMMERCIAL_READINESS_ASSESSED")
            return redirect("/readiness", message=f"Readiness assessed with {len(report.blockers)} blockers.")
        except Exception as exc:
            return redirect("/readiness", error=str(exc))

    @app.get("/operations", response_class=HTMLResponse)
    def operations(request: Request) -> HTMLResponse:
        return render(request, "operations.html", operation_artifacts=[_json(path) for path in state.store.list("operations")])

    @app.post("/operations/sbom")
    def operation_sbom(current: UiIdentity = Depends(require(UiRole.ADMIN))) -> RedirectResponse:
        try:
            temp = state.workspace / "staging" / "sbom.cdx.json"
            CommercialOperationsService().generate_sbom(temp)
            payload = _json(temp)
            path = state.store.put(category="operations", artifact_id="sbom", payload=payload, actor_ref=current.actor_ref, role=current.role.value, action="SBOM_GENERATED")
            return redirect("/operations", message=f"SBOM generated: {path.name}")
        except Exception as exc:
            return redirect("/operations", error=str(exc))

    @app.post("/operations/support-bundle")
    def operation_support_bundle(
        run_dir: Annotated[str, Form()],
        current: UiIdentity = Depends(require(UiRole.ADMIN)),
    ) -> RedirectResponse:
        try:
            output = state.store.tenant_root / "bundles" / f"support-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.zip"
            CommercialOperationsService().build_support_bundle(run_dir=Path(run_dir), output=output, include_source=False)
            state.store.audit(actor_ref=current.actor_ref, role=current.role.value, action="SUPPORT_BUNDLE_GENERATED", artifact_ref=output.relative_to(state.store.tenant_root).as_posix(), artifact_digest="sha256:" + __import__("hashlib").sha256(output.read_bytes()).hexdigest(), details={"source_included": False})
            return redirect("/operations", message=f"Support bundle generated: {output.name}")
        except Exception as exc:
            return redirect("/operations", error=str(exc))

    @app.post("/operations/backup")
    def operation_backup(current: UiIdentity = Depends(require(UiRole.ADMIN))) -> RedirectResponse:
        try:
            output = state.store.tenant_root / "backups" / f"artifact-backup-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.zip"
            CommercialDataLifecycleService().backup_tenant_artifacts(store=state.store, output=output)
            state.store.audit(actor_ref=current.actor_ref, role=current.role.value, action="COMMERCIAL_ARTIFACT_BACKUP_CREATED", artifact_ref=output.relative_to(state.store.tenant_root).as_posix(), artifact_digest="sha256:" + __import__("hashlib").sha256(output.read_bytes()).hexdigest(), details={"source_included": False})
            return redirect("/operations", message=f"Artifact backup created: {output.name}")
        except Exception as exc:
            return redirect("/operations", error=str(exc))

    @app.post("/operations/deletion")
    def operation_deletion(
        request_path: Annotated[str, Form()], as_of: Annotated[str, Form()],
        current: UiIdentity = Depends(require(UiRole.ADMIN)),
    ) -> RedirectResponse:
        try:
            request_model = CommercialDeletionRequest.model_validate_json(Path(request_path).read_text(encoding="utf-8"))
            attestation = CommercialDataLifecycleService().execute_deletion(
                store=state.store, request=request_model, executed_by_ref=current.actor_ref, executed_role=current.role.value, as_of=as_of
            )
            return redirect("/operations", message=f"Deletion completed and attested: {attestation.attestation_id}")
        except Exception as exc:
            return redirect("/operations", error=str(exc))

    @app.post("/operations/metering")
    def operation_metering(
        period_start: Annotated[str, Form()],
        period_end: Annotated[str, Form()],
        current: UiIdentity = Depends(require(UiRole.ADMIN)),
    ) -> RedirectResponse:
        try:
            snapshot = CommercialOperationsService().meter_workspace(store=state.store, period_start=period_start, period_end=period_end)
            state.store.put(category="operations", artifact_id=f"metering-{period_start}-{period_end}", payload=snapshot, actor_ref=current.actor_ref, role=current.role.value, action="METERING_SNAPSHOT_CREATED")
            return redirect("/operations", message="Metering snapshot created.")
        except Exception as exc:
            return redirect("/operations", error=str(exc))

    @app.get("/audit", response_class=HTMLResponse)
    def audit(request: Request) -> HTMLResponse:
        return render(request, "audit.html", events=state.store.audit_events(500))

    @app.get("/api/artifacts")
    def api_artifacts(category: str | None = None) -> dict[str, object]:
        return {"tenant_ref": state.store.tenant_ref, "artifacts": [path.relative_to(state.store.tenant_root).as_posix() for path in state.store.list(category)]}

    @app.get("/api/graph")
    def api_graph() -> dict[str, object]:
        latest = state.store.latest("graphs")
        return _json(latest) if latest else {"nodes": [], "edges": []}

    @app.get("/download/{bundle_path:path}")
    def download(bundle_path: str, current: UiIdentity = Depends(require(UiRole.VIEWER))) -> FileResponse:
        candidate = (state.store.tenant_root / bundle_path).resolve()
        try:
            candidate.relative_to(state.store.tenant_root)
        except ValueError as exc:
            raise HTTPException(status_code=403, detail="Path escapes tenant workspace.") from exc
        if not candidate.is_file():
            raise HTTPException(status_code=404, detail="File not found.")
        return FileResponse(candidate)

    return app
