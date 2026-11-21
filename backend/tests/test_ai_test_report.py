"""Raport „Czy nasz agent AI jest bezpieczny?” z wyników testu agenta (§23.4)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models import AgentTestCaseResult, AgentTestRun, AuditLog, ReportDelivery
from app.reports.ai_test import AiTestReportError, create_ai_test_report
from app.reports.config import ReportsConfig
from app.reports.pdf import render_html, report_view
from app.reports.service import template_is_valid
from tests.pipeline_helpers import RULES

CONFIG = ReportsConfig.from_dir(RULES)


def _run(session: Session, results: list[tuple[str, bool, bool]]) -> uuid.UUID:
    run = AgentTestRun(
        suite="quick",
        trigger="manual",
        requested_by="admin",
        status="done",
        result_sha256="ab" * 32,
        finished_at=datetime(2026, 11, 21, 6, 0, tzinfo=UTC),
    )
    session.add(run)
    session.flush()
    for index, (category, model, code) in enumerate(results):
        session.add(
            AgentTestCaseResult(
                run_id=run.id,
                case_id=f"case_{index}",
                category=category,
                title=f"Przypadek {index}",
                model_resisted=model,
                code_held=code,
            )
        )
    session.flush()
    return run.id


@pytest.mark.parametrize(
    ("results", "light"),
    [
        ([("scope", True, True), ("injection", True, True)], "green"),
        ([("scope", True, True), ("injection", False, True)], "yellow"),
        ([("scope", True, True), ("injection", False, False)], "red"),
    ],
)
def test_light_follows_code_and_model_results(
    session_factory: sessionmaker[Session], results: list[tuple[str, bool, bool]], light: str
) -> None:
    with session_factory() as session:
        run_id = _run(session, results)
        report = create_ai_test_report(session, CONFIG, run_id, actor="test")
        assert report.kind == "ai_test"
        assert report.light == light
        assert template_is_valid(report, CONFIG).ok, template_is_valid(report, CONFIG)
        assert len(report.technical["rows"]) == 2
        assert session.scalars(
            select(ReportDelivery).where(ReportDelivery.report_id == report.id)
        ).all()


def test_report_is_created_once_per_run_and_renders(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        run_id = _run(session, [("injection", False, True)])
        first = create_ai_test_report(session, CONFIG, run_id, actor="test")
        again = create_ai_test_report(session, CONFIG, run_id, actor="test")
        assert again.id == first.id
        html = render_html(
            report_view(first, technical=True, personal=False),
            generated_at=datetime(2026, 11, 21, tzinfo=UTC),
            audience="menedżer",
        )
        assert "Przypadki testu (1)" in html
        assert "Kod zatrzymał" in html
        audits = session.scalars(select(AuditLog).where(AuditLog.action == "report_created")).all()
        assert len(audits) == 1


def test_unfinished_run_is_rejected(session_factory: sessionmaker[Session]) -> None:
    with session_factory() as session:
        run = AgentTestRun(suite="quick", trigger="manual", requested_by="admin", status="running")
        session.add(run)
        session.flush()
        with pytest.raises(AiTestReportError):
            create_ai_test_report(session, CONFIG, run.id, actor="test")
