"""Database layer using SQLAlchemy."""
import json
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from src.config_loader import get_settings

Base = declarative_base()


class RawContentORM(Base):
    __tablename__ = "raw_contents"

    id = Column(String(64), primary_key=True)
    source_name = Column(String(100), nullable=False, index=True)
    url = Column(Text, nullable=True)
    title = Column(Text, nullable=True)
    content = Column(Text, nullable=False)
    content_hash = Column(String(64), nullable=False, unique=True, index=True)
    collected_at = Column(DateTime, default=datetime.utcnow)
    metadata_json = Column(JSON, default=dict)


class ThreatIntelligenceORM(Base):
    __tablename__ = "threat_intelligence"

    id = Column(String(64), primary_key=True)
    title = Column(Text, nullable=False)
    threat_type = Column(String(100), nullable=False, index=True)
    iocs_json = Column(JSON, default=list)
    involved_assets_json = Column(JSON, default=list)
    satellite_model = Column(String(100), default="")
    confidence = Column(Float, nullable=False, index=True)
    source = Column(String(100), nullable=False, index=True)
    raw_text = Column(Text, nullable=False)
    summary = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    is_valid = Column(Boolean, default=False, index=True)
    validation_reason = Column(Text, default="")


class EvaluationResultORM(Base):
    __tablename__ = "evaluation_results"

    id = Column(String(64), primary_key=True)
    run_at = Column(DateTime, default=datetime.utcnow)
    benchmark_path = Column(Text, nullable=False)
    results_json = Column(JSON, default=dict)
    winner = Column(String(20), nullable=True)
    notes = Column(Text, default="")


class ReviewORM(Base):
    __tablename__ = "reviews"

    id = Column(String(64), primary_key=True)
    intelligence_id = Column(String(64), nullable=False, index=True)
    version = Column(String(20), default="")
    reviewer_mode = Column(String(20), default="rule")
    approved = Column(Boolean, nullable=False)
    issue_codes = Column(JSON, default=list)
    rounds = Column(Integer, default=1)
    confidence_before = Column(Float, default=0.0)
    confidence_after = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class DomainMetricORM(Base):
    __tablename__ = "domain_metrics"

    id = Column(String(64), primary_key=True)
    domain = Column(String(100), nullable=False, index=True)
    run_at = Column(DateTime, default=datetime.utcnow, index=True)
    matched_items = Column(Integer, default=0)
    total_sources = Column(Integer, default=0)
    dark_sources = Column(Integer, default=0)
    matched_keywords_json = Column(JSON, default=list)
    sample_summary = Column(Text, default="")


class ThreatEventORM(Base):
    __tablename__ = "threat_events"

    id = Column(String(64), primary_key=True)
    title = Column(Text, nullable=False)
    key_indicators = Column(JSON, default=list)
    intel_ids = Column(JSON, default=list)
    sources = Column(JSON, default=list)
    source_count = Column(Integer, default=0)
    threat_types = Column(JSON, default=list)
    confidence = Column(Float, default=0.0)
    corroborated = Column(Boolean, default=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class Database:
    def __init__(self, db_url: Optional[str] = None):
        settings = get_settings()
        if db_url is None:
            sqlite_path = settings.get("storage.sqlite_path", "data/threat_intel.db")
            db_url = f"sqlite:///{sqlite_path}"
        self.engine = create_engine(db_url, echo=settings.get("storage.echo", False))
        # Keep instances readable after the session context exits (dashboard does
        # attribute reads on returned ORM objects); avoid expired attributes.
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

    def create_tables(self):
        Base.metadata.create_all(self.engine)

    @contextmanager
    def session(self):
        s = self.Session()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    def save_raw_content(self, raw: "RawContent") -> bool:  # type: ignore
        from src.models.source import RawContent

        with self.session() as s:
            existing = s.query(RawContentORM).filter_by(content_hash=raw.content_hash).first()
            if existing:
                return False
            s.add(
                RawContentORM(
                    id=raw.id,
                    source_name=raw.source_name,
                    url=raw.url,
                    title=raw.title,
                    content=raw.content,
                    content_hash=raw.content_hash,
                    collected_at=raw.collected_at,
                    metadata_json=raw.metadata,
                )
            )
        return True

    def save_intelligence(self, intel) -> None:
        fields = dict(
            title=intel.title,
            threat_type=intel.threat_type,
            iocs_json=intel.iocs,
            involved_assets_json=intel.involved_assets,
            satellite_model=intel.satellite_model or "",
            confidence=intel.confidence,
            source=intel.source,
            raw_text=intel.raw_text,
            summary=intel.summary,
            created_at=intel.created_at,
            is_valid=intel.is_valid,
            validation_reason=intel.validation_reason,
        )
        with self.session() as s:
            existing = s.get(ThreatIntelligenceORM, intel.id)
            if existing:
                # Upsert: the validator updates rows already inserted by the analyzer.
                for key, value in fields.items():
                    setattr(existing, key, value)
            else:
                s.add(ThreatIntelligenceORM(id=intel.id, **fields))

    def list_intelligence(
        self, is_valid: Optional[bool] = None, limit: int = 100, offset: int = 0
    ) -> List[ThreatIntelligenceORM]:
        with self.session() as s:
            q = s.query(ThreatIntelligenceORM)
            if is_valid is not None:
                q = q.filter_by(is_valid=is_valid)
            return q.order_by(ThreatIntelligenceORM.created_at.desc()).offset(offset).limit(limit).all()

    def count_intelligence(self, is_valid: Optional[bool] = None) -> int:
        with self.session() as s:
            q = s.query(ThreatIntelligenceORM)
            if is_valid is not None:
                q = q.filter_by(is_valid=is_valid)
            return q.count()

    def count_raw_contents(self) -> int:
        with self.session() as s:
            return s.query(RawContentORM).count()

    def save_evaluation_record(self, evaluation_result) -> str:
        """Persist an A/B evaluation result and return its record id."""
        from src.models.evaluation import EvaluationResult

        record_id = str(uuid4())
        results_json = {
            version: metrics.model_dump()
            for version, metrics in evaluation_result.results.items()
        }
        with self.session() as s:
            s.add(
                EvaluationResultORM(
                    id=record_id,
                    benchmark_path=evaluation_result.benchmark_path,
                    results_json=results_json,
                    winner=evaluation_result.winner,
                    notes=evaluation_result.notes,
                )
            )
        return record_id

    def list_evaluation_records(self, limit: int = 10) -> List[EvaluationResultORM]:
        with self.session() as s:
            return (
                s.query(EvaluationResultORM)
                .order_by(EvaluationResultORM.run_at.desc())
                .limit(limit)
                .all()
            )

    def save_review(self, record) -> None:
        """Persist one review record emitted by the collaboration loop."""
        with self.session() as s:
            s.add(
                ReviewORM(
                    id=record.id,
                    intelligence_id=record.intelligence_id,
                    version=record.version,
                    reviewer_mode=record.reviewer_mode,
                    approved=record.approved,
                    issue_codes=record.issue_codes,
                    rounds=record.rounds,
                    confidence_before=record.confidence_before,
                    confidence_after=record.confidence_after,
                    created_at=record.created_at,
                )
            )

    def count_reviews(self, approved: Optional[bool] = None) -> int:
        with self.session() as s:
            q = s.query(ReviewORM)
            if approved is not None:
                q = q.filter_by(approved=approved)
            return q.count()

    def list_reviews(self, limit: int = 100) -> List[ReviewORM]:
        with self.session() as s:
            return s.query(ReviewORM).order_by(ReviewORM.created_at.desc()).limit(limit).all()

    def save_event(self, event) -> None:
        with self.session() as s:
            existing = s.get(ThreatEventORM, event.id)
            fields = dict(
                title=event.title,
                key_indicators=event.key_indicators,
                intel_ids=event.intel_ids,
                sources=event.sources,
                source_count=event.source_count,
                threat_types=event.threat_types,
                confidence=event.confidence,
                corroborated=event.corroborated,
                first_seen=event.first_seen,
                last_seen=event.last_seen,
                created_at=event.created_at,
            )
            if existing:
                for key, value in fields.items():
                    setattr(existing, key, value)
            else:
                s.add(ThreatEventORM(id=event.id, **fields))

    def count_events(self, corroborated: Optional[bool] = None) -> int:
        with self.session() as s:
            q = s.query(ThreatEventORM)
            if corroborated is not None:
                q = q.filter_by(corroborated=corroborated)
            return q.count()

    def list_events(self, limit: int = 50) -> List[ThreatEventORM]:
        with self.session() as s:
            return s.query(ThreatEventORM).order_by(ThreatEventORM.last_seen.desc()).limit(limit).all()

    def save_domain_metrics(self, metrics: List["DomainMetric"]) -> None:  # type: ignore
        """Persist a batch of per-domain monitoring metrics in one transaction."""
        from src.models.metric import DomainMetric

        with self.session() as s:
            for metric in metrics:
                s.add(
                    DomainMetricORM(
                        id=metric.id,
                        domain=metric.domain,
                        run_at=metric.run_at,
                        matched_items=metric.matched_items,
                        total_sources=metric.total_sources,
                        dark_sources=metric.dark_sources,
                        matched_keywords_json=metric.matched_keywords,
                        sample_summary=metric.sample_summary,
                    )
                )

    def latest_domain_metrics(self, limit_per_domain: int = 5) -> List[DomainMetricORM]:
        """Most recent metric rows per domain (multi-domain monitoring dashboard).

        SQLite lacks portable window functions, so we pull rows ordered by the
        newest run and dedupe per domain in Python — the dataset is small.
        """
        with self.session() as s:
            rows = (
                s.query(DomainMetricORM)
                .order_by(DomainMetricORM.run_at.desc())
                .all()
            )
        seen: dict = {}
        for row in rows:
            seen.setdefault(row.domain, []).append(row)
        latest: List[DomainMetricORM] = []
        for domain_rows in seen.values():
            latest.extend(domain_rows[:limit_per_domain])
        latest.sort(key=lambda r: r.run_at, reverse=True)
        return latest

    def list_domain_metrics(self, limit: int = 100) -> List[DomainMetricORM]:
        with self.session() as s:
            return s.query(DomainMetricORM).order_by(DomainMetricORM.run_at.desc()).limit(limit).all()


def init_db():
    settings = get_settings()
    sqlite_path = settings.get("storage.sqlite_path", "data/threat_intel.db")
    Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)
    db = Database()
    db.create_tables()
    print(f"Database initialized at: {sqlite_path}")
