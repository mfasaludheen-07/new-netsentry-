from datetime import datetime, timezone
from app.extensions import db
from app.models import TimelineEvent


class TimelineService:
    @classmethod
    def get_timeline(cls, case_id: str = None, filters: dict = None) -> list:
        filters = filters or {}
        query = TimelineEvent.query

        if case_id:
            query = query.filter_by(case_id=case_id)

        if filters.get('event_type'):
            query = query.filter_by(event_type=filters['event_type'])

        if filters.get('severity'):
            query = query.filter_by(severity=filters['severity'])

        if filters.get('search'):
            term = f"%{filters['search']}%"
            query = query.filter(
                (TimelineEvent.description.ilike(term)) |
                (TimelineEvent.source.ilike(term)) |
                (TimelineEvent.destination.ilike(term))
            )

        return query.order_by(TimelineEvent.event_time.asc(), TimelineEvent.id.asc()).all()

    @classmethod
    def add_event(
        cls,
        case_id: str,
        event_time: datetime,
        event_type: str,
        description: str,
        severity: str = 'INFO',
        source: str = None,
        destination: str = None,
        protocol: str = None,
        reference_type: str = None,
        reference_id: str = None
    ) -> int:
        if event_time is None:
            event_time = datetime.now(timezone.utc)

        tl_event = TimelineEvent(
            case_id=case_id,
            event_time=event_time,
            event_type=event_type,
            source=source,
            destination=destination,
            protocol=protocol,
            severity=severity,
            description=description,
            reference_type=reference_type,
            reference_id=str(reference_id) if reference_id else None
        )
        db.session.add(tl_event)
        db.session.commit()
        return tl_event.id
