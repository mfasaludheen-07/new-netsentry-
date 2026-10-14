from datetime import datetime
from app.extensions import db
from app.models import NetworkEvent, EventCorrelation, CaseEvent


class CorrelationEngine:
    @classmethod
    def correlate_events(cls, case_id: str = None) -> dict:
        """
        Analyzes network events to discover high-confidence correlation pairs.
        Can run scoped to a specific case_id or the recent dataset.
        """
        correlated_count = 0

        if case_id:
            events = db.session.query(NetworkEvent).join(
                CaseEvent, NetworkEvent.id == CaseEvent.event_id
            ).filter(CaseEvent.case_id == case_id).order_by(NetworkEvent.timestamp.asc()).all()
        else:
            events = NetworkEvent.query.order_by(NetworkEvent.timestamp.asc()).limit(500).all()

        n = len(events)
        for i in range(n):
            for j in range(i + 1, n):
                ev_a = events[i]
                ev_b = events[j]

                # Time delta
                delta_sec = abs((ev_b.timestamp - ev_a.timestamp).total_seconds())
                if delta_sec > 600:
                    continue  # Beyond 10-minute correlation window

                reasons = []
                corr_type = 'TEMPORAL_LINK'
                confidence = 'LOW'

                # Same endpoint
                if ev_a.hostname and ev_b.hostname and ev_a.hostname == ev_b.hostname:
                    reasons.append(f"Same internal origin endpoint ({ev_a.hostname})")
                    confidence = 'MEDIUM'

                # Matching source IP
                if ev_a.source_ip == ev_b.source_ip:
                    reasons.append(f"Matching source IP ({ev_a.source_ip})")

                # Identical destination IP (shared target)
                if ev_a.destination_ip == ev_b.destination_ip:
                    reasons.append(f"Identical target destination IP ({ev_a.destination_ip})")
                    corr_type = 'SHARED_DESTINATION'
                    confidence = 'HIGH'

                # Shared domain
                if ev_a.domain and ev_b.domain and ev_a.domain == ev_b.domain:
                    reasons.append(f"Shared target domain ({ev_a.domain})")
                    corr_type = 'SHARED_DOMAIN'
                    confidence = 'HIGH'

                # Sequence 1: DNS query followed by connection attempt
                if ev_a.event_type == 'dns_query' and ev_b.event_type == 'connection' and delta_sec <= 60:
                    reasons.append(f"Sequential DNS resolution followed by connection attempt within {int(delta_sec)}s")
                    corr_type = 'DNS_TO_CONNECTION'
                    confidence = 'HIGH'

                # Sequence 2: Recon probing followed by session
                if ev_a.destination_port != ev_b.destination_port and ev_a.destination_ip == ev_b.destination_ip and delta_sec <= 180:
                    reasons.append(f"Reconnaissance probing followed by lateral port interaction within {int(delta_sec)}s")
                    corr_type = 'RECON_TO_EXPLOIT'
                    confidence = 'HIGH'

                if len(reasons) >= 2:
                    reason_text = f"{'; '.join(reasons)} (Δt = {int(delta_sec)}s)."
                    # Check if already correlated
                    existing = EventCorrelation.query.filter_by(
                        event_a_id=ev_a.id,
                        event_b_id=ev_b.id
                    ).first()

                    if not existing:
                        corr = EventCorrelation(
                            case_id=case_id,
                            event_a_id=ev_a.id,
                            event_b_id=ev_b.id,
                            correlation_type=corr_type,
                            correlation_reason=reason_text,
                            confidence=confidence
                        )
                        db.session.add(corr)
                        correlated_count += 1

        db.session.commit()
        return {'correlated_pairs': correlated_count}
