"""Persistent, explainable response rules for classified honeypot sessions."""

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from database.db import (
    DEFAULT_DB_PATH,
    create_adaptive_action,
    create_alert,
    get_session,
    list_adaptive_actions,
)


MALICIOUS_LABELS = frozenset(
    {"brute_force", "port_scan", "sql_injection", "directory_probe"}
)
ALLOWED_LABELS = MALICIOUS_LABELS | {"benign"}
INITIAL_ALERT_THRESHOLD = 0.8
MIN_ALERT_THRESHOLD = 0.5
MAX_ALERT_THRESHOLD = 0.95
THRESHOLD_STEP = 0.05
BEHAVIOUR_WINDOW = 5
MALICIOUS_STREAK_FOR_RATE_LIMIT = 3
RATE_LIMIT_DURATION_SECONDS = 60
RATE_LIMIT_RETRY_AFTER_SECONDS = 1
MAX_ACTION_HISTORY = 1000
SCAN_BANNER = "Restricted system monitor"


@dataclass(frozen=True)
class SourceControls:
    alert_threshold: float
    rate_limited: bool
    retry_after_seconds: int
    scan_banner: bool


@dataclass(frozen=True)
class AdaptiveDecision:
    session_id: int
    source_ip: str
    classification: str
    confidence: float
    alert_threshold: float
    alert_created: bool
    rate_limited: bool
    scan_banner: bool


def _validate_session_id(session_id: int) -> int:
    if type(session_id) is not int or session_id < 1:
        raise ValueError("session_id must be a positive integer.")
    return session_id


def _validate_confidence(confidence: float) -> float:
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0 <= confidence <= 1
    ):
        raise ValueError("confidence must be a number from 0 through 1.")
    return float(confidence)


def _validate_classification(classification: str) -> str:
    if not isinstance(classification, str) or classification not in ALLOWED_LABELS:
        raise ValueError(
            f"classification must be one of: {', '.join(sorted(ALLOWED_LABELS))}."
        )
    return classification


def _validate_db_path(db_path: str | Path) -> str | Path:
    if not isinstance(db_path, (str, Path)) or not str(db_path).strip():
        raise ValueError("db_path must be a non-empty path.")
    return db_path


def _source_actions(source_ip: str, db_path: str | Path) -> list[dict[str, object]]:
    actions = list_adaptive_actions(limit=MAX_ACTION_HISTORY, db_path=db_path)
    return [
        action
        for action in reversed(actions)
        if isinstance(action.get("details"), dict)
        and action["details"].get("source_ip") == source_ip
    ]


def get_source_controls(
    source_ip: str,
    *,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> SourceControls:
    """Return currently persisted controls for a validated IPv4/IPv6 source."""
    db_path = _validate_db_path(db_path)
    if not isinstance(source_ip, str):
        raise ValueError("source_ip must be a valid IPv4 or IPv6 address.")
    try:
        normalized_ip = str(ipaddress.ip_address(source_ip))
    except ValueError as exc:
        raise ValueError("source_ip must be a valid IPv4 or IPv6 address.") from exc

    threshold = INITIAL_ALERT_THRESHOLD
    limited_until: datetime | None = None
    scan_banner = False
    for action in _source_actions(normalized_ip, db_path):
        action_type = action["action_type"]
        details = action["details"]
        if action_type == "threshold_adjusted":
            threshold = float(details["new_threshold"])
        elif action_type == "rate_limit_enabled":
            created_at = datetime.fromisoformat(str(action["created_at"])).replace(
                tzinfo=timezone.utc
            )
            limited_until = created_at + timedelta(
                seconds=int(details["duration_seconds"])
            )
        elif action_type == "rate_limit_cleared":
            limited_until = None
        elif action_type == "scan_banner_changed":
            scan_banner = True
        elif action_type == "scan_banner_reset":
            scan_banner = False

    now = datetime.now(timezone.utc)
    active_limit = limited_until is not None and limited_until > now
    return SourceControls(
        alert_threshold=threshold,
        rate_limited=active_limit,
        retry_after_seconds=RATE_LIMIT_RETRY_AFTER_SECONDS if active_limit else 0,
        scan_banner=scan_banner,
    )


def observe_classification(
    session_id: int,
    classification: str,
    confidence: float,
    *,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> AdaptiveDecision:
    """Record a classifier result and apply threshold, rate-limit, and banner rules.

    Rules:
    - Lower the alert threshold by 0.05 when at least 60% of the last five
      classifications from this source are malicious; raise it by 0.05 when
      at least 80% are benign. Keep it between 0.50 and 0.95.
    - Enable a 60-second, one-second retry-after rate limit after three
      consecutive malicious classifications that meet the active threshold.
    - Change the banner after a sufficiently confident port-scan classification.
    - Clear an active rate limit after three consecutive benign classifications.

    Each classification and every resulting adaptation is persisted to
    adaptive_actions, associated with its session, and malicious alerts are
    also recorded in alerts.
    """
    session_id = _validate_session_id(session_id)
    classification = _validate_classification(classification)
    confidence = _validate_confidence(confidence)
    db_path = _validate_db_path(db_path)

    session = get_session(session_id, db_path=db_path)
    if session is None:
        raise ValueError(f"Session {session_id} does not exist.")
    source_ip = str(session["source_ip"])
    source_actions = _source_actions(source_ip, db_path)
    controls = get_source_controls(source_ip, db_path=db_path)
    previous_classifications = [
        action
        for action in source_actions
        if action["action_type"] == "classification_observed"
    ]

    recent = previous_classifications[-(BEHAVIOUR_WINDOW - 1) :] + [
        {"details": {"classification": classification}}
    ]
    recent_labels = [action["details"]["classification"] for action in recent]
    malicious_ratio = sum(label in MALICIOUS_LABELS for label in recent_labels) / len(
        recent_labels
    )
    benign_ratio = recent_labels.count("benign") / len(recent_labels)
    new_threshold = controls.alert_threshold
    if len(recent_labels) == BEHAVIOUR_WINDOW and malicious_ratio >= 0.6:
        new_threshold = max(MIN_ALERT_THRESHOLD, new_threshold - THRESHOLD_STEP)
    elif len(recent_labels) == BEHAVIOUR_WINDOW and benign_ratio >= 0.8:
        new_threshold = min(MAX_ALERT_THRESHOLD, new_threshold + THRESHOLD_STEP)

    if new_threshold != controls.alert_threshold:
        create_adaptive_action(
            session_id,
            "threshold_adjusted",
            {
                "source_ip": source_ip,
                "old_threshold": controls.alert_threshold,
                "new_threshold": new_threshold,
                "recent_malicious_ratio": malicious_ratio,
                "window_size": len(recent_labels),
            },
            outcome="alert threshold adjusted from recent classifications",
            db_path=db_path,
        )

    is_malicious = (
        classification in MALICIOUS_LABELS and confidence >= new_threshold
    )
    severity = "high" if classification in {"port_scan", "sql_injection"} else "medium"
    alert_id = None
    if is_malicious:
        alert_id = create_alert(
            session_id,
            severity,
            f"Session classified as {classification} with confidence {confidence:.3f}.",
            db_path=db_path,
        )

    create_adaptive_action(
        session_id,
        "classification_observed",
        {
            "source_ip": source_ip,
            "classification": classification,
            "confidence": confidence,
            "threshold": new_threshold,
            "malicious": is_malicious,
        },
        alert_id=alert_id,
        outcome="alerted" if is_malicious else "observed",
        db_path=db_path,
    )

    classification_history = [
        action
        for action in source_actions
        if action["action_type"] == "classification_observed"
    ]
    if is_malicious:
        malicious_streak = 1
        for action in reversed(classification_history):
            details = action["details"]
            if details.get("malicious") is True:
                malicious_streak += 1
            else:
                break
        current_controls = get_source_controls(source_ip, db_path=db_path)
        if (
            malicious_streak >= MALICIOUS_STREAK_FOR_RATE_LIMIT
            and not current_controls.rate_limited
        ):
            create_adaptive_action(
                session_id,
                "rate_limit_enabled",
                {
                    "source_ip": source_ip,
                    "duration_seconds": RATE_LIMIT_DURATION_SECONDS,
                    "retry_after_seconds": RATE_LIMIT_RETRY_AFTER_SECONDS,
                    "malicious_streak": malicious_streak,
                },
                alert_id=alert_id,
                outcome="source rate limited",
                db_path=db_path,
            )
    elif classification == "benign":
        benign_streak = 1
        for action in reversed(classification_history):
            details = action["details"]
            if details.get("classification") == "benign":
                benign_streak += 1
            else:
                break
        current_controls = get_source_controls(source_ip, db_path=db_path)
        if benign_streak >= 3 and current_controls.rate_limited:
            create_adaptive_action(
                session_id,
                "rate_limit_cleared",
                {
                    "source_ip": source_ip,
                    "benign_streak": benign_streak,
                },
                outcome="source rate limit cleared",
                db_path=db_path,
            )

    current_controls = get_source_controls(source_ip, db_path=db_path)
    if (
        classification == "port_scan"
        and confidence >= new_threshold
        and not current_controls.scan_banner
    ):
        create_adaptive_action(
            session_id,
            "scan_banner_changed",
            {
                "source_ip": source_ip,
                "banner": SCAN_BANNER,
                "trigger": classification,
            },
            alert_id=alert_id,
            outcome="scan banner changed",
            db_path=db_path,
        )
        current_controls = get_source_controls(source_ip, db_path=db_path)

    return AdaptiveDecision(
        session_id=session_id,
        source_ip=source_ip,
        classification=classification,
        confidence=confidence,
        alert_threshold=current_controls.alert_threshold,
        alert_created=alert_id is not None,
        rate_limited=current_controls.rate_limited,
        scan_banner=current_controls.scan_banner,
    )
