import asyncio

import pytest

from adaptive.rules import (
    SCAN_BANNER,
    get_source_controls,
    observe_classification,
)
from database.db import (
    create_session,
    initialize_database,
    list_adaptive_actions,
    list_alerts,
)


def _session(db_path):
    return create_session("127.0.0.1", db_path=db_path)


def test_repeated_malicious_classifications_adjust_threshold_and_rate_limit(tmp_path):
    db_path = tmp_path / "adaptive.db"
    initialize_database(db_path)
    decisions = []

    for _ in range(3):
        decisions.append(
            observe_classification(
                _session(db_path),
                "brute_force",
                0.9,
                db_path=db_path,
            )
        )

    controls = get_source_controls("127.0.0.1", db_path=db_path)
    assert controls.alert_threshold == pytest.approx(0.8)
    assert controls.rate_limited is True
    assert decisions[-1].rate_limited is True
    assert len(list_alerts(db_path=db_path)) == 3
    actions = list_adaptive_actions(db_path=db_path)
    assert any(action["action_type"] == "rate_limit_enabled" for action in actions)
    assert all(
        action["details"]["source_ip"] == "127.0.0.1"
        for action in actions
    )


def test_five_malicious_observations_lower_threshold_and_port_scan_changes_banner(
    tmp_path,
):
    db_path = tmp_path / "banner.db"
    initialize_database(db_path)

    for _ in range(4):
        observe_classification(
            _session(db_path),
            "brute_force",
            0.9,
            db_path=db_path,
        )
    decision = observe_classification(
        _session(db_path),
        "port_scan",
        0.9,
        db_path=db_path,
    )

    controls = get_source_controls("127.0.0.1", db_path=db_path)
    assert decision.alert_threshold == pytest.approx(0.75)
    assert controls.alert_threshold == pytest.approx(0.75)
    assert controls.scan_banner is True
    actions = list_adaptive_actions(db_path=db_path)
    banner_action = next(
        action for action in actions if action["action_type"] == "scan_banner_changed"
    )
    assert banner_action["details"]["banner"] == SCAN_BANNER


def test_three_benign_classifications_clear_rate_limit(tmp_path):
    db_path = tmp_path / "clear.db"
    initialize_database(db_path)
    for _ in range(3):
        observe_classification(
            _session(db_path),
            "sql_injection",
            0.95,
            db_path=db_path,
        )
    assert get_source_controls("127.0.0.1", db_path=db_path).rate_limited is True

    for _ in range(5):
        observe_classification(
            _session(db_path),
            "benign",
            0.95,
            db_path=db_path,
        )

    controls = get_source_controls("127.0.0.1", db_path=db_path)
    assert controls.rate_limited is False
    assert controls.alert_threshold == pytest.approx(0.85)
    actions = list_adaptive_actions(db_path=db_path)
    assert any(action["action_type"] == "rate_limit_cleared" for action in actions)


def test_low_confidence_classification_does_not_trigger_malicious_action(tmp_path):
    db_path = tmp_path / "low-confidence.db"
    initialize_database(db_path)
    decision = observe_classification(
        _session(db_path),
        "port_scan",
        0.2,
        db_path=db_path,
    )

    assert decision.alert_created is False
    assert decision.scan_banner is False
    assert decision.rate_limited is False
    assert list_alerts(db_path=db_path) == []


@pytest.mark.parametrize(
    ("classification", "confidence", "message"),
    [
        ("unknown", 0.9, "classification"),
        ("benign", 1.1, "confidence"),
        ("benign", True, "confidence"),
        ("benign", 0.5, "session_id"),
    ],
)
def test_rejects_invalid_classification_input(
    tmp_path,
    classification,
    confidence,
    message,
):
    db_path = tmp_path / "invalid.db"
    initialize_database(db_path)
    session_id = _session(db_path)

    with pytest.raises(ValueError, match=message):
        observe_classification(
            session_id if message != "session_id" else True,
            classification,
            confidence,
            db_path=db_path,
        )


def test_rejects_missing_session(tmp_path):
    db_path = tmp_path / "missing.db"
    initialize_database(db_path)

    with pytest.raises(ValueError, match="does not exist"):
        observe_classification(999, "benign", 0.9, db_path=db_path)


def test_web_service_enforces_rate_limit_and_scan_banner(tmp_path):
    from database.db import list_sessions
    from honeypot.web_service import create_app

    db_path = tmp_path / "web.db"
    initialize_database(db_path)
    app = create_app(db_path)
    app.config.update(TESTING=True)
    client = app.test_client()

    first_response = client.get("/login")
    assert first_response.status_code == 200
    session_id = list_sessions(db_path=db_path)[0]["id"]
    observe_classification(session_id, "port_scan", 0.99, db_path=db_path)

    banner_response = client.get("/login")
    assert SCAN_BANNER.encode() in banner_response.data

    for _ in range(2):
        observe_classification(
            list_sessions(db_path=db_path)[0]["id"],
            "brute_force",
            0.99,
            db_path=db_path,
        )
    limited_response = client.get("/login")
    assert limited_response.status_code == 429
    assert limited_response.headers["Retry-After"] == "1"


def test_tcp_service_enforces_persisted_rate_limit(tmp_path):
    from database.db import list_sessions
    from honeypot.tcp_service import LOCALHOST, start_tcp_service

    async def exercise():
        db_path = tmp_path / "tcp.db"
        initialize_database(db_path)
        first = _session(db_path)
        for _ in range(3):
            observe_classification(first, "brute_force", 0.99, db_path=db_path)
        server = await start_tcp_service(port=0, db_path=db_path)
        try:
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection(LOCALHOST, port)
            response = await reader.readline()
            writer.close()
            await writer.wait_closed()
            return response
        finally:
            server.close()
            await server.wait_closed()

    assert asyncio.run(exercise()) == b"Rate limited. Try again later.\n"
