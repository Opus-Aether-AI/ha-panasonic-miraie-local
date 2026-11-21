"""Whether an AC is answering, and whether its status still follows the unit (health.py)."""

from custom_components.ac_mitm.health import STALE_AFTER, STILL_AFTER, Health

ON = {"ps": "on", "acmd": "cool", "actmp": "23.0", "rmtmp": "05.25", "ts": "1", "rssi": -60}
OFF = {**ON, "ps": "off"}


def test_a_short_gap_keeps_the_state_then_it_goes_stale():
    h = Health(0)
    h.answered(ON, 10)
    assert not h.stale(10) and h.attributes() == {}
    assert h.missed_poll(20) == 10
    assert h.attributes() == {"last_answer": "1970-01-01T00:00:10+00:00"}
    assert not h.stale(10 + STALE_AFTER)
    assert h.stale(10 + STALE_AFTER + 1)
    h.answered(ON, 80)
    assert h.missed == 0 and h.attributes() == {}


def test_never_answered_is_stale():
    assert Health(0).stale(0)


def test_timestamp_and_signal_alone_are_not_the_unit_moving():
    h = Health(0)
    t = 0
    while t <= STILL_AFTER + 10:
        h.answered({**ON, "ts": str(t), "rssi": -50 - t % 7}, t)
        t += 10
    assert not h.following
    assert h.attributes() == {"status_unchanged_since": "1970-01-01T00:00:00+00:00"}


def test_a_status_that_moves_by_itself_is_following():
    h = Health(0)
    for i in range(0, STILL_AFTER + 600, 600):
        h.answered({**ON, "rmtmp": f"{i % 7:02d}.25"}, i)
    assert h.following


def test_what_was_sent_is_not_a_change_of_its_own():
    h = Health(0)
    h.answered(ON, 0)
    h.commanded({**ON, "actmp": "24.0"}, 100)
    h.answered({**ON, "actmp": "24.0"}, 110)
    assert h.moved_at == 0
    h.answered({**ON, "actmp": "24.0"}, STILL_AFTER)
    assert not h.following and h.still_since == 0


def test_only_running_counts_and_the_flag_stays_until_it_moves():
    h = Health(0)
    for t in range(0, 3 * STILL_AFTER, 60):          # off for hours, unchanged: no claim
        h.answered(OFF, t)
    assert h.following
    start = 3 * STILL_AFTER
    h.commanded(ON, start)                           # turned on from Home Assistant
    for t in range(start, start + STILL_AFTER, 60):
        h.answered(ON, t)
    assert h.following
    h.answered(ON, start + STILL_AFTER)
    assert not h.following
    h.commanded(OFF, start + STILL_AFTER + 60)       # off again: still not following
    h.answered(OFF, start + STILL_AFTER + 70)
    assert not h.following
    h.answered({**OFF, "rmtmp": "09.26"}, start + STILL_AFTER + 80)
    assert h.following and h.moved_at == start + STILL_AFTER + 80


def test_a_change_from_the_remote_counts():
    h = Health(0)
    h.answered(ON, 0)
    h.answered({**ON, "actmp": "24.0", "cnt": "rem"}, 600)
    assert h.moved_at == 600
