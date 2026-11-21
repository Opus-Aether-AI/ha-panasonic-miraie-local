"""Whether an AC is answering, and whether its status still follows the unit.

No Home Assistant here, so it can be tested on its own. The coordinator feeds it each poll's answer
(or the miss) and each command's readback.

Two things can make the state shown wrong rather than merely old:

- The AC stops answering. A missed reply or two is normal on Wi-Fi, so the last state stays for
  STALE_AFTER seconds, with the time of the last answer beside it; after that the entities show
  as unavailable.
- The AC answers, but its status stops following the unit: every field stays exactly as it was,
  apart from what Home Assistant itself sends. Some MirAIe Wi-Fi modules do this once they can't
  reach Panasonic's cloud (seen on CS-CU-EU18CKY5XFM, firmware 3.02): the reply keeps a fresh
  timestamp and signal, while the room reading, and anything changed on the remote, stay where
  they were. On a unit that follows, the room reading alone moves within minutes of running, so a
  status that hasn't changed by itself through STILL_AFTER seconds of running is not following.
"""

from __future__ import annotations

from datetime import datetime, timezone

STALE_AFTER = 60
STILL_AFTER = 30 * 60
# Fields that change with every answer without saying anything about the AC itself.
VOLATILE = frozenset({"ts", "rssi", "sid", "_transport", "onlineStatus", "_topic"})


def settled(status: dict) -> dict:
    """The status without the fields that move on every answer."""
    return {key: value for key, value in status.items() if key not in VOLATILE}


def iso(when: float) -> str:
    return datetime.fromtimestamp(when, timezone.utc).isoformat(timespec="seconds")


class Health:
    def __init__(self, now: float):
        self.answered_at: float | None = None
        self.missed = 0
        # When the status last changed by itself: not counting what was sent to it. Before the
        # first change is seen, the time this started, so "since" is "at least since".
        self.moved_at = now
        self.on_since: float | None = None
        # Set once the AC has run STILL_AFTER with no change of its own: when it last moved.
        # It stays set, even while the AC is off, until the status changes by itself again.
        self.still_since: float | None = None
        self._known: dict | None = None

    def answered(self, status: dict, now: float) -> None:
        """A poll's answer."""
        known = settled(status)
        if self._known is not None and known != self._known:
            self.moved_at, self.still_since = now, None
        self._known = known
        self._heard(status, now)

    def commanded(self, status: dict, now: float) -> None:
        """A command's readback: what was just set, so not a change the AC made by itself."""
        self._known = settled(status)
        self._heard(status, now)

    def missed_poll(self, now: float) -> float:
        """Count a poll with no answer; returns how long since the last answer (0 if never)."""
        self.missed += 1
        return now - self.answered_at if self.answered_at is not None else 0.0

    def stale(self, now: float) -> bool:
        """True once the AC has gone STALE_AFTER without answering, or never answered."""
        return self.answered_at is None or now - self.answered_at > STALE_AFTER

    @property
    def following(self) -> bool:
        return self.still_since is None

    def attributes(self) -> dict:
        """For the climate entity. Each changes only when the situation does, never every poll."""
        out = {}
        if self.missed and self.answered_at is not None:
            out["last_answer"] = iso(self.answered_at)
        if self.still_since is not None:
            out["status_unchanged_since"] = iso(self.still_since)
        return out

    def _heard(self, status: dict, now: float) -> None:
        self.answered_at, self.missed = now, 0
        if str(status.get("ps", "")).lower() != "on":
            self.on_since = None
            return
        if self.on_since is None:
            self.on_since = now
        if self.still_since is None and now - max(self.moved_at, self.on_since) >= STILL_AFTER:
            self.still_since = self.moved_at
