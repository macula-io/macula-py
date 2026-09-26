"""macula-go's teststation for a test module: two in-process macula 12
stations sharing a DHT and a test realm with one org, driven over stdin.

The binary is MACULA_TESTSTATION (CI builds it from the macula-go ref in
abi/MACULA_GO_REF). A test that needs it and finds it unset fails naming the
variable; it never skips.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from dataclasses import dataclass


@dataclass(frozen=True)
class StationInfo:
    host: str
    port: int
    node_id: str


class TestStations:
    __test__ = False

    def __init__(self, profile: str = "pq_pure") -> None:
        binary = os.environ.get("MACULA_TESTSTATION")
        if not binary:
            raise RuntimeError(
                "MACULA_TESTSTATION is not set: build macula-go's teststation/cmd/teststation "
                "at abi/MACULA_GO_REF and point it at the binary (scripts/build_native.sh does both)"
            )
        self._child = subprocess.Popen(
            [binary, profile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1
        )
        first = self._child.stdout.readline()
        if not first:
            raise RuntimeError("teststation printed nothing")
        info = json.loads(first)
        self.stations = [StationInfo(s["host"], s["port"], s["node_id"]) for s in info["stations"]]
        self.profile = profile
        self.realm_name: str = info["realm_name"]
        self.realm_id: str = info["realm_id"]
        self.realm_key: str = info["realm_key"]
        self.org: str = info["org"]
        self._lock = threading.Lock()

    def _ask(self, command: str) -> str:
        with self._lock:
            self._child.stdin.write(command + "\n")
            self._child.stdin.flush()
            reply = self._child.stdout.readline()
        if not reply:
            raise RuntimeError("teststation ended")
        return reply.strip()

    def admit(self, node_id: str) -> None:
        """The org delegates its procedures to the node."""
        reply = self._ask(f"admit {node_id}")
        if not reply.startswith("admitted"):
            raise RuntimeError(reply)

    def relayed(self) -> int:
        """How many streams the stations relay now."""
        return int(self._ask("relayed").split(" ")[1])

    def stop(self) -> None:
        self._child.stdin.close()
        try:
            self._child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._child.kill()
            self._child.wait()
