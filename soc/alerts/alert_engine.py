"""
Sorabbyngo Sentinel OS — SOC Alert Engine
Subscribes to all security NATS subjects.
Triggers playbooks. Maintains alert log.
"""
import asyncio
import json
import logging
import os
from datetime import datetime, timezone

import nats

from soc.playbooks.incident_response import get_playbook

log = logging.getLogger("sentinel.soc.alerts")

NATS_URL = os.environ.get("NATS_URL", "nats://localhost:4222")

ALERT_SUBJECTS = [
    "sorabbyngo.cyberwall.alert",
    "sorabbyngo.sentinel.threat",
    "sorabbyngo.sentinel.escalation",
]

BANNER = """
╔══════════════════════════════════════════════════════════╗
║   Sorabbyngo Sentinel OS — SOC Alert Engine              ║
║   Security Operations · AI-assisted · Africa-first       ║
╚══════════════════════════════════════════════════════════╝
"""


class SOCAlertEngine:
    def __init__(self):
        self._nc      = None
        self._running = False
        self._alert_count = 0

    async def start(self):
        self._running = True
        print(BANNER)

        self._nc = await nats.connect(
            NATS_URL,
            name="sorabbyngo-sentinel-soc",
            max_reconnect_attempts=-1,
        )
        log.info("SOC Alert Engine connected to NATS")

        for subject in ALERT_SUBJECTS:
            await self._nc.subscribe(subject, cb=self._on_alert)

        log.info("Monitoring %d subjects", len(ALERT_SUBJECTS))

        while self._running:
            await asyncio.sleep(60)

    async def _on_alert(self, msg):
        try:
            event = json.loads(msg.data.decode())
        except Exception:
            return

        self._alert_count += 1
        level       = event.get("level", "INFO")
        threat_type = event.get("threat_type", "unknown")
        score       = event.get("score", 0)

        log.warning(
            "[SOC] #%d [%s] %s score=%.1f",
            self._alert_count, level, threat_type, score,
        )

        # Trigger playbook for HIGH/CRITICAL
        if level in ("HIGH", "CRITICAL"):
            playbook = get_playbook(threat_type, level, nc=self._nc)
            if playbook:
                log.info("[SOC] Triggering playbook: %s", playbook.name)
                asyncio.create_task(playbook.execute(event))

    def stop(self):
        self._running = False


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )
    asyncio.run(SOCAlertEngine().start())
