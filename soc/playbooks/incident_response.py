"""
Sorabbyngo Sentinel — Incident Response Playbooks
Automated response procedures for common threat scenarios.
Each playbook is triggered by a threat level/type combination
and executes a series of containment and investigation steps.
"""
import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Callable

log = logging.getLogger("sentinel.soc.playbooks")

NATS_URL = os.environ.get("NATS_URL", "nats://localhost:4222")


class PlaybookStep:
    def __init__(self, name: str, action: Callable, critical: bool = False):
        self.name     = name
        self.action   = action
        self.critical = critical   # If True, abort playbook on failure


class IncidentPlaybook:
    """Base class for incident response playbooks."""

    name        = "base_playbook"
    description = "Base incident response playbook"
    triggers    = []   # (threat_type, min_level) pairs

    def __init__(self, nc=None):
        self._nc      = nc
        self._steps   = []
        self._results = []
        self._define_steps()

    def _define_steps(self):
        """Override in subclasses to define playbook steps."""
        pass

    async def execute(self, event: dict) -> dict:
        """Execute all playbook steps. Returns execution report."""
        log.info("[Playbook] %s triggered by %s", self.name, event.get("threat_type"))
        start   = datetime.now(timezone.utc)
        results = []

        for step in self._steps:
            log.info("[Playbook] Step: %s", step.name)
            try:
                result = await step.action(event)
                results.append({"step": step.name, "status": "ok", "result": result})
            except Exception as e:
                log.error("[Playbook] Step %s failed: %s", step.name, e)
                results.append({"step": step.name, "status": "error", "error": str(e)})
                if step.critical:
                    log.error("[Playbook] Critical step failed — aborting")
                    break

        report = {
            "playbook":    self.name,
            "trigger":     event.get("threat_type"),
            "started_at":  start.isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "steps":       results,
            "success":     all(r["status"] == "ok" for r in results),
        }
        await self._publish_report(report)
        return report

    async def _publish_report(self, report: dict):
        if not self._nc:
            return
        try:
            await self._nc.publish(
                "sorabbyngo.sentinel.playbook_report",
                json.dumps(report).encode(),
            )
        except Exception as e:
            log.debug("[Playbook] Report publish error: %s", e)


class MalwarePlaybook(IncidentPlaybook):
    """Response playbook for malware detection events."""

    name        = "malware_response"
    description = "Contain and investigate malware detection"
    triggers    = [
        ("malware_detected", "HIGH"),
        ("rootkit",          "CRITICAL"),
        ("process_injection","HIGH"),
        ("webshell",         "CRITICAL"),
    ]

    def _define_steps(self):
        self._steps = [
            PlaybookStep("isolate_process",   self._isolate_process,   critical=False),
            PlaybookStep("quarantine_file",   self._quarantine_file,   critical=False),
            PlaybookStep("capture_memory",    self._capture_memory,    critical=False),
            PlaybookStep("notify_sentinel",   self._notify_sentinel,   critical=True),
            PlaybookStep("alert_soc",         self._alert_soc,         critical=False),
            PlaybookStep("collect_ioc",       self._collect_ioc,       critical=False),
        ]

    async def _isolate_process(self, event: dict) -> str:
        pid = event.get("data", {}).get("pid")
        if pid:
            import subprocess
            result = subprocess.run(["kill", "-STOP", str(pid)], capture_output=True)
            return f"PID {pid} suspended (SIGSTOP)" if result.returncode == 0 else f"Could not stop PID {pid}"
        return "No PID in event"

    async def _quarantine_file(self, event: dict) -> str:
        path = event.get("data", {}).get("path", "")
        if path and self._nc:
            await self._nc.publish(
                "sorabbyngo.cyberwall.quarantine",
                json.dumps({"path": path}).encode(),
            )
            return f"Quarantine requested: {path}"
        return "No path in event"

    async def _capture_memory(self, event: dict) -> str:
        if self._nc:
            await self._nc.publish(
                "sorabbyngo.sentinel.command",
                json.dumps({"command": "memory_dump", "label": "malware_incident"}).encode(),
            )
            return "Memory dump requested"
        return "NATS unavailable"

    async def _notify_sentinel(self, event: dict) -> str:
        if self._nc:
            await self._nc.publish(
                "sorabbyngo.sentinel.threat",
                json.dumps({
                    **event,
                    "playbook": self.name,
                    "message":  f"Malware incident — {event.get('threat_type')} — automated response active",
                    "action_taken": "process_suspended + quarantine_requested + memory_dump",
                }).encode(),
            )
            return "Sentinel notified"
        return "NATS unavailable"

    async def _alert_soc(self, event: dict) -> str:
        log.critical(
            "[SOC ALERT] MALWARE INCIDENT\n"
            "  Type: %s\n  Score: %s\n  Node: %s\n  Path: %s",
            event.get("threat_type"),
            event.get("score"),
            event.get("node_id", "?")[:16],
            event.get("data", {}).get("path", "unknown"),
        )
        return "SOC alerted via log"

    async def _collect_ioc(self, event: dict) -> dict:
        """Collect Indicators of Compromise."""
        ioc = {
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "threat_type": event.get("threat_type"),
            "score":       event.get("score"),
            "path":        event.get("data", {}).get("path"),
            "pid":         event.get("data", {}).get("pid"),
            "hash":        event.get("data", {}).get("sha256"),
            "node_id":     event.get("node_id"),
        }
        log.info("[Playbook] IOC collected: %s", json.dumps(ioc))
        return ioc


class NetworkAttackPlaybook(IncidentPlaybook):
    """Response playbook for network attack events."""

    name        = "network_attack_response"
    description = "Block and investigate network attacks"
    triggers    = [
        ("port_scan",  "HIGH"),
        ("syn_flood",  "HIGH"),
        ("ddos",       "CRITICAL"),
        ("null_scan",  "HIGH"),
        ("xmas_scan",  "HIGH"),
    ]

    def _define_steps(self):
        self._steps = [
            PlaybookStep("block_source_ip",   self._block_ip,        critical=True),
            PlaybookStep("capture_traffic",   self._capture_traffic, critical=False),
            PlaybookStep("notify_sentinel",   self._notify,          critical=True),
            PlaybookStep("update_byngonet",   self._update_byngonet, critical=False),
        ]

    async def _block_ip(self, event: dict) -> str:
        src_ip = event.get("data", {}).get("src_ip", "")
        if src_ip and self._nc:
            await self._nc.publish(
                "sorabbyngo.cyberwall.block_request",
                json.dumps({"ip": src_ip, "reason": event.get("threat_type")}).encode(),
            )
            return f"Block requested: {src_ip}"
        return "No source IP"

    async def _capture_traffic(self, event: dict) -> str:
        if self._nc:
            await self._nc.publish(
                "sorabbyngo.sentinel.command",
                json.dumps({"command": "packet_capture", "duration": 60}).encode(),
            )
            return "Packet capture requested (60s)"
        return "NATS unavailable"

    async def _notify(self, event: dict) -> str:
        if self._nc:
            await self._nc.publish(
                "sorabbyngo.sentinel.threat",
                json.dumps({
                    **event,
                    "playbook":     self.name,
                    "message":      f"Network attack — {event.get('threat_type')} from {event.get('data',{}).get('src_ip','?')}",
                    "action_taken": "ip_blocked + traffic_captured",
                }).encode()
            )
            return "Sentinel notified"
        return "NATS unavailable"

    async def _update_byngonet(self, event: dict) -> str:
        """Broadcast blocked IP to all mesh nodes."""
        src_ip = event.get("data", {}).get("src_ip", "")
        if src_ip and self._nc:
            await self._nc.publish(
                "sorabbyngo.security.blocked_ip_broadcast",
                json.dumps({
                    "ip":        src_ip,
                    "reason":    event.get("threat_type"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }).encode()
            )
            return f"Block broadcast to mesh: {src_ip}"
        return "No IP to broadcast"


# Playbook registry
PLAYBOOKS = [
    MalwarePlaybook,
    NetworkAttackPlaybook,
]


def get_playbook(threat_type: str, level: str, nc=None) -> IncidentPlaybook:
    """Find the appropriate playbook for a threat."""
    for PlaybookClass in PLAYBOOKS:
        for trigger_type, trigger_level in PlaybookClass.triggers:
            if trigger_type == threat_type:
                return PlaybookClass(nc=nc)
    return None
