"""
Sorabbyngo Sentinel — Packet Capture Tool
Real-time packet capture with AI-assisted threat analysis.
Uses tcpdump for capture, feeds suspicious traffic to Byngox security_agent.
"""
import asyncio
import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("sentinel.network.capture")

CAPTURE_DIR = Path(os.environ.get("SENTINEL_CAPTURE_DIR", "/var/lib/sentinel/captures"))
NATS_URL    = os.environ.get("NATS_URL", "nats://localhost:4222")

# Suspicious traffic patterns to alert on
ALERT_FILTERS = [
    "tcp[tcpflags] == tcp-syn",                    # SYN scan
    "tcp[tcpflags] == 0",                          # NULL scan
    "tcp[tcpflags] & (tcp-fin|tcp-urg|tcp-psh) == (tcp-fin|tcp-urg|tcp-psh)",  # XMAS
    "icmp[icmptype] == icmp-echo and ip[8] == 1",  # TTL=1 traceroute
]


class PacketCapture:
    def __init__(self, interface: str = "eth0"):
        self.interface  = interface
        self._running   = False
        self._proc      = None
        CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

    async def capture(self, duration_sec: int = 60, output_file: str = None) -> str:
        """Capture packets for N seconds. Returns path to pcap file."""
        if not output_file:
            ts          = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_file = str(CAPTURE_DIR / f"capture_{ts}.pcap")

        log.info("[Capture] Starting on %s for %ds → %s",
                 self.interface, duration_sec, output_file)

        proc = await asyncio.create_subprocess_exec(
            "tcpdump",
            "-i", self.interface,
            "-w", output_file,
            "-G", str(duration_sec),
            "-W", "1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=duration_sec + 5)
        log.info("[Capture] Complete: %s", output_file)
        return output_file

    async def monitor_threats(self, interface: str = None):
        """
        Live monitoring — alerts on suspicious packet patterns via NATS.
        """
        iface   = interface or self.interface
        self._running = True
        log.info("[Capture] Live threat monitoring on %s", iface)

        for alert_filter in ALERT_FILTERS:
            asyncio.create_task(
                self._monitor_filter(iface, alert_filter)
            )

        while self._running:
            await asyncio.sleep(1)

    async def _monitor_filter(self, iface: str, bpf_filter: str):
        """Monitor for a specific BPF filter pattern."""
        while self._running:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "tcpdump", "-i", iface, "-l", "-n",
                    bpf_filter,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                while self._running and proc.stdout:
                    line = await asyncio.wait_for(
                        proc.stdout.readline(), timeout=5.0
                    )
                    if line:
                        await self._alert(bpf_filter, line.decode().strip())
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                log.debug("[Capture] Monitor error: %s", e)
                await asyncio.sleep(5)

    async def _alert(self, filter_type: str, raw: str):
        """Publish packet threat alert to NATS."""
        try:
            import nats as nats_lib
            nc = await nats_lib.connect(NATS_URL)
            await nc.publish(
                "sorabbyngo.cyberwall.alert",
                json.dumps({
                    "source":      "sentinel.packet_capture",
                    "threat_type": self._classify_filter(filter_type),
                    "level":       "HIGH",
                    "score":       7.5,
                    "description": f"Suspicious packet: {raw[:100]}",
                    "data":        {"filter": filter_type, "raw": raw[:200]},
                    "timestamp":   datetime.now(timezone.utc).isoformat(),
                }).encode()
            )
            await nc.close()
        except Exception as e:
            log.debug("[Capture] NATS alert error: %s", e)
        log.warning("[Capture] THREAT [%s]: %s", filter_type[:30], raw[:80])

    def _classify_filter(self, f: str) -> str:
        if "syn" in f.lower():     return "syn_scan"
        if "flags] == 0" in f:    return "null_scan"
        if "fin|tcp-urg" in f:    return "xmas_scan"
        if "icmp" in f.lower():   return "icmp_probe"
        return "suspicious_packet"

    def stop(self):
        self._running = False
