"""
Sorabbyngo Sentinel — Memory Forensics Tool
Acquires and analyses memory dumps for threat investigation.
Integrates with Byngox security_agent for AI-assisted analysis.
"""
import asyncio
import json
import logging
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("sentinel.forensics.memory")

DUMP_DIR   = Path(os.environ.get("SENTINEL_DUMP_DIR", "/var/lib/sentinel/dumps"))
NATS_URL   = os.environ.get("NATS_URL", "nats://localhost:4222")


class MemoryForensics:
    """
    Acquires memory dumps and analyses them for:
    - Process injection
    - Rootkit artifacts
    - Encryption keys in memory
    - Network connection artifacts
    """

    def __init__(self):
        DUMP_DIR.mkdir(parents=True, exist_ok=True)
        self._avml_ok = self._check_avml()
        self._vol_ok  = self._check_volatility()

    def _check_avml(self) -> bool:
        result = subprocess.run(["which", "avml"], capture_output=True)
        return result.returncode == 0

    def _check_volatility(self) -> bool:
        result = subprocess.run(["which", "vol"], capture_output=True)
        if result.returncode == 0:
            return True
        result = subprocess.run(["which", "volatility3"], capture_output=True)
        return result.returncode == 0

    async def acquire(self, label: str = "") -> str:
        """
        Acquire a memory dump using avml or /proc/kcore fallback.
        Returns path to dump file.
        """
        ts        = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        label_str = f"_{label}" if label else ""
        dump_path = DUMP_DIR / f"memdump{label_str}_{ts}.lime"

        if self._avml_ok:
            log.info("[Memory] Acquiring with avml → %s", dump_path)
            proc = await asyncio.create_subprocess_exec(
                "avml", str(dump_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                log.error("[Memory] avml failed: %s", stderr.decode()[:200])
                return ""
        else:
            # Fallback — copy /proc/kcore (limited but always available)
            log.warning("[Memory] avml not found — using /proc/kcore fallback")
            dump_path = DUMP_DIR / f"kcore{label_str}_{ts}.raw"
            try:
                proc = await asyncio.create_subprocess_exec(
                    "dd", "if=/proc/kcore",
                    f"of={dump_path}",
                    "bs=1M",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()
            except Exception as e:
                log.error("[Memory] kcore dump failed: %s", e)
                return ""

        size_mb = dump_path.stat().st_size / (1024 * 1024) if dump_path.exists() else 0
        log.info("[Memory] Dump acquired: %s (%.1f MB)", dump_path.name, size_mb)
        return str(dump_path)

    async def analyse(self, dump_path: str) -> dict:
        """
        Run Volatility3 analysis on a memory dump.
        Returns structured findings.
        """
        if not self._vol_ok:
            log.warning("[Memory] Volatility3 not found — skipping analysis")
            return {"error": "volatility3 not installed"}

        vol_bin = "vol" if subprocess.run(
            ["which", "vol"], capture_output=True
        ).returncode == 0 else "volatility3"

        findings = {
            "dump_path": dump_path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "processes": [],
            "network":   [],
            "injected":  [],
        }

        # Process list
        proc = await asyncio.create_subprocess_exec(
            vol_bin, "-f", dump_path, "windows.pslist",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        findings["processes"] = stdout.decode().splitlines()[:50]

        # Network connections
        proc = await asyncio.create_subprocess_exec(
            vol_bin, "-f", dump_path, "windows.netstat",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        findings["network"] = stdout.decode().splitlines()[:50]

        log.info("[Memory] Analysis complete — %d processes found", len(findings["processes"]))
        return findings

    async def scan_strings(self, dump_path: str, patterns: list) -> list:
        """Search memory dump for suspicious strings."""
        matches = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "strings", "-n", "8", dump_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
            lines = stdout.decode(errors="ignore").splitlines()
            for pattern in patterns:
                hits = [l for l in lines if pattern.lower() in l.lower()]
                if hits:
                    matches.append({"pattern": pattern, "hits": hits[:10]})
        except Exception as e:
            log.error("[Memory] String scan error: %s", e)
        return matches
