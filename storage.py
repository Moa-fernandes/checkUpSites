"""Persistência de métricas de acesso, histórico e lista de interessados."""

import csv
import json
import os
import tempfile
import threading
from datetime import datetime
from pathlib import Path

try:
    import redis as _redis_lib
except ImportError:  # pragma: no cover
    _redis_lib = None

_lock = threading.Lock()


def resolve_storage_dir(preferred_dir: Path | str | None = None) -> Path:
    """Retorna um diretório gravável (prioriza CHECKUP_DATA_DIR, depois preferred_dir, depois /tmp)."""
    env_dir = os.environ.get("CHECKUP_DATA_DIR", "").strip()
    candidates: list[Path] = []
    if env_dir:
        candidates.append(Path(env_dir))
    if preferred_dir is not None:
        candidates.append(Path(preferred_dir))
    candidates.append(Path(tempfile.gettempdir()) / "checkup_data")

    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            probe = candidate / ".checkup_write_probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return candidate
        except OSError:
            continue

    fallback = Path(tempfile.gettempdir()) / "checkup_data"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


class Storage:
    def __init__(self, base_dir: Path):
        self.base_dir = resolve_storage_dir(base_dir)
        self.waitlist_file = self.base_dir / "interessados.csv"
        self.history_file = self.base_dir / "historico.json"
        self.visits_file = self.base_dir / "visitas.txt"
        self.visitors_file = self.base_dir / "visitantes.txt"
        self._redis_client = None
        self._redis_url_used = None

    def _get_redis(self):
        url = (os.environ.get("REDIS_URL") or os.environ.get("REDIS_TLS_URL") or "").strip()
        if not url or _redis_lib is None:
            return None
        if self._redis_client is None or self._redis_url_used != url:
            self._redis_client = _redis_lib.from_url(
                url,
                decode_responses=True,
                socket_connect_timeout=3,
                socket_timeout=3,
            )
            self._redis_url_used = url
        return self._redis_client

    def _read_int(self, path: Path) -> int:
        if not path.exists():
            return 0
        text = path.read_text(encoding="utf-8").strip()
        return int(text) if text.isdigit() else 0

    def _count_lines(self, path: Path) -> int:
        if not path.exists():
            return 0
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())

    def _existing_visitor_ids(self) -> set[str]:
        if not self.visitors_file.exists():
            return set()
        return {line.strip() for line in self.visitors_file.read_text(encoding="utf-8").splitlines() if line.strip()}

    def record_page_view(self, visitor_id: str | None) -> None:
        clean_vid = (visitor_id or "").strip()
        with _lock:
            client = self._get_redis()
            if client is not None:
                try:
                    client.incr("checkup:visits")
                    if clean_vid:
                        client.sadd("checkup:unique_visitors", clean_vid)
                    return
                except Exception:
                    pass

            self.visits_file.write_text(str(self._read_int(self.visits_file) + 1), encoding="utf-8")
            if clean_vid and clean_vid not in self._existing_visitor_ids():
                with self.visitors_file.open("a", encoding="utf-8") as f:
                    f.write(clean_vid + "\n")

    def get_stats(self) -> dict:
        client = self._get_redis()
        if client is not None:
            try:
                v_res = client.get("checkup:visits")
                u_res = client.scard("checkup:unique_visitors")
                if v_res is not None or u_res is not None:
                    return {
                        "visits": int(v_res or 0),
                        "visitors": int(u_res or 0),
                    }
            except Exception:
                pass

        return {
            "visits": self._read_int(self.visits_file),
            "visitors": self._count_lines(self.visitors_file),
        }

    def _load_history(self) -> dict:
        if not self.history_file.exists():
            return {}
        try:
            data = json.loads(self.history_file.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def record_and_compare_history(self, result: dict) -> dict | None:
        url = result["url"]
        metrics = result["metrics"]
        now_iso = datetime.now().isoformat(timespec="seconds")
        now_label = datetime.now().strftime("%d/%m/%Y %H:%M")

        snapshot = {
            "checked_at": now_iso,
            "checked_at_label": now_label,
            "score": result["score"],
            "total_issues": result["total_issues"],
            "ttfb_ms": metrics["ttfb_ms"],
            "ssl_days_left": metrics.get("ssl_days_left"),
        }

        with _lock:
            history = self._load_history()
            entries = history.get(url, [])
            previous = entries[-1] if entries else None

            comparison = None
            if previous:
                comparison = {
                    "previous_label": previous.get("checked_at_label") or previous.get("checked_at", ""),
                    "previous_score": previous["score"],
                    "score_diff": result["score"] - previous["score"],
                    "issues_diff": result["total_issues"] - previous["total_issues"],
                    "ttfb_diff": metrics["ttfb_ms"] - previous["ttfb_ms"],
                    "ssl_days_diff": (
                        metrics["ssl_days_left"] - previous["ssl_days_left"]
                        if metrics.get("ssl_days_left") is not None and previous.get("ssl_days_left") is not None
                        else None
                    ),
                }

            entries.append(snapshot)
            history[url] = entries[-10:]
            self.history_file.write_text(json.dumps(history, ensure_ascii=False, indent=2), encoding="utf-8")

        return comparison

    def add_waitlist_email(self, email: str) -> None:
        with _lock:
            new_file = not self.waitlist_file.exists()
            with self.waitlist_file.open("a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if new_file:
                    writer.writerow(["email", "data"])
                writer.writerow([email, datetime.now().isoformat(timespec="seconds")])