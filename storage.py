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

    def _atomic_write_json(self, path: Path, payload: dict) -> None:
        raw = json.dumps(payload, ensure_ascii=False, indent=2)
        tmp_fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp_hist_", suffix=".json")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                f.write(raw)
            os.replace(tmp_name, path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def record_and_compare_history(self, result: dict, requested_url: str | None = None) -> dict | None:
        url = result["url"]
        metrics = result.get("metrics") or {}
        now = datetime.now()
        now_iso = now.isoformat(timespec="seconds")
        now_label = now.strftime("%d/%m/%Y %H:%M")

        cur_score = int(result.get("score") or 0)
        cur_issues = int(result.get("total_issues") or 0)
        cur_ttfb = int(metrics.get("ttfb_ms") or 0)
        cur_ssl_days = metrics.get("ssl_days_left")

        snapshot = {
            "checked_at": now_iso,
            "checked_at_label": now_label,
            "requested_url": (requested_url or url).strip(),
            "final_url": url,
            "score": cur_score,
            "total_issues": cur_issues,
            "ttfb_ms": cur_ttfb,
            "ssl_days_left": cur_ssl_days,
        }

        with _lock:
            history = self._load_history()
            raw_entries = history.get(url)
            entries = [e for e in raw_entries if isinstance(e, dict)] if isinstance(raw_entries, list) else []
            previous = entries[-1] if entries else None

            comparison = None
            if previous and isinstance(previous.get("score"), (int, float)):
                prev_score = int(previous["score"])
                prev_issues = int(previous.get("total_issues") or 0)
                prev_ttfb = int(previous.get("ttfb_ms") or 0)
                prev_ssl_days = previous.get("ssl_days_left")

                score_diff = cur_score - prev_score
                if score_diff > 0:
                    trend = "melhorou"
                elif score_diff < 0:
                    trend = "piorou"
                else:
                    trend = "estavel"

                comparison = {
                    "previous_label": previous.get("checked_at_label") or previous.get("checked_at", ""),
                    "previous_score": prev_score,
                    "score_diff": score_diff,
                    "trend": trend,
                    "issues_diff": cur_issues - prev_issues,
                    "ttfb_diff": cur_ttfb - prev_ttfb,
                    "ssl_days_diff": (
                        int(cur_ssl_days) - int(prev_ssl_days)
                        if isinstance(cur_ssl_days, (int, float)) and isinstance(prev_ssl_days, (int, float))
                        else None
                    ),
                    "total_checks": len(entries) + 1,
                }

            entries.append(snapshot)
            history[url] = entries[-10:]
            self._atomic_write_json(self.history_file, history)

        return comparison

    def add_waitlist_email(self, email: str) -> bool:
        clean_email = (email or "").strip().lower()
        if not clean_email:
            return False
        today_prefix = datetime.now().strftime("%Y-%m-%d")

        with _lock:
            if self.waitlist_file.exists():
                try:
                    with self.waitlist_file.open("r", newline="", encoding="utf-8") as rf:
                        reader = csv.reader(rf)
                        for row in reader:
                            if len(row) >= 2 and row[0].strip().lower() == clean_email and row[1].startswith(today_prefix):
                                return False
                except Exception:
                    pass

            new_file = not self.waitlist_file.exists()
            with self.waitlist_file.open("a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if new_file:
                    writer.writerow(["email", "data"])
                writer.writerow([clean_email, datetime.now().isoformat(timespec="seconds")])
            return True
