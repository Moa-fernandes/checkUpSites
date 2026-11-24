import os

def _writable_base_dir() -> str:
    env_dir = os.environ.get("CHECKUP_DATA_DIR")
    if env_dir:
        os.makedirs(env_dir, exist_ok=True)
        return env_dir
    try:
        test_file = os.path.join(_writable_base_dir(), ".write_test")
        with open(test_file, "w", encoding="utf-8") as tf:
            tf.write("ok")
        os.remove(test_file)
        return _writable_base_dir()
    except OSError:
        tmp_dir = os.path.join("/tmp", "checkup_data")
        os.makedirs(tmp_dir, exist_ok=True)
        return tmp_dir

"""Persistência local de métricas de acesso, histórico e lista de interessados."""

import csv
import json
import threading
from datetime import datetime
from pathlib import Path

_lock = threading.Lock()


class Storage:
    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self.waitlist_file = self.base_dir / "interessados.csv"
        self.history_file = self.base_dir / "historico.json"
        self.visits_file = self.base_dir / "visitas.txt"
        self.visitors_file = self.base_dir / "visitantes.txt"

    def _read_int(self, path: Path) -> int:
        if not path.exists():
            return 0
        text = path.read_text(encoding="utf-8").strip()
        return int(text) if text.isdigit() else 0

    def _count_lines(self, path: Path) -> int:
        if not path.exists():
            return 0
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())

    def record_page_view(self, new_visitor_id: str | None) -> None:
        with _lock:
            self.visits_file.write_text(str(self._read_int(self.visits_file) + 1), encoding="utf-8")
            if new_visitor_id:
                with self.visitors_file.open("a", encoding="utf-8") as f:
                    f.write(new_visitor_id + "\n")

    def get_stats(self) -> dict:
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