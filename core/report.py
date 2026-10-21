"""
core/report.py

Geração e histórico de relatórios dos módulos. Cada módulo chama
ReportManager.save() ao final de uma execução relevante, produzindo
um JSON reproduzível em reports/ e uma entrada no índice de histórico.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.config import REPORT_DIR

INDEX_PATH = REPORT_DIR / "index.json"


class ReportManager:
    def __init__(self, report_dir: Path = REPORT_DIR) -> None:
        self.report_dir = report_dir
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.report_dir / "index.json"
        if not self.index_path.exists():
            self._write_index([])

    def _read_index(self) -> list[dict[str, Any]]:
        try:
            with open(self.index_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return []

    def _write_index(self, entries: list[dict[str, Any]]) -> None:
        with open(self.index_path, "w", encoding="utf-8") as fh:
            json.dump(entries, fh, indent=2, ensure_ascii=False)

    def save(self, module: str, title: str, data: dict[str, Any]) -> Path:
        """Salva um relatório individual e atualiza o índice de histórico."""
        report_id = uuid.uuid4().hex[:12]
        timestamp = datetime.now(timezone.utc).isoformat()
        filename = f"{module}_{report_id}.json"
        path = self.report_dir / filename

        payload = {
            "id": report_id,
            "module": module,
            "title": title,
            "generated_at": timestamp,
            "data": data,
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)

        index = self._read_index()
        index.append(
            {
                "id": report_id,
                "module": module,
                "title": title,
                "generated_at": timestamp,
                "file": filename,
            }
        )
        self._write_index(index)
        return path

    def list_history(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._read_index()[-limit:][::-1]

    def load(self, report_id: str) -> dict[str, Any] | None:
        for entry in self._read_index():
            if entry["id"] == report_id:
                path = self.report_dir / entry["file"]
                if path.exists():
                    with open(path, "r", encoding="utf-8") as fh:
                        return json.load(fh)
        return None
