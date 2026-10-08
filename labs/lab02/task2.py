"""Утиліта аналізу журналів активності користувачів (Варіант 7)."""

import argparse
import csv
import json
import logging
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Сигнатури чутливих директорій і файлів
CRITICAL_RESOURCE_REGEX: re.Pattern[str] = re.compile(
    r"(/prod/|/admin/|/finance/|payroll|secrets|confidential|budget)",
    re.IGNORECASE,
)


@dataclass
class ActivityEntry:
    """Модель одного запису журналу дій."""

    timestamp: datetime
    user_id: str
    action: str
    resource: str
    ip: str


def setup_logger(log_file: Path | None = None) -> logging.Logger:
    """Компактне налаштування консольного та файлового логера."""
    logger = logging.getLogger("UserActivityAudit")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    fmt = logging.Formatter("[%(levelname)s] %(message)s")
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    for h in handlers:
        h.setFormatter(fmt)
        logger.addHandler(h)
    return logger


def parse_activity_log(file_path: Path, logger: logging.Logger) -> list[ActivityEntry]:
    """Зчитування CSV-файлу та перетворення даних на об'єкти."""
    if not file_path.is_file():
        logger.error("Вхідний файл логу не знайдено: %s", file_path)
        raise FileNotFoundError(f"Файл {file_path} не існує")
    logger.info("Reading user activity log %s...", file_path.as_posix())
    entries: list[ActivityEntry] = []
    with file_path.open(encoding="utf-8") as f:
        for row_num, row in enumerate(csv.DictReader(f), start=2):
            try:
                entries.append(
                    ActivityEntry(
                        timestamp=datetime.fromisoformat(row["Timestamp"].strip()),
                        user_id=row["UserID"].strip(),
                        action=row["Action"].strip(),
                        resource=row["Resource"].strip(),
                        ip=row["IP"].strip(),
                    )
                )
            except (KeyError, ValueError) as err:
                logger.warning("Пропущено некоректний рядок #%d: %s", row_num, err)
    logger.info("Total records processed: %d.", len(entries))
    return entries


def is_off_hours(dt: datetime) -> tuple[bool, str]:
    """Виявлення активності у вихідні або вночі (22:00-06:00)."""
    # 5 — субота, 6 — неділя
    if dt.weekday() in (5, 6):
        return True, "Saturday" if dt.weekday() == 5 else "Sunday"
    if dt.hour >= 22 or dt.hour < 6:
        return True, "Night (22:00 - 06:00)"
    return False, ""


def analyze_activity(
    activity_log_path: Path,
    output_report_path: Path,
    after_hours_only: bool = False,
    log_file_path: Path | None = None,
) -> dict[str, Any]:
    """Аналіз аномалій, пошук масових запитів та експорт звіту."""
    logger = setup_logger(log_file_path)
    entries = parse_activity_log(activity_log_path, logger)
    off_hours_alerts: list[dict[str, Any]] = []
    # Групування звернень за користувачами через defaultdict
    user_actions: defaultdict[str, list[ActivityEntry]] = defaultdict(list)
    critical_access: defaultdict[str, list[ActivityEntry]] = defaultdict(list)
    for entry in entries:
        user_actions[entry.user_id].append(entry)
        # Перевірка на позаробочий час
        is_off, period = is_off_hours(entry.timestamp)
        if is_off:
            off_hours_alerts.append(
                {
                    "user_id": entry.user_id,
                    "timestamp": entry.timestamp.isoformat(),
                    "period": period,
                    "action": entry.action,
                    "resource": entry.resource,
                    "ip": entry.ip,
                }
            )
        # Перевірка доступу до критичних ресурсів
        if CRITICAL_RESOURCE_REGEX.search(entry.resource):
            critical_access[entry.user_id].append(entry)

    # Виведення тривог про позаробочий час
    print("\n=== Off-Hours Activity Alerts (22:00 - 06:00 / Weekends) ===")
    for alert in off_hours_alerts:
        t_str = datetime.fromisoformat(alert["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        print(
            f"[ALERT] User '{alert['user_id']}' performed {alert['action']} at {t_str} "
            f"({alert['period']}) on '{alert['resource']}' from IP {alert['ip']}"
        )

    # Виявлення масових звернень (від 5 запитів до важливих даних)
    mass_critical_alerts: list[dict[str, Any]] = []
    print(
        "\n=== Mass Critical Resource Anomalies (>5 requests to critical resources) ==="
    )
    for uid, crit_list in critical_access.items():
        if len(crit_list) >= 5:
            crit_list.sort(key=lambda x: x.timestamp)
            sec = int(
                (crit_list[-1].timestamp - crit_list[0].timestamp).total_seconds()
            )
            t_start = crit_list[0].timestamp.strftime("%H:%M:%S")
            t_end = crit_list[-1].timestamp.strftime("%H:%M:%S")
            print(
                f"[ALERT] User '{uid}' executed {len(crit_list)} requests to sensitive "
                f"resources within {sec} seconds (from {t_start} to {t_end})."
            )
            mass_critical_alerts.append(
                {
                    "user_id": uid,
                    "total_requests": len(crit_list),
                    "duration_seconds": sec,
                    "details": [asdict(e) for e in crit_list],
                }
            )

    # Формування та збереження JSON-звіту
    report: dict[str, Any] = {
        "metadata": {
            "source_file": activity_log_path.as_posix(),
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "total_records": len(entries),
            "after_hours_flag": after_hours_only,
        },
        "off_hours_activity_alerts": off_hours_alerts,
        "mass_critical_anomalies": mass_critical_alerts,
    }
    output_report_path.parent.mkdir(parents=True, exist_ok=True)
    with output_report_path.open("w", encoding="utf-8") as out_f:
        json.dump(report, out_f, indent=4, default=str)
    logger.info(
        "Anomalous activity report written to %s", output_report_path.as_posix()
    )
    return report


def build_parser() -> argparse.ArgumentParser:
    """Конфігурація CLI-аргументів."""
    parser = argparse.ArgumentParser(
        description="Аналізатор журналів активності користувачів (Варіант 7)"
    )
    parser.add_argument(
        "--activity-log",
        type=Path,
        default=Path("labs/lab02/data/activity.csv"),
        help="Шлях до вхідного файлу журналу дій (CSV)",
    )
    parser.add_argument(
        "--after-hours",
        action="store_true",
        help="Прапорець для фільтрації подій у позаробочий час",
    )
    parser.add_argument(
        "--out-report",
        type=Path,
        default=Path("labs/lab02/data/off_hours_audit.json"),
        help="Шлях для збереження вихідного JSON-звіту",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=Path("labs/lab02/data/activity_audit.log"),
        help="Шлях до файлу системного логування",
    )
    return parser


def main() -> None:
    """Автономний запуск task2.py."""
    args = build_parser().parse_args()
    try:
        analyze_activity(
            activity_log_path=args.activity_log,
            output_report_path=args.out_report,
            after_hours_only=args.after_hours,
            log_file_path=args.log_file,
        )
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"[ERROR] Помилка виконання: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
