#!/usr/bin/env python3
"""Экспорт места на Дисках Яндекс 360. Python 3.9+, без зависимостей.

Окружение или .env рядом со скриптом: ORGID, ADMIN_TOKEN, CLIENT_ID, CLIENT_SECRET.
Запуск: python3 disk_space.py --output disk_space.csv
Аккаунты не изменяются; ошибки пользователей сохраняются в CSV.
"""

import argparse
import csv
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


FIELDS = (
    "email", "uid", "is_enabled", "used_bytes", "free_bytes", "total_bytes",
    "used_gib", "free_gib", "total_gib", "status", "error",
)
RETRY_STATUSES = {429, 500, 502, 503, 504}
OAUTH_ERROR_CODES = frozenset({
    "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client",
    "unsupported_grant_type", "invalid_scope", "access_denied",
    "invalid_target", "temporarily_unavailable", "server_error",
})


def safe_oauth_error(response):
    """Возвращает только известный код; произвольные строки не выводятся."""
    try:
        raw = response.read(16_385)
        if len(raw) > 16_384:
            return "unavailable_error_code"
        payload = json.loads(raw)
        code = payload.get("error") if isinstance(payload, dict) else None
    except (OSError, ValueError, UnicodeError):
        return "unavailable_error_code"
    if isinstance(code, str) and code in OAUTH_ERROR_CODES:
        return code
    return "unavailable_error_code"


class ApiError(Exception):
    """Только безопасное описание: без токенов и тела ответа."""


def read_config(env_path):
    """Простой .env: KEY=value, кавычки, полные строки комментариев.

    Без подстановок и исполнения shell. Окружение приоритетнее файла.
    """
    names = ("ORGID", "ADMIN_TOKEN", "CLIENT_ID", "CLIENT_SECRET")
    values = {}
    try:
        content = env_path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        content = ""
    for number, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        if not separator:
            raise ValueError(f".env: строка {number}: ожидается KEY=value")
        key, value = key.strip(), value.strip()
        if key not in names:
            continue
        if value.startswith(("'", '"')):
            if len(value) < 2 or value[-1] != value[0]:
                raise ValueError(f".env: строка {number}: незакрытые кавычки")
            value = value[1:-1]
        values[key] = value
    return {name: os.environ.get(name, values.get(name, "")).strip() for name in names}


def validate_credential(name, value):
    """Проверяет символы, не раскрывая значение секрета."""
    if not value or any(not 33 <= ord(char) <= 126 for char in value):
        raise ValueError(
            f"{name}: ожидается непустое значение из печатных ASCII-символов "
            "без пробелов. Проверьте кириллицу, переносы и невидимые символы."
        )


def request_json(url, *, token=None, form=None):
    headers = {"Accept": "application/json"}
    if token is not None:
        try:
            validate_credential("OAuth token", token)
        except ValueError:
            raise ApiError("invalid_token_characters") from None
        headers["Authorization"] = f"OAuth {token}"
    data = None
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urlencode(form).encode()
    request = Request(url, data=data, headers=headers)
    for attempt in range(5):
        delay = 2 ** attempt
        try:
            with urlopen(request, timeout=60) as response:
                result = json.load(response)
            if not isinstance(result, dict):
                raise ApiError("invalid_json_object")
            return result
        except HTTPError as exc:
            status = exc.code
            retry_after = exc.headers.get("Retry-After", "")
            terminal = status not in RETRY_STATUSES or attempt == 4
            detail = ""
            try:
                if terminal and url == "https://oauth.yandex.ru/token":
                    detail = ":" + safe_oauth_error(exc)
            finally:
                exc.close()
            if terminal:
                raise ApiError(f"http_{status}{detail}") from None
            if retry_after.isdigit():
                delay = max(delay, min(int(retry_after), 300))
        except (URLError, TimeoutError, ConnectionError):
            if attempt == 4:
                raise ApiError("network_error") from None
        except UnicodeEncodeError:
            raise ApiError("request_encoding_error") from None
        except (ValueError, UnicodeError):
            raise ApiError("invalid_json") from None
        time.sleep(delay)


def iter_users(config):
    url = (
        "https://cloud-api.yandex.net/v1/directory/organizations/"
        f"{config['ORGID']}/users"
    )
    offset, limit = 0, 100
    seen = set()
    while True:
        result = request_json(
            f"{url}?{urlencode({'limit': limit, 'offset': offset})}",
            token=config["ADMIN_TOKEN"],
        )
        users, total = result["items"], result["total"]
        if not isinstance(users, list) or type(total) is not int or total < 0:
            raise ApiError("invalid_user_list")
        if not users and offset < total:
            raise ApiError("unexpected_empty_page")
        for user in users:
            uid = str(user["id"])
            if uid not in seen:
                seen.add(uid)
                yield user
        offset += limit
        if offset >= total:
            break


def disk_row(user, config):
    row = {
        "email": user["email"], "uid": str(user["id"]),
        "is_enabled": user.get("is_enabled", ""), "status": "ok", "error": "",
    }
    stage = "oauth"
    try:
        token = request_json("https://oauth.yandex.ru/token", form={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": config["CLIENT_ID"],
            "client_secret": config["CLIENT_SECRET"],
            "subject_token": row["uid"],
            "subject_token_type": "urn:yandex:params:oauth:token-type:uid",
        })["access_token"]
        if not isinstance(token, str) or not token:
            raise ApiError("invalid_access_token")
        stage = "disk"
        disk = request_json("https://cloud-api.yandex.net/v1/disk/", token=token)
        used, total = disk["used_space"], disk["total_space"]
        if any(type(value) is not int or value < 0 for value in (used, total)):
            raise ApiError("invalid_capacity")
        # При превышении квоты доступное место равно нулю.
        for name, value in (("used", used), ("free", max(total - used, 0)), ("total", total)):
            row[f"{name}_bytes"] = value
            row[f"{name}_gib"] = f"{value / 1024 ** 3:.4f}"
    except ApiError as exc:
        row.update(status="error", error=f"{stage}:{exc}")
    except (KeyError, TypeError, ValueError):
        row.update(status="error", error=f"{stage}:invalid_response")
    return row


def export(config, output, workers):
    # Сначала получаем весь список: сбой пагинации не создаст неполный отчёт.
    users = list(iter_users(config))
    output.parent.mkdir(parents=True, exist_ok=True)
    errors = 0
    with output.open("x", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, delimiter=";")
        writer.writeheader()
        with ThreadPoolExecutor(max_workers=workers) as executor:
            for row in executor.map(lambda user: disk_row(user, config), users):
                writer.writerow(row)
                stream.flush()
                errors += row["status"] == "error"
    print(f"CSV: {output.resolve()} | пользователей: {len(users)} | ошибок: {errors}")
    return 1 if errors else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(
        f"disk_space_{datetime.now():%Y%m%d_%H%M%S}.csv"
    ))
    parser.add_argument("--workers", type=int, default=5, help="Число потоков (по умолчанию 5)")
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers должен быть больше нуля")
    try:
        config = read_config(Path(__file__).resolve().with_name(".env"))
    except UnicodeError:
        parser.error("Сохраните .env в кодировке UTF-8")
    except OSError:
        parser.error("Не удалось прочитать .env рядом со скриптом")
    except ValueError as exc:
        parser.error(str(exc))
    missing = [name for name, value in config.items() if not value]
    if missing:
        parser.error("Не заданы в окружении или .env: " + ", ".join(missing))
    try:
        for name in ("ADMIN_TOKEN", "CLIENT_ID", "CLIENT_SECRET"):
            validate_credential(name, config[name])
    except ValueError as exc:
        parser.error(str(exc))
    if not config["ORGID"].isascii() or not config["ORGID"].isdigit():
        parser.error("ORGID должен быть числом")
    try:
        return export(config, args.output, args.workers)
    except FileExistsError:
        print("Файл уже существует: укажите другое имя через --output.", file=sys.stderr)
    except ApiError as exc:
        print(f"Ошибка API: {exc}. Выгрузка не завершена.", file=sys.stderr)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        print(f"Выгрузка не завершена: {type(exc).__name__}.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
