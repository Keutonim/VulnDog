"""Общий модуль редкации секретов в выводах инструментов/логах (УМ-6; B4.T0 SEC-11).

``redact(text) -> str`` маскирует заголовки и токены, чтобы куки/секреты
никогда не попадали в tool-сообщения LLM, SSE-ноты или evidence:
Authorization, Cookie, Set-Cookie, X-Api-Key, ``token=``, JWT (``eyJ...``),
``password=...`` → ``<redacted>``. API-ключи дополнительно прогоняются через
``config.mask_secret``.

B4.T0 SEC-11 — расширенные паттерны: AWS (``AKIA…``), GitHub (``ghp_/ghs_``),
``sk-…``, ``api_key``/``apikey``/``refresh_token``/``access_token`` в JSON-полях,
``-----BEGIN PRIVATE KEY``, session-id-куки (``PHPSESSID=``, ``JSESSIONID=``).

``sanitize_snapshot(text)`` — для снапшотов ARIA/DOM, попадающих в evidence:
вырезает строки с ``document.cookie``/``localStorage``/``sessionStorage``,
прогоняет ``redact()`` и ограничивает размер (``MAX_SNAPSHOT_BYTES`` = 200 KB);
скриншоты — ``MAX_SCREENSHOT_BYTES`` = 2 MB.
"""

from __future__ import annotations

import logging
import re

# SEC-11: лимиты размера evidence.
MAX_SNAPSHOT_BYTES = 200_000  # 200 KB текст (снапшоты/DOM)
MAX_SCREENSHOT_BYTES = 2_000_000  # 2 MB скриншот

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

_PATTERNS = [
    re.compile(r"(?i)(authorization\s*:\s*(?:bearer\s+)?)[^\s\r\n]+"),
    re.compile(r"(?i)(set-cookie\s*:\s*)[^\r\n]+"),
    re.compile(r"(?i)(cookie\s*:\s*)[^\r\n]+"),
    re.compile(r"(?i)(x-api-key\s*:\s*)[^\s\r\n]+"),
    re.compile(r"(?i)(token\s*=\s*)[^\s&;,\r\n]+"),
    re.compile(r"(?i)(password\s*=\s*)[^\s&;,\r\n]+"),
    # B4.T0 SEC-11: session-id-куки; B6.T4: расширен до session=/sess= (SEC-12:
    # «session-id-подобные» — sessionid, а также короткая форма session)
    re.compile(r"(?i)((?:phpsessid|jsessionid|asp\.net_sessionid|sessionid|session|sess)\s*=\s*)[^\s&;,\r\n]+"),
    # B4.T0 SEC-11: секретные ключи в JSON-подобных полях (имя остаётся, значение маскируется)
    re.compile(
        r"""(?i)(["']?(?:api_?key|refresh_token|access_token|secret|client_secret)["']?\s*[:=]\s*["']?)[^\s"',}\]]+"""
    ),
]

# B4.T0 SEC-11: токены без «имени» — маскируются целиком.
_TOKEN_RES = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),  # GitHub tokens
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),  # OpenAI-style / router sk-ключи
    re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY(?: BLOCK)?-----"),  # PEM
]

# SEC-11: строки снапшота с клиентскими секретами вырезаются целиком.
# Линейный поиск по строкам (без .*(...).*$ — бэктрекинг на больших текстах).
_STORAGE_MARK_RE = re.compile(r"(?i)document\.cookie|localstorage|sessionstorage")


def _drop_storage_lines(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not _STORAGE_MARK_RE.search(line))


def _redact_jwt(match: re.Match) -> str:
    token = match.group(0)
    return token[:10] + "<redacted>"


def redact(text: str) -> str:
    if not isinstance(text, str):
        return text
    out = text
    for pattern in _PATTERNS:
        out = pattern.sub(lambda m: m.group(1) + "<redacted>", out)
    for token_re in _TOKEN_RES:
        out = token_re.sub("<redacted>", out)
    out = _JWT_RE.sub(_redact_jwt, out)
    return out


# SEC-10c/12 (B6.T4): частичный JWT-остаток после redact() — тоже значение.
_PARTIAL_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+")


def scrub(text: str) -> str:
    """``redact()`` + добив частичных JWT (``eyJhbGciO<redacted>`` → ``<jwt>``).

    Канальный вариант для персиста/передачи (SEC-12: sqlite/SSE/PDF/экспорты/
    логи): куски токенов — не меньше утечка, чем токен целиком.
    """
    if not isinstance(text, str):
        return text
    return _PARTIAL_JWT_RE.sub("<jwt>", redact(text))


def sanitize_snapshot(text: str, max_bytes: int = MAX_SNAPSHOT_BYTES) -> str:
    """SEC-11: снапшот/сниппет DOM для evidence.

    1) вырезаются строки с ``document.cookie``/``localStorage``/``sessionStorage``
       (значения клиентских секретов не должны попадать в evidence вовсе);
    2) ``redact()`` по расширенным паттернам;
    3) жёсткий лимит размера (``max_bytes``, дефолт 200 KB) с маркером обрезки.
    """
    if not isinstance(text, str):
        return text
    out = _drop_storage_lines(text)
    out = redact(out)
    encoded = out.encode("utf-8")
    if len(encoded) <= max_bytes:
        return out
    dropped = len(encoded) - max_bytes
    kept = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return f"{kept}\n...[truncated {dropped} bytes]"


def redact_key(key: str) -> str:
    """Маскировать значение API-ключа через config.mask_secret (безопасно)."""
    if not key:
        return "<empty>"
    try:
        from ..config import mask_secret

        return mask_secret(key)
    except Exception:  # noqa: BLE001
        return "<redacted>"


# --------------------------------------------------------------- консоль-логи


class RedactingLogFilter(logging.Filter):
    """SEC-12 (B6.T4), канал «логи uvicorn/консоль»: каждая запись лога
    проходит ``scrub`` — секреты цели не попадают в лог-файлы/консоль.

    Устанавливается на хендлеры/логгеры через :func:`install_redacting_filter`
    (api.create_app); работает и для ``logger.warning("... %s", value)``
    (args сворачиваются в отредактированное сообщение).
    """

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            message = record.getMessage()
            scrubbed = scrub(message)
            if scrubbed != message:
                record.msg = scrubbed
                record.args = None
        except Exception:  # noqa: BLE001 — лог-фильтр не роняет логирование
            pass
        return True


def install_redacting_filter(target: logging.Logger | None = None) -> RedactingLogFilter:
    """Повесить RedactingLogFilter на логгер (по умолчанию — корневой vulndog).

    Идемпотентно: повторная установка не дублирует фильтр.
    """
    logger = target or logging.getLogger("vulndog")
    for existing in logger.filters:
        if isinstance(existing, RedactingLogFilter):
            return existing
    flt = RedactingLogFilter()
    logger.addFilter(flt)
    return flt
