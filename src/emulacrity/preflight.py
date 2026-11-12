"""Pre-flight checks for Mode 1 source material.

Fails fast, before any tokens are spent or web search runs, when the
combined local sources would exceed the Messages API's request-size or
PDF-page limits — rather than letting a large multi-PDF evaluation error
out after minutes of thinking/search spend.

Limits (per the PDF support docs): 32 MB request body, 600 pages per
request for 1M-context models (e.g. claude-sonnet-5, what Emulacrity uses).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pypdf import PdfReader

MAX_REQUEST_BYTES = 32 * 1024 * 1024
MAX_PAGES = 600
MAX_TEXT_FILE_BYTES = 2 * 1024 * 1024  # 2 MB per non-PDF source file
# base64 inflates raw bytes by 4/3; PDFs go over the wire base64-encoded,
# plain-text sources don't.
BASE64_OVERHEAD = 4 / 3


class PreflightError(ValueError):
    """Raised when local source material would exceed a known API limit."""


@dataclass
class _SourceInfo:
    path: Path
    raw_bytes: int
    page_count: int = 0
    is_pdf: bool = False


def _inspect(path: Path) -> _SourceInfo:
    if not path.exists():
        raise PreflightError(f"Source file not found: {path}")

    raw_bytes = path.stat().st_size
    if path.suffix.lower() != ".pdf":
        if raw_bytes >= MAX_TEXT_FILE_BYTES:
            raise PreflightError(
                f"Text source '{path.name}' is {raw_bytes / (1024 * 1024):.1f} MB, "
                f"which exceeds the {MAX_TEXT_FILE_BYTES // (1024 * 1024)} MB per-file "
                "limit for text sources. Trim, split, or convert to PDF."
            )
        return _SourceInfo(path=path, raw_bytes=raw_bytes)

    try:
        page_count = len(PdfReader(str(path)).pages)
    except Exception as exc:  # malformed/encrypted/corrupt PDF
        raise PreflightError(f"Could not read '{path}' as a PDF: {exc}") from exc

    return _SourceInfo(path=path, raw_bytes=raw_bytes, page_count=page_count, is_pdf=True)


def check_local_sources(paths: list[Path]) -> None:
    """Validate combined local (non-URL) Mode 1 sources against API limits."""
    if not paths:
        return

    infos = [_inspect(p) for p in paths]

    estimated_request_bytes = sum(
        int(info.raw_bytes * BASE64_OVERHEAD) if info.is_pdf else info.raw_bytes
        for info in infos
    )
    if estimated_request_bytes > MAX_REQUEST_BYTES:
        mib = 1024 * 1024
        raw_mb = sum(info.raw_bytes for info in infos) / mib
        est_mb = estimated_request_bytes / mib
        limit_mb = MAX_REQUEST_BYTES / mib
        raise PreflightError(
            f"Combined source material is ~{raw_mb:.1f} MB on disk "
            f"(~{est_mb:.1f} MB once PDFs are base64-encoded for the "
            f"request), which exceeds the Messages API's {limit_mb:.0f} MB "
            "request limit. Trim, split, or drop a source."
        )

    total_pages = sum(info.page_count for info in infos)
    if total_pages > MAX_PAGES:
        per_file = ", ".join(
            f"{info.path.name}: {info.page_count}p" for info in infos if info.is_pdf
        )
        raise PreflightError(
            f"Combined source PDFs have {total_pages} pages, which exceeds "
            f"the {MAX_PAGES}-page-per-request limit ({per_file}). Trim, "
            "split, or drop a source."
        )
