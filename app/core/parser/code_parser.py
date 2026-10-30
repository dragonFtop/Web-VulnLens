from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.errors import AppError

EXT_LANGUAGE = {
    ".py": "python",
    ".php": "php",
    ".js": "javascript",
}

LANGUAGE_DISPLAY = {
    "python": "Python",
    "php": "PHP",
    "javascript": "JavaScript",
    "http": "HTTP 请求",
}

ENCODINGS = ("utf-8-sig", "gbk", "latin-1")


@dataclass
class ParsedCode:
    filename: str
    language: str
    text: str
    lines: list[str]
    encoding: str

    @property
    def line_count(self) -> int:
        return len(self.lines)

    def line(self, number: int) -> str:
        if 1 <= number <= len(self.lines):
            return self.lines[number - 1]
        return ""


def decode_bytes(data: bytes) -> tuple[str, str]:
    if b"\x00" in data:
        raise AppError("E_UPLOAD_TYPE", "文件包含二进制内容，无法作为代码分析", 400)
    for encoding in ENCODINGS:
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    raise AppError("E_UPLOAD_TYPE", "无法识别文件编码，请转换为 UTF-8", 400)


def detect_language(filename: str | None, text: str) -> str:
    suffix = Path(filename or "").suffix.lower()
    if suffix in EXT_LANGUAGE:
        return EXT_LANGUAGE[suffix]

    lowered = text.lower()
    if "<?php" in lowered:
        return "php"
    python_signals = ("def ", "import ", "from ", "print(", "self.")
    js_signals = ("function ", "const ", "let ", "=>", "console.log", "require(")
    py_score = sum(signal in text for signal in python_signals)
    js_score = sum(signal in text for signal in js_signals)
    if "<?php" in lowered:
        return "php"
    if js_score > py_score and js_score > 0:
        return "javascript"
    if py_score > 0:
        return "python"
    raise AppError("E_UPLOAD_TYPE", "无法识别代码语言，仅支持 .py/.php/.js", 400)


def parse_code(data: bytes | str, filename: str) -> ParsedCode:
    if isinstance(data, bytes):
        text, encoding = decode_bytes(data)
    else:
        text, encoding = data, "utf-8"
    language = detect_language(filename, text)
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")
    return ParsedCode(
        filename=filename,
        language=language,
        text=normalized,
        lines=lines,
        encoding=encoding,
    )


def format_numbered(lines: list[str], start: int, end: int) -> str:
    start = max(start, 1)
    end = min(end, len(lines))
    if start > end:
        return ""
    width = len(str(end))
    return "\n".join(f"{number:>{width}} | {lines[number - 1]}" for number in range(start, end + 1))
