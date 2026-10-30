from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from rank_bm25 import BM25Okapi

TOKEN_RE = re.compile(r"[a-z0-9_]+")

TYPE_EXPANSION = {
    "SQL_INJECTION": "sql injection parameterized prepared statement placeholder bind query hard negative",
    "XSS": "xss output encoding html escape sanitize dom context hard negative",
    "COMMAND_INJECTION": "command injection shell subprocess eval exec allowlist escape hard negative",
}


@dataclass(frozen=True)
class KnowledgeEntry:
    id: str
    title: str
    cwe: str
    vuln_types: tuple[str, ...]
    languages: tuple[str, ...]
    keywords: tuple[str, ...]
    content: str
    refs: tuple[str, ...]

    def to_prompt_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "cwe": self.cwe,
            "content": self.content,
            "refs": list(self.refs),
        }

    def to_public_dict(self) -> dict:
        return self.to_prompt_dict()


def tokenize(text: str) -> list[str]:
    return TOKEN_RE.findall(text.lower())


class KnowledgeRetriever:
    def __init__(self, kb_path: Path | str | None = None) -> None:
        path = Path(kb_path) if kb_path else Path(__file__).with_name("kb.jsonl")
        self.entries: list[KnowledgeEntry] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)
                self.entries.append(
                    KnowledgeEntry(
                        id=raw["id"],
                        title=raw["title"],
                        cwe=raw.get("cwe", ""),
                        vuln_types=tuple(raw.get("vuln_types", [])),
                        languages=tuple(raw.get("languages", [])),
                        keywords=tuple(raw.get("keywords", [])),
                        content=raw.get("content", ""),
                        refs=tuple(raw.get("refs", [])),
                    )
                )

    def _filtered(self, vuln_type: str, language: str) -> list[KnowledgeEntry]:
        return [
            entry
            for entry in self.entries
            if (vuln_type in entry.vuln_types or "GENERAL" in entry.vuln_types)
            and (language == "http" or language in entry.languages)
        ]

    def retrieve(
        self,
        vuln_type: str,
        language: str,
        query_text: str = "",
        top_k: int = 3,
    ) -> list[KnowledgeEntry]:
        filtered = self._filtered(vuln_type, language)
        if not filtered:
            return []
        query = " ".join(
            [vuln_type, language, TYPE_EXPANSION.get(vuln_type, ""), query_text[:2000]]
        )
        query_tokens = tokenize(query)
        corpus = [
            tokenize(
                " ".join(
                    [
                        entry.id,
                        entry.title,
                        entry.cwe,
                        " ".join(entry.keywords),
                        entry.content,
                    ]
                )
            )
            or ["empty"]
            for entry in filtered
        ]
        bm25 = BM25Okapi(corpus)
        scores = bm25.get_scores(query_tokens)
        ranked = sorted(
            zip(filtered, scores),
            key=lambda pair: (-float(pair[1]), pair[0].id),
        )
        if all(float(score) <= 0 for _, score in ranked):
            ranked = sorted(
                zip(filtered, scores),
                key=lambda pair: (
                    0 if vuln_type in pair[0].vuln_types else 1,
                    pair[0].id,
                ),
            )
        return [entry for entry, _ in ranked[: max(top_k, 1)]]

    def get(self, entry_id: str) -> KnowledgeEntry | None:
        for entry in self.entries:
            if entry.id == entry_id:
                return entry
        return None

    def public_entries(self, entry_ids: list[str]) -> list[dict]:
        result = []
        seen = set()
        for entry_id in entry_ids:
            if entry_id in seen:
                continue
            seen.add(entry_id)
            entry = self.get(entry_id)
            if entry:
                result.append(entry.to_public_dict())
        return result


@lru_cache(maxsize=1)
def get_retriever() -> KnowledgeRetriever:
    return KnowledgeRetriever()
