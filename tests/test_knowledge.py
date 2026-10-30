from __future__ import annotations

from app.core.knowledge.retriever import KnowledgeRetriever, tokenize


def test_retriever_filters_by_type_and_language():
    retriever = KnowledgeRetriever()
    sql_entries = retriever.retrieve("SQL_INJECTION", "python", "f-string execute", top_k=5)
    assert sql_entries
    assert all(
        "SQL_INJECTION" in entry.vuln_types or "GENERAL" in entry.vuln_types
        for entry in sql_entries
    )
    assert all("python" in entry.languages or "GENERAL" in entry.vuln_types for entry in sql_entries)


def test_retriever_http_ignores_language_filter():
    retriever = KnowledgeRetriever()
    http_entries = retriever.retrieve("XSS", "http", "encoded script payload", top_k=3)
    assert http_entries
    assert all(
        "XSS" in entry.vuln_types or "GENERAL" in entry.vuln_types
        for entry in http_entries
    )


def test_retriever_top_k_and_general_fallback():
    retriever = KnowledgeRetriever()
    assert len(retriever.retrieve("SQL_INJECTION", "python", top_k=2)) == 2
    general = retriever.retrieve("UNKNOWN_TYPE", "python", top_k=3)
    assert general
    assert all("GENERAL" in entry.vuln_types for entry in general)
    assert retriever.retrieve("SQL_INJECTION", "cobol", top_k=3) == []


def test_public_entries_lookup_and_tokenize():
    retriever = KnowledgeRetriever()
    entries = retriever.public_entries(["KB-SQLI-02", "KB-SQLI-02", "KB-NOT-FOUND"])
    assert [entry["id"] for entry in entries] == ["KB-SQLI-02"]
    assert entries[0]["title"]
    assert retriever.get("KB-XSS-01") is not None
    assert tokenize("SQLi: f-string / placeholder!") == ["sqli", "f", "string", "placeholder"]
