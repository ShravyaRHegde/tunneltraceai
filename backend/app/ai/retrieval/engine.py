"""Evidence-First Hybrid Retrieval Engine.

Implements the canonical TunnelTrace retrieval sequence:
1. Exact structured entity lookup from PostgreSQL scoped strictly to analysis_id.
2. Exact rule-anchored normative standards lookup based on Stage-8 findings.
3. Hybrid pgvector semantic search + lexical full-text search with RRF.
4. Assembly into FactLockContext and AssembledPromptContext.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.context.assembler import (
    AssembledPromptContext,
    ContextAssembler,
    RetrievedStandardItem,
)
from app.ai.context.fact_lock import FactLockBuilder, FactLockContext
from app.ai.knowledge.service import get_knowledge_service
from app.ai.retrieval.router import QueryIntent, QueryRouter

logger = logging.getLogger(__name__)

# Deterministic rule-to-normative-standard cross-reference mapping
RULE_STANDARD_ANCHORS: dict[str, list[tuple[str, str]]] = {
    "RULE-IKE-V2": [
        ("RFC 7296", "Section 1.2"),
        ("NIST SP 800-77 Rev. 1", "Section 5.1.1"),
    ],
    "RULE-CIPHER-AEAD": [
        ("RFC 8221", "Section 3"),
        ("RFC 8247", "Section 2.1"),
        ("NIST SP 800-77 Rev. 1", "Section 5.1.1"),
    ],
    "RULE-INTEGRITY-ALGO": [
        ("RFC 8221", "Section 3"),
        ("RFC 8247", "Section 2.1"),
    ],
    "RULE-DH-GROUP": [
        ("RFC 8247", "Section 2.4"),
        ("NIST SP 800-57 Part 1 Rev. 5", "Section 5.6.1"),
    ],
    "RULE-PFS-ACTIVE": [
        ("RFC 7296", "Section 1.3"),
        ("NIST SP 800-77 Rev. 1", "Section 5.1.2"),
    ],
    "RULE-ESP-ENCRYPTION": [
        ("RFC 4303", "Section 2.1"),
        ("RFC 8221", "Section 3"),
    ],
    "RULE-REPLAY-PROTECTION": [
        ("RFC 4303", "Section 3.3.3"),
        ("RFC 4303", "Section 3.4.3"),
    ],
    "RULE-PQC-TRANSITION": [
        ("RFC 9395", "Section 1"),
        ("NIST SP 800-77 Rev. 1", "Section 5.1.1"),
    ],
}


class EvidenceFirstRetrievalEngine:
    """Orchestrates evidence-first hybrid retrieval guaranteeing zero cross-analysis leakage."""

    def __init__(self) -> None:
        self.knowledge_service = get_knowledge_service()

    async def retrieve(
        self,
        session: AsyncSession,
        analysis_id: uuid.UUID | str,
        query: str,
        chat_history: list[dict[str, str]] | None = None,
        top_k: int = 5,
    ) -> AssembledPromptContext:
        """Execute full evidence-first retrieval pipeline scoped to analysis_id."""
        # 1. Scope and Fact Lock
        fact_lock = await FactLockBuilder.build_from_analysis(session, analysis_id)

        # 2. Query Routing and Entity Resolution
        routing = QueryRouter.route(query)

        # 3. Exact Rule-Anchored Standards Retrieval
        exact_standards: list[RetrievedStandardItem] = []
        seen_chunks: set[str] = set()

        # Identify which rules are relevant to the query or findings in this analysis
        relevant_rules: set[str] = set(routing.entities.rule_ids)

        if routing.intent == QueryIntent.PROTOCOL_EXPLANATION:
            relevant_rules.update(["RULE-CIPHER-AEAD", "RULE-DH-GROUP", "RULE-ESP-ENCRYPTION", "RULE-IKE-V2"])
        elif routing.intent == QueryIntent.SCORE_EXPLANATION:
            relevant_rules.update(["RULE-IKE-V2", "RULE-CIPHER-AEAD"])

        # If findings were mentioned or exist in this analysis, pull their rule standards
        for item in fact_lock.items:
            if item.fact_type == "SECURITY_FINDING":
                val = item.value if isinstance(item.value, dict) else {}
                rid = val.get("rule_id")
                if rid and (not routing.entities.finding_ids or val.get("finding_id") in routing.entities.finding_ids):
                    relevant_rules.add(rid)

        # Look up exact chunks for relevant rules
        for rule_id in relevant_rules:
            anchors = RULE_STANDARD_ANCHORS.get(rule_id, [])
            for doc_code, sec_ref in anchors:
                chunk = await self.knowledge_service.get_exact_chunk_by_reference(
                    session, doc_code, sec_ref
                )
                if chunk and str(chunk.id) not in seen_chunks:
                    seen_chunks.add(str(chunk.id))
                    exact_standards.append(
                        RetrievedStandardItem(
                            source_id=f"standard:{chunk.document_code}:{chunk.section_reference}",
                            document_code=chunk.document_code,
                            section_reference=chunk.section_reference,
                            section_title=chunk.section_title,
                            authority=chunk.authority,
                            revision=chunk.revision,
                            chunk_text=chunk.chunk_text,
                            similarity_score=1.0,  # Exact rule anchor
                        )
                    )

        # 4. Semantic / Hybrid Standards Retrieval
        # Remaining budget for semantic search
        semantic_budget = max(2, top_k - len(exact_standards))
        hybrid_matches = await self.knowledge_service.hybrid_search(
            session, query=query, top_k=semantic_budget
        )

        for chunk, score in hybrid_matches:
            if str(chunk.id) not in seen_chunks:
                seen_chunks.add(str(chunk.id))
                exact_standards.append(
                    RetrievedStandardItem(
                        source_id=f"standard:{chunk.document_code}:{chunk.section_reference}",
                        document_code=chunk.document_code,
                        section_reference=chunk.section_reference,
                        section_title=chunk.section_title,
                        authority=chunk.authority,
                        revision=chunk.revision,
                        chunk_text=chunk.chunk_text,
                        similarity_score=score,
                    )
                )

        # 5. Assemble Context
        return ContextAssembler.assemble(
            fact_lock=fact_lock,
            standards=exact_standards,
            query=query,
            chat_history=chat_history,
        )

    async def search_evidence_only(
        self,
        session: AsyncSession,
        analysis_id: uuid.UUID | str,
        query: str,
        top_k: int = 5,
    ) -> dict[str, Any]:
        """Deterministic Evidence Search fallback (useful when LLM is offline)."""
        fact_lock = await FactLockBuilder.build_from_analysis(session, analysis_id)
        routing = QueryRouter.route(query)

        # Filter relevant facts
        relevant_facts = [
            item.to_dict()
            for item in fact_lock.items
            if any(term in item.name.lower() or term in item.source_id.lower() for term in query.lower().split())
            or item.fact_type in ("SECURITY_FINDING", "SECURITY_SCORE")
        ]

        # Hybrid search standards
        standards_matches = await self.knowledge_service.hybrid_search(
            session, query=query, top_k=top_k
        )

        return {
            "analysis_id": str(analysis_id),
            "query": query,
            "intent": routing.intent.value,
            "fact_lock_hash": fact_lock.fact_lock_hash,
            "matched_facts": relevant_facts[:10],
            "matched_standards": [
                {
                    "source_id": f"standard:{c.document_code}:{c.section_reference}",
                    "document_code": c.document_code,
                    "section_reference": c.section_reference,
                    "section_title": c.section_title,
                    "authority": c.authority,
                    "similarity": sim,
                    "excerpt": c.chunk_text[:300] + "...",
                }
                for c, sim in standards_matches
            ],
        }


_retrieval_engine: EvidenceFirstRetrievalEngine | None = None


def get_retrieval_engine() -> EvidenceFirstRetrievalEngine:
    """Singleton getter for EvidenceFirstRetrievalEngine."""
    global _retrieval_engine
    if _retrieval_engine is None:
        _retrieval_engine = EvidenceFirstRetrievalEngine()
    return _retrieval_engine
