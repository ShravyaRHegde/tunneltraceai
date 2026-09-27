"""Grounded AI Analyst Orchestrator Service.

Coordinates Evidence-First Retrieval -> Fact Lock Context Assembly ->
Local LLM Generation (Qwen/Gemma) -> Citation Integrity Gate ->
Claim Grounding Gate -> Bounded Repair / Abstention -> Answer Provenance Ledger.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.context.assembler import AssembledPromptContext
from app.ai.grounding.abstention import (
    CANONICAL_ABSTENTION_MESSAGE,
    AbstentionDetector,
)
from app.ai.grounding.citation_gate import CitationIntegrityGate
from app.ai.grounding.claim_gate import ClaimGroundingGate
from app.ai.grounding.provenance import AnswerProvenanceLedger
from app.ai.provider import (
    ModelTimeoutError,
    ModelUnavailableError,
    StructuredOutputError,
    get_llm_provider,
)
from app.ai.retrieval.engine import get_retrieval_engine
from app.core.config import get_settings
from app.db.models.ai import (
    AIChatMessageModel,
    AIChatSessionModel,
    RAGQueryRunModel,
)

logger = logging.getLogger(__name__)


class GroundedAIAnalystService:
    """Master service for grounded, explainable forensic reasoning."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.provider = get_llm_provider()
        self.retrieval_engine = get_retrieval_engine()

    async def get_or_create_session(
        self,
        session: AsyncSession,
        session_id: uuid.UUID | str | None,
        analysis_id: uuid.UUID | str | None,
        model_name: str | None = None,
    ) -> AIChatSessionModel:
        """Retrieve existing active chat session or instantiate a new one."""
        target_model = model_name or self.settings.AI_PRIMARY_MODEL
        aid = uuid.UUID(str(analysis_id)) if analysis_id else None

        if session_id:
            sid = uuid.UUID(str(session_id))
            stmt = select(AIChatSessionModel).where(AIChatSessionModel.id == sid)
            res = await session.execute(stmt)
            chat_session = res.scalar_one_or_none()
            if chat_session:
                return chat_session

        # Create new chat session
        new_session = AIChatSessionModel(
            analysis_id=aid,
            title="IPsec Security Analysis Thread",
            model_name=target_model,
            is_active=True,
        )
        session.add(new_session)
        await session.flush()
        return new_session

    async def execute_query(
        self,
        session: AsyncSession,
        analysis_id: uuid.UUID | str,
        question: str,
        chat_session_id: uuid.UUID | str | None = None,
        model_override: str | None = None,
    ) -> dict[str, Any]:
        """Execute full grounded analysis query adhering to all canonical safety gates."""
        start_time = time.perf_counter()
        aid = uuid.UUID(str(analysis_id))
        selected_model = model_override or self.settings.AI_PRIMARY_MODEL

        # 1. Resolve or create chat session
        chat_session = await self.get_or_create_session(
            session, chat_session_id, aid, model_name=selected_model
        )

        # 2. Fetch recent conversation history
        history_stmt = (
            select(AIChatMessageModel)
            .where(AIChatMessageModel.session_id == chat_session.id)
            .order_by(AIChatMessageModel.created_at.asc())
        )
        history_res = await session.execute(history_stmt)
        messages = history_res.scalars().all()
        chat_history = [
            {"role": m.role, "content": m.content}
            for m in messages
        ]

        # Record user message in DB
        user_msg = AIChatMessageModel(
            session_id=chat_session.id,
            role="user",
            content=question.strip(),
            status="COMPLETED",
        )
        session.add(user_msg)
        await session.flush()

        # 3. Evidence-First Hybrid Retrieval & Fact-Lock Context Assembly
        try:
            assembled: AssembledPromptContext = await self.retrieval_engine.retrieve(
                session=session,
                analysis_id=aid,
                query=question,
                chat_history=chat_history,
                top_k=self.settings.AI_RETRIEVAL_TOP_K,
            )
        except Exception as exc:
            logger.error("Retrieval failed for analysis %s: %s", aid, exc, exc_info=True)
            return self._build_error_response(
                chat_session.id,
                status="RETRIEVAL_FAILED",
                answer="Failed to retrieve forensic analysis facts from database.",
                error=str(exc),
                analysis_id=aid,
            )

        # 4. Local Model Generation Pass
        gen_start = time.perf_counter()
        parsed_json: dict[str, Any] = {}
        llm_resp = None
        current_model = selected_model

        try:
            parsed_json, llm_resp = await self.provider.generate_structured(
                prompt=assembled.user_prompt,
                system=assembled.system_prompt,
                model=current_model,
                temperature=0.1,
                max_tokens=1024,
            )
        except (ModelUnavailableError, ModelTimeoutError) as exc:
            logger.warning(
                "Primary model %s failed (%s). Attempting fallback %s",
                current_model,
                exc,
                self.settings.AI_FALLBACK_MODEL,
            )
            # Attempt secondary fallback model
            current_model = self.settings.AI_FALLBACK_MODEL
            try:
                parsed_json, llm_resp = await self.provider.generate_structured(
                    prompt=assembled.user_prompt,
                    system=assembled.system_prompt,
                    model=current_model,
                    temperature=0.1,
                    max_tokens=1024,
                )
            except Exception as fb_exc:
                logger.error("Fallback model also failed: %s", fb_exc)
                return self._build_error_response(
                    chat_session.id,
                    status="MODEL_UNAVAILABLE",
                    answer="Local AI model runtime is currently offline or timed out.",
                    error=str(fb_exc),
                    analysis_id=aid,
                )
        except StructuredOutputError as exc:
            logger.warning("Structured output error from model: %s", exc)
            # Build controlled fallback response
            parsed_json = AbstentionDetector.build_abstention_response("Model produced invalid structured output")

        gen_latency_ms = (time.perf_counter() - gen_start) * 1000.0

        # Extract components
        status = parsed_json.get("status", "ANSWERED")
        raw_answer = str(parsed_json.get("answer", "")).strip()
        claims = parsed_json.get("claims", [])
        citations = parsed_json.get("citations", [])
        limitations = parsed_json.get("limitations", [])

        # 5. Citation Integrity Gate Check
        cit_result = CitationIntegrityGate.validate(
            model_citations=citations,
            answer_text=raw_answer,
            allowed_source_ids=assembled.allowed_source_ids,
        )

        # 6. Claim Grounding Gate Check
        claim_result = ClaimGroundingGate.validate(
            claims=claims,
            answer_text=raw_answer,
            fact_lock=assembled.fact_lock,
        )

        # 7. Bounded Repair Pass (If validation failed and not an abstention)
        if (not cit_result.is_valid or not claim_result.is_valid) and not AbstentionDetector.is_abstention(raw_answer):
            logger.warning(
                "Grounding validation failed (Citations valid=%s, Claims valid=%s). Invoking controlled repair pass.",
                cit_result.is_valid,
                claim_result.is_valid,
            )
            repair_feedback = (
                f"\n\n[VALIDATION WARNING: Your previous response was rejected by the grounding gate.\n"
                f"Citation errors: {cit_result.error_summary or 'None'}\n"
                f"Claim errors: {claim_result.error_summary or 'None'}\n"
                f"CORRECTION MANDATE: You MUST cite ONLY source IDs from this allowed set: "
                f"{sorted(list(assembled.allowed_source_ids))[:15]}...\n"
                f"Do not contradict <fact_lock> or invent CVEs. If evidence is lacking, respond with the canonical abstention.]"
            )

            try:
                parsed_json, llm_resp = await self.provider.generate_structured(
                    prompt=assembled.user_prompt + repair_feedback,
                    system=assembled.system_prompt,
                    model=current_model,
                    temperature=0.05,
                    max_tokens=1024,
                )
                raw_answer = str(parsed_json.get("answer", "")).strip()
                claims = parsed_json.get("claims", [])
                citations = parsed_json.get("citations", [])
                limitations = parsed_json.get("limitations", [])

                # Re-validate
                cit_result = CitationIntegrityGate.validate(
                    model_citations=citations,
                    answer_text=raw_answer,
                    allowed_source_ids=assembled.allowed_source_ids,
                )
                claim_result = ClaimGroundingGate.validate(
                    claims=claims,
                    answer_text=raw_answer,
                    fact_lock=assembled.fact_lock,
                )
            except Exception as repair_exc:
                logger.error("Repair pass failed: %s", repair_exc)

            # If still invalid after repair, enforce canonical abstention
            if not cit_result.is_valid or not claim_result.is_valid:
                logger.error("Grounding gate failed after repair. Enforcing canonical abstention.")
                status = "INSUFFICIENT_EVIDENCE"
                raw_answer = CANONICAL_ABSTENTION_MESSAGE
                claims = []
                citations = []
                limitations = ["Grounding validation failed to verify model citations/claims against authoritative evidence."]

        # Ensure answer is never empty string
        if not raw_answer.strip():
            score_items = assembled.fact_lock.get_items_by_type("SECURITY_SCORE")
            is_unassessable = False
            if score_items:
                sc_val = score_items[0].value
                if isinstance(sc_val, dict) and sc_val.get("coverage_percentage", 100.0) == 0.0:
                    is_unassessable = True
            elif not assembled.fact_lock.items:
                is_unassessable = True

            if is_unassessable:
                status = "INSUFFICIENT_EVIDENCE"
                raw_answer = "No observable IPsec packet evidence (IKE negotiation or ESP traffic) was found in this capture artifact. Consequently, cryptographic parameters and compliance posture cannot be verified, and policy rules remain in an UNKNOWN evidence state."
                limitations = ["Zero observable IPsec packet evidence found in capture."]
            else:
                status = "INSUFFICIENT_EVIDENCE"
                raw_answer = CANONICAL_ABSTENTION_MESSAGE
                limitations = ["Model produced empty structured answer; enforced canonical evidence abstention."]

        total_latency_ms = (time.perf_counter() - start_time) * 1000.0

        # 8. Record RAG Query Run Audit Trace
        query_run_id = uuid.uuid4()
        source_ids_used = [str(c.get("source_id", "")) for c in cit_result.valid_citations]

        import hashlib
        q_hash = hashlib.sha256(question.encode("utf-8")).hexdigest()

        query_run = RAGQueryRunModel(
            id=query_run_id,
            analysis_id=aid,
            session_id=chat_session.id,
            query_text_hash=q_hash,
            query_intent="EXPLANATION",
            retrieved_source_ids=list(assembled.allowed_source_ids),
            model_name=current_model,
            embedding_model=self.settings.AI_EMBEDDING_MODEL,
            prompt_template_version=assembled.prompt_template_version,
            citation_validity_rate=cit_result.validity_rate,
            execution_status=status,
            latency_ms=total_latency_ms,
        )
        session.add(query_run)
        await session.flush()

        # 9. Record Tamper-Evident Answer Provenance Ledger
        provenance_rec = await AnswerProvenanceLedger.record_provenance(
            session=session,
            query_run_id=query_run_id,
            analysis_id=aid,
            answer_text=raw_answer,
            fact_lock_hash=assembled.fact_lock.fact_lock_hash,
            retrieved_source_ids=source_ids_used,
            prompt_text=assembled.user_prompt,
            model_name=current_model,
            citation_summary={
                "total": cit_result.total_citations,
                "valid": len(cit_result.valid_citations),
                "validity_rate": cit_result.validity_rate,
            },
        )

        # 10. Persist Assistant Message
        assistant_msg = AIChatMessageModel(
            session_id=chat_session.id,
            role="assistant",
            content=raw_answer,
            status=status,
            claims=list(cit_result.valid_citations) if claims is None else claims,
            citations=list(cit_result.valid_citations),
            limitations=limitations,
            fact_locks=[item.to_dict() for item in assembled.fact_lock.items[:10]],
            query_run_id=query_run_id,
        )
        session.add(assistant_msg)
        await session.commit()

        return {
            "query_run_id": str(query_run_id),
            "session_id": str(chat_session.id),
            "analysis_id": str(aid),
            "status": status,
            "answer": raw_answer,
            "claims": claims,
            "citations": list(cit_result.valid_citations),
            "limitations": limitations,
            "provenance": {
                "answer_hash": provenance_rec.answer_hash,
                "fact_lock_hash": provenance_rec.fact_lock_hash,
                "prompt_template_version": assembled.prompt_template_version,
                "model_name": current_model,
                "verified_at": provenance_rec.verified_at.isoformat(),
            },
            "metrics": {
                "generation_ms": round(gen_latency_ms, 2),
                "total_ms": round(total_latency_ms, 2),
                "citation_validity_rate": cit_result.validity_rate,
                "prompt_eval_count": llm_resp.prompt_eval_count if llm_resp else 0,
                "eval_count": llm_resp.eval_count if llm_resp else 0,
            },
        }

    def _build_error_response(
        self,
        session_id: uuid.UUID,
        status: str,
        answer: str,
        error: str,
        analysis_id: uuid.UUID | str | None = None,
    ) -> dict[str, Any]:
        return {
            "query_run_id": str(uuid.uuid4()),
            "session_id": str(session_id),
            "analysis_id": str(analysis_id) if analysis_id else "",
            "status": status,
            "answer": answer,
            "claims": [],
            "citations": [],
            "limitations": [f"Execution halted: {error}"],
            "provenance": None,
            "metrics": {"total_ms": 0.0},
        }


_analyst_service: GroundedAIAnalystService | None = None


def get_analyst_service() -> GroundedAIAnalystService:
    """Singleton getter for GroundedAIAnalystService."""
    global _analyst_service
    if _analyst_service is None:
        _analyst_service = GroundedAIAnalystService()
    return _analyst_service
