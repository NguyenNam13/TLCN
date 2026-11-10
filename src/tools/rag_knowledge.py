# -*- coding: utf-8 -*-
"""
src/tools/rag_knowledge.py
Module alias cho rag_knowledge_base.py nhằm đảm bảo tính tương thích và linh hoạt
giữa các quy ước đặt tên (rag_knowledge vs rag_knowledge_base).
"""

from src.tools.rag_knowledge_base import (
    FallbackVectorStore,
    RAGKnowledgeBaseTool,
    CHROMADB_AVAILABLE,
)

__all__ = [
    "FallbackVectorStore",
    "RAGKnowledgeBaseTool",
    "CHROMADB_AVAILABLE",
]
