"""Supabase pgvector storage for vulnerability embeddings"""

import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

from openai import AsyncOpenAI
from supabase import Client, create_client

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityEmbedding:
    """Vulnerability with embedding vector"""

    id: str
    tech_name: str
    vulnerability_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    embedding: List[float]
    metadata: Dict = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class VectorStore:
    """Vector storage using Supabase pgvector"""

    def __init__(self, supabase_url: str, supabase_key: str, openai_api_key: str):
        """
        Initialize vector store

        Args:
            supabase_url: Supabase project URL
            supabase_key: Supabase API key
            openai_api_key: OpenAI API key for embeddings
        """
        self.supabase: Client = create_client(supabase_url, supabase_key)
        self.openai = AsyncOpenAI(api_key=openai_api_key)
        self.embedding_model = "text-embedding-3-small"
        self.embedding_dimension = 1536

    async def create_embedding(self, text: str) -> List[float]:
        """
        Create embedding vector for text

        Args:
            text: Text to embed

        Returns:
            Embedding vector
        """
        try:
            response = await self.openai.embeddings.create(model=self.embedding_model, input=text)
            return response.data[0].embedding

        except Exception as e:
            logger.error(f"Failed to create embedding: {e}")
            raise

    async def store_vulnerability(
        self,
        tech_name: str,
        vulnerability_id: str,
        title: str,
        description: str,
        severity: str,
        cvss_score: float,
        metadata: Optional[Dict] = None,
    ) -> str:
        """
        Store vulnerability with embedding in Supabase

        Args:
            tech_name: Technology name (e.g., "React", "Django")
            vulnerability_id: CVE or vulnerability ID
            title: Vulnerability title
            description: Detailed description
            severity: CRITICAL, HIGH, MEDIUM, LOW
            cvss_score: CVSS score
            metadata: Additional metadata

        Returns:
            Record ID
        """
        try:
            # Create embedding from title + description
            text = f"{title}. {description}"
            embedding = await self.create_embedding(text)

            # Store in Supabase
            data = {
                "tech_name": tech_name,
                "vulnerability_id": vulnerability_id,
                "title": title,
                "description": description,
                "severity": severity,
                "cvss_score": cvss_score,
                "embedding": embedding,
                "metadata": json.dumps(metadata or {}),
            }

            result = self.supabase.table("vulnerabilities").insert(data).execute()

            logger.info(f"Stored vulnerability: {vulnerability_id} for {tech_name}")
            return result.data[0]["id"]

        except Exception as e:
            logger.error(f"Failed to store vulnerability: {e}")
            raise

    async def search_similar(
        self,
        query: str,
        tech_name: Optional[str] = None,
        limit: int = 10,
        similarity_threshold: float = 0.7,
    ) -> List[Dict]:
        """
        Search for similar vulnerabilities using semantic search

        Args:
            query: Search query
            tech_name: Optional filter by technology
            limit: Maximum results
            similarity_threshold: Minimum similarity score (0-1)

        Returns:
            List of similar vulnerabilities with similarity scores
        """
        try:
            # Create query embedding
            query_embedding = await self.create_embedding(query)

            # Perform vector similarity search
            # Using pgvector's cosine similarity
            rpc_params = {
                "query_embedding": query_embedding,
                "match_threshold": similarity_threshold,
                "match_count": limit,
            }

            if tech_name:
                rpc_params["filter_tech_name"] = tech_name

            result = self.supabase.rpc("match_vulnerabilities", rpc_params).execute()

            logger.info(f"Found {len(result.data)} similar vulnerabilities")
            return result.data

        except Exception as e:
            logger.error(f"Similarity search failed: {e}")
            return []

    async def get_by_tech(
        self, tech_name: str, severity: Optional[str] = None, limit: int = 50
    ) -> List[Dict]:
        """
        Get vulnerabilities by technology name

        Args:
            tech_name: Technology name
            severity: Optional severity filter
            limit: Maximum results

        Returns:
            List of vulnerabilities
        """
        try:
            query = self.supabase.table("vulnerabilities").select("*")
            query = query.eq("tech_name", tech_name)

            if severity:
                query = query.eq("severity", severity)

            query = query.order("cvss_score", desc=True).limit(limit)

            result = query.execute()

            logger.info(f"Found {len(result.data)} vulnerabilities for {tech_name}")
            return result.data

        except Exception as e:
            logger.error(f"Failed to get vulnerabilities: {e}")
            return []

    async def batch_store(self, vulnerabilities: List[Dict]) -> List[str]:
        """
        Batch store multiple vulnerabilities

        Args:
            vulnerabilities: List of vulnerability dicts

        Returns:
            List of record IDs
        """
        ids = []

        for vuln in vulnerabilities:
            try:
                record_id = await self.store_vulnerability(
                    tech_name=vuln["tech_name"],
                    vulnerability_id=vuln["vulnerability_id"],
                    title=vuln["title"],
                    description=vuln["description"],
                    severity=vuln["severity"],
                    cvss_score=vuln["cvss_score"],
                    metadata=vuln.get("metadata"),
                )
                ids.append(record_id)

            except Exception as e:
                logger.error(f"Failed to store {vuln.get('vulnerability_id')}: {e}")
                continue

        logger.info(f"Batch stored {len(ids)}/{len(vulnerabilities)} vulnerabilities")
        return ids

    def init_schema(self):
        """
        Initialize Supabase schema (run this once)

        SQL to run in Supabase SQL editor:

        ```sql
        -- Enable pgvector extension
        create extension if not exists vector;

        -- Create vulnerabilities table
        create table if not exists vulnerabilities (
            id uuid default gen_random_uuid() primary key,
            tech_name text not null,
            vulnerability_id text not null,
            title text not null,
            description text not null,
            severity text not null,
            cvss_score float not null,
            embedding vector(1536),
            metadata jsonb,
            created_at timestamp with time zone default now(),
            updated_at timestamp with time zone default now()
        );

        -- Create index for vector similarity search
        create index if not exists vulnerabilities_embedding_idx
        on vulnerabilities
        using ivfflat (embedding vector_cosine_ops)
        with (lists = 100);

        -- Create index for tech_name
        create index if not exists vulnerabilities_tech_name_idx
        on vulnerabilities (tech_name);

        -- Create index for severity
        create index if not exists vulnerabilities_severity_idx
        on vulnerabilities (severity);

        -- Create function for similarity search
        create or replace function match_vulnerabilities(
            query_embedding vector(1536),
            match_threshold float,
            match_count int,
            filter_tech_name text default null
        )
        returns table (
            id uuid,
            tech_name text,
            vulnerability_id text,
            title text,
            description text,
            severity text,
            cvss_score float,
            similarity float,
            metadata jsonb
        )
        language sql
        as $$
            select
                v.id,
                v.tech_name,
                v.vulnerability_id,
                v.title,
                v.description,
                v.severity,
                v.cvss_score,
                1 - (v.embedding <=> query_embedding) as similarity,
                v.metadata
            from vulnerabilities v
            where
                (filter_tech_name is null or v.tech_name = filter_tech_name)
                and 1 - (v.embedding <=> query_embedding) > match_threshold
            order by v.embedding <=> query_embedding
            limit match_count;
        $$;
        ```
        """
        schema_sql = self.__doc__.split("```sql")[1].split("```")[0]
        logger.info("Schema SQL ready. Run this in Supabase SQL editor:")
        print(schema_sql)
