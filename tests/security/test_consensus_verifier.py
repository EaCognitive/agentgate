"""Tests for distributed certificate consensus and transparency log."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from server.policy_governance.kernel import consensus_verifier
from server.policy_governance.kernel.consensus_verifier import (
    ConsensusConfig,
    ConsensusResult,
    CoSignature,
    SafetyNode,
    TransparencyLogEntry,
    _load_consensus_config,
    append_to_transparency_log,
    broadcast_global_revocation,
    collect_quorum,
    get_global_revocations,
    get_safety_nodes,
    get_transparency_log,
    register_safety_node,
    remove_safety_node,
    request_co_signature,
    verify_transparency_log,
)
from server.policy_governance.kernel.formal_models import (
    AlphaContext,
    DecisionCertificate,
    DecisionResult,
    GammaKnowledgeBase,
    ProofType,
)


@pytest.fixture(name="mock_session")
def fixture_mock_session():
    """Create a mock async database session."""
    session = AsyncMock()
    session.add = MagicMock()
    session.delete = AsyncMock()
    return session


@pytest.fixture(name="sample_certificate")
def fixture_sample_certificate():
    """Create a sample decision certificate for testing."""
    return DecisionCertificate(
        theorem_hash="a" * 64,
        result=DecisionResult.ADMISSIBLE,
        proof_type=ProofType.CONSTRUCTIVE_TRACE,
        proof_payload={"trace": "test"},
        alpha_hash="b" * 64,
        gamma_hash="c" * 64,
        solver_version="formal-solver/v1",
        signature="test_signature",
    )


@pytest.fixture(name="sample_alpha")
def fixture_sample_alpha():
    """Create a sample alpha context."""
    return AlphaContext.from_runtime(
        principal="user@example.com",
        action="read",
        resource="document://test",
        runtime_context={"ip": "127.0.0.1"},
    )


@pytest.fixture(name="sample_gamma")
def fixture_sample_gamma():
    """Create a sample gamma knowledge base."""
    gamma = GammaKnowledgeBase(
        principal="user@example.com",
        tenant_id="tenant-123",
        facts=[{"type": "user", "active": True}],
    )
    gamma.compute_gamma_hash()
    return gamma


@pytest.fixture(name="sample_safety_node")
def fixture_sample_safety_node():
    """Create a sample safety node."""
    return SafetyNode(
        node_id="node_abc123",
        endpoint_url="https://node.example.com",
        public_key_pem="-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
        is_local=False,
        trust_score=1.0,
    )


@pytest.mark.asyncio
async def test_transparency_log_append(mock_session, sample_certificate):
    """Test appending entry to transparency log."""
    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = None

    with patch(
        "server.policy_governance.kernel.consensus_verifier.db_execute", return_value=mock_result
    ):
        with patch("server.policy_governance.kernel.consensus_verifier.db_commit"):
            entry = await append_to_transparency_log(
                mock_session,
                sample_certificate,
                alpha_hash="b" * 64,
                gamma_hash="c" * 64,
                node_id="test_node",
            )

            assert isinstance(entry, TransparencyLogEntry)
            assert entry.log_index == 0
            assert entry.decision_id == str(sample_certificate.decision_id)
            assert entry.certificate_hash == sample_certificate.certificate_hash
            assert entry.node_id == "test_node"


@pytest.mark.asyncio
async def test_transparency_log_sequential_index(mock_session, sample_certificate):
    """Test that log indices are sequential when appending multiple entries."""
    mock_last_entry = MagicMock()
    mock_last_entry.log_index = 4

    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = mock_last_entry

    with patch(
        "server.policy_governance.kernel.consensus_verifier.db_execute", return_value=mock_result
    ):
        with patch("server.policy_governance.kernel.consensus_verifier.db_commit"):
            entry = await append_to_transparency_log(
                mock_session,
                sample_certificate,
                alpha_hash="b" * 64,
                gamma_hash="c" * 64,
            )

            assert entry.log_index == 5


@pytest.mark.asyncio
async def test_transparency_log_query_pagination(mock_session):
    """Test get_transparency_log with limit and offset."""
    mock_records = []
    for i in range(3):
        record = MagicMock()
        record.log_index = i
        record.decision_id = f"decision-{i}"
        record.certificate_hash = "a" * 64
        record.alpha_hash = "b" * 64
        record.gamma_hash = "c" * 64
        record.result = "ADMISSIBLE"
        record.node_id = "local"
        record.created_at = datetime.now(timezone.utc)
        mock_records.append(record)

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = mock_records

    with patch(
        "server.policy_governance.kernel.consensus_verifier.db_execute", return_value=mock_result
    ):
        entries = await get_transparency_log(mock_session, limit=10, offset=0)

        assert len(entries) == 3
        assert all(isinstance(e, TransparencyLogEntry) for e in entries)
        assert entries[0].log_index == 0
        assert entries[2].log_index == 2


@pytest.mark.asyncio
async def test_log_verification_valid(mock_session):
    """Test verify_transparency_log returns valid=True for clean log."""
    mock_records = []
    for i in range(5):
        record = MagicMock()
        record.log_index = i
        record.certificate_hash = "a" * 64
        mock_records.append(record)

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = mock_records

    with patch(
        "server.policy_governance.kernel.consensus_verifier.db_execute", return_value=mock_result
    ):
        verification = await verify_transparency_log(mock_session, start_index=0)

        assert verification.valid is True
        assert verification.checked_entries == 5
        assert verification.failure_reason is None


@pytest.mark.asyncio
async def test_log_verification_detects_gap(mock_session):
    """Test that missing index is detected during verification."""
    mock_records = []
    for i in [0, 1, 3, 4]:
        record = MagicMock()
        record.log_index = i
        record.certificate_hash = "a" * 64
        mock_records.append(record)

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = mock_records

    with patch(
        "server.policy_governance.kernel.consensus_verifier.db_execute", return_value=mock_result
    ):
        verification = await verify_transparency_log(mock_session, start_index=0)

        assert verification.valid is False
        assert verification.failure_reason is not None
        assert "gap detected" in verification.failure_reason.lower()
        assert verification.failed_index == 2


@pytest.mark.asyncio
async def test_single_node_mode_no_consensus(mock_session, sample_certificate):
    """Test consensus disabled, only transparency log is active."""
    config = ConsensusConfig(
        enabled=False,
        quorum_threshold=1,
        nodes=[],
    )

    with patch("server.policy_governance.kernel.consensus_verifier.db_commit"):
        result = await collect_quorum(
            mock_session,
            sample_certificate,
            AlphaContext.from_runtime(
                principal="user@test.com",
                action="read",
                resource="doc://1",
            ),
            GammaKnowledgeBase(principal="user@test.com"),
            config,
        )

        assert result.quorum_reached is True
        assert result.signatures_collected == 0
        assert result.global_revocation is False


@pytest.mark.asyncio
async def test_consensus_config_from_env():
    """Test _load_consensus_config reads environment variables."""
    with patch.dict(
        "os.environ",
        {
            "AGENTGATE_CONSENSUS_ENABLED": "true",
            "AGENTGATE_CONSENSUS_QUORUM": "3",
            "AGENTGATE_CONSENSUS_TIMEOUT_MS": "10000",
        },
    ):
        setattr(consensus_verifier, "_CONSENSUS_CONFIG_CACHE", None)

        config = _load_consensus_config()

        assert config.enabled is True
        assert config.quorum_threshold == 3
        assert config.verification_timeout_ms == 10000


@pytest.mark.asyncio
async def test_consensus_config_defaults():
    """Test default config has enabled=False, quorum=1."""
    env_overrides = {k: "" for k in list(os.environ) if k.startswith("AGENTGATE_CONSENSUS_")}
    with patch.dict("os.environ", env_overrides):
        setattr(consensus_verifier, "_CONSENSUS_CONFIG_CACHE", None)

        config = _load_consensus_config()

        assert config.enabled is False
        assert config.quorum_threshold == 1
        assert config.verification_timeout_ms == 5000


@pytest.mark.asyncio
async def test_co_signature_collection_success(
    sample_safety_node,
    sample_certificate,
    sample_alpha,
    sample_gamma,
):
    """Test successful co-signature collection with mocked httpx."""
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "signature": "node_signature_123",
        "result": "ADMISSIBLE",
    }
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    mock_client.post.return_value = mock_response

    with patch("httpx.AsyncClient", return_value=mock_client):
        signature = await request_co_signature(
            sample_safety_node,
            sample_certificate,
            sample_alpha,
            sample_gamma,
            timeout_ms=5000,
        )

        assert signature is not None
        assert isinstance(signature, CoSignature)
        assert signature.node_id == sample_safety_node.node_id
        assert signature.signature == "node_signature_123"
        assert signature.re_evaluation_result == "ADMISSIBLE"


@pytest.mark.asyncio
async def test_co_signature_collection_timeout(
    sample_safety_node,
    sample_certificate,
    sample_alpha,
    sample_gamma,
):
    """Test graceful handling of co-signature timeout."""
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    mock_client.post.side_effect = httpx.TimeoutException("Timeout")

    with patch("httpx.AsyncClient", return_value=mock_client):
        signature = await request_co_signature(
            sample_safety_node,
            sample_certificate,
            sample_alpha,
            sample_gamma,
            timeout_ms=1000,
        )

        assert signature is None


@pytest.mark.asyncio
async def test_quorum_reached(
    mock_session,
    sample_certificate,
    sample_alpha,
    sample_gamma,
    sample_safety_node,
):
    """Test quorum reached when enough signatures collected."""
    config = ConsensusConfig(
        enabled=True,
        quorum_threshold=2,
        nodes=[sample_safety_node, sample_safety_node],
    )

    mock_signature = CoSignature(
        node_id="node_1",
        decision_id=str(sample_certificate.decision_id),
        signature="sig1",
        verified_at=datetime.now(timezone.utc),
        re_evaluation_result="ADMISSIBLE",
    )

    patch_path = "server.policy_governance.kernel.consensus_verifier.request_co_signature"
    with patch(patch_path, return_value=mock_signature):
        with patch("server.policy_governance.kernel.consensus_verifier.db_commit"):
            result = await collect_quorum(
                mock_session,
                sample_certificate,
                sample_alpha,
                sample_gamma,
                config,
            )

            assert result.quorum_reached is True
            assert result.signatures_collected >= config.quorum_threshold


@pytest.mark.asyncio
async def test_quorum_failure(
    mock_session,
    sample_certificate,
    sample_alpha,
    sample_gamma,
    sample_safety_node,
):
    """Test quorum failure when insufficient signatures collected."""
    config = ConsensusConfig(
        enabled=True,
        quorum_threshold=5,
        nodes=[sample_safety_node],
    )

    with patch(
        "server.policy_governance.kernel.consensus_verifier.request_co_signature", return_value=None
    ):
        with patch("server.policy_governance.kernel.consensus_verifier.db_commit"):
            result = await collect_quorum(
                mock_session,
                sample_certificate,
                sample_alpha,
                sample_gamma,
                config,
            )

            assert result.quorum_reached is False
            assert result.signatures_collected < config.quorum_threshold


@pytest.mark.asyncio
async def test_global_revocation_on_inadmissible(
    mock_session,
    sample_certificate,
    sample_alpha,
    sample_gamma,
    sample_safety_node,
):
    """Test global revocation triggered when node returns INADMISSIBLE."""
    config = ConsensusConfig(
        enabled=True,
        quorum_threshold=1,
        nodes=[sample_safety_node],
    )

    mock_signature = CoSignature(
        node_id=sample_safety_node.node_id,
        decision_id=str(sample_certificate.decision_id),
        signature="sig",
        verified_at=datetime.now(timezone.utc),
        re_evaluation_result="INADMISSIBLE",
    )

    patch_path = "server.policy_governance.kernel.consensus_verifier.request_co_signature"
    with patch(patch_path, return_value=mock_signature):
        with patch("server.policy_governance.kernel.consensus_verifier.db_commit"):
            result = await collect_quorum(
                mock_session,
                sample_certificate,
                sample_alpha,
                sample_gamma,
                config,
            )

            assert result.global_revocation is True
            assert result.revocation_reason is not None
            assert "rejected" in result.revocation_reason.lower()


@pytest.mark.asyncio
async def test_global_revocation_persisted(mock_session):
    """Test that revocation record is created in database."""
    config = ConsensusConfig(
        enabled=True,
        quorum_threshold=1,
        nodes=[],
    )

    with patch("server.policy_governance.kernel.consensus_verifier.db_commit"):
        result = await broadcast_global_revocation(
            mock_session,
            "decision-123",
            "Node disagreement detected",
            config,
        )

        assert result["decision_id"] == "decision-123"
        assert result["reason"] == "Node disagreement detected"
        assert "revoked_at" in result
        mock_session.add.assert_called_once()


@pytest.mark.asyncio
async def test_safety_node_registration(mock_session):
    """Test registering a safety node and verifying in list."""
    with patch("server.policy_governance.kernel.consensus_verifier.db_commit"):
        node = await register_safety_node(
            mock_session,
            endpoint_url="https://node.example.com",
            public_key_pem="-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
            is_local=False,
        )

        assert isinstance(node, SafetyNode)
        assert node.node_id.startswith("node_")
        assert node.endpoint_url == "https://node.example.com"
        assert node.is_local is False
        assert node.trust_score == 1.0
        mock_session.add.assert_called_once()


@pytest.mark.asyncio
async def test_safety_node_removal(mock_session):
    """Test registering then removing a node, verify it's gone."""
    mock_record = MagicMock()
    mock_record.node_id = "node_xyz"

    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = mock_record

    with patch(
        "server.policy_governance.kernel.consensus_verifier.db_execute", return_value=mock_result
    ):
        with patch("server.policy_governance.kernel.consensus_verifier.db_commit"):
            success = await remove_safety_node(mock_session, "node_xyz")

            assert success is True
            mock_session.delete.assert_called_once_with(mock_record)


@pytest.mark.asyncio
async def test_safety_node_removal_not_found(mock_session):
    """Test removing non-existent node returns False."""
    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = None

    with patch(
        "server.policy_governance.kernel.consensus_verifier.db_execute", return_value=mock_result
    ):
        success = await remove_safety_node(mock_session, "node_nonexistent")

        assert success is False
        mock_session.delete.assert_not_called()


@pytest.mark.asyncio
async def test_consensus_result_structure():
    """Test ConsensusResult has all required fields."""
    result = ConsensusResult(
        decision_id="decision-123",
        quorum_reached=True,
        signatures_collected=3,
        required=2,
        co_signatures=[],
        global_revocation=False,
        revocation_reason=None,
    )

    assert result.decision_id == "decision-123"
    assert result.quorum_reached is True
    assert result.signatures_collected == 3
    assert result.required == 2
    assert isinstance(result.co_signatures, list)
    assert result.global_revocation is False
    assert result.revocation_reason is None


@pytest.mark.asyncio
async def test_transparency_log_entry_structure():
    """Test TransparencyLogEntry has all required fields."""
    entry = TransparencyLogEntry(
        log_index=42,
        decision_id="decision-456",
        certificate_hash="a" * 64,
        alpha_hash="b" * 64,
        gamma_hash="c" * 64,
        result="ADMISSIBLE",
        node_id="local",
        created_at=datetime.now(timezone.utc),
        node_signatures=[],
    )

    assert entry.log_index == 42
    assert entry.decision_id == "decision-456"
    assert len(entry.certificate_hash) == 64
    assert len(entry.alpha_hash) == 64
    assert len(entry.gamma_hash) == 64
    assert entry.result == "ADMISSIBLE"
    assert entry.node_id == "local"
    assert isinstance(entry.created_at, datetime)
    assert isinstance(entry.node_signatures, list)


@pytest.mark.asyncio
async def test_get_safety_nodes(mock_session):
    """Test retrieving all registered safety nodes."""
    mock_records = []
    for i in range(3):
        record = MagicMock()
        record.node_id = f"node_{i}"
        record.endpoint_url = f"https://node{i}.example.com"
        record.public_key_pem = "test_key"
        record.is_local = False
        record.trust_score = 1.0
        record.registered_at = datetime.now(timezone.utc)
        mock_records.append(record)

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = mock_records

    with patch(
        "server.policy_governance.kernel.consensus_verifier.db_execute", return_value=mock_result
    ):
        nodes = await get_safety_nodes(mock_session)

        assert len(nodes) == 3
        assert all(isinstance(n, SafetyNode) for n in nodes)
        assert nodes[0].node_id == "node_0"
        assert nodes[2].node_id == "node_2"


@pytest.mark.asyncio
async def test_get_global_revocations(mock_session):
    """Test retrieving global revocation records."""
    mock_records = []
    for i in range(2):
        record = MagicMock()
        record.decision_id = f"decision-{i}"
        record.reason = f"Reason {i}"
        record.revoked_at = datetime.now(timezone.utc)
        record.initiated_by_node_id = "local"
        record.revocation_id = f"rev_{i}"
        record.acknowledged_by = []
        mock_records.append(record)

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = mock_records

    with patch(
        "server.policy_governance.kernel.consensus_verifier.db_execute", return_value=mock_result
    ):
        revocations = await get_global_revocations(mock_session)

        assert len(revocations) == 2
        assert all(isinstance(r, dict) for r in revocations)
        assert revocations[0]["decision_id"] == "decision-0"
        assert "reason" in revocations[0]
        assert "revoked_at" in revocations[0]


@pytest.mark.asyncio
async def test_log_verification_empty_log(mock_session):
    """Test verification of empty log returns valid."""
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []

    with patch(
        "server.policy_governance.kernel.consensus_verifier.db_execute", return_value=mock_result
    ):
        verification = await verify_transparency_log(mock_session)

        assert verification.valid is True
        assert verification.checked_entries == 0


@pytest.mark.asyncio
async def test_log_verification_invalid_hash_length(mock_session):
    """Test verification detects invalid certificate hash length."""
    record = MagicMock()
    record.log_index = 0
    record.certificate_hash = "short"

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [record]

    with patch(
        "server.policy_governance.kernel.consensus_verifier.db_execute", return_value=mock_result
    ):
        verification = await verify_transparency_log(mock_session)

        assert verification.valid is False
        assert "hash length" in verification.failure_reason.lower()


@pytest.mark.asyncio
async def test_broadcast_revocation_notifications(mock_session):
    """Test revocation notifications are sent to all nodes."""
    node1 = SafetyNode(
        node_id="node_1",
        endpoint_url="https://node1.example.com",
        public_key_pem="key1",
        is_local=False,
    )
    node2 = SafetyNode(
        node_id="node_2",
        endpoint_url="https://node2.example.com",
        public_key_pem="key2",
        is_local=False,
    )

    config = ConsensusConfig(
        enabled=True,
        quorum_threshold=1,
        nodes=[node1, node2],
    )

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    mock_client.post = AsyncMock()

    with patch("server.policy_governance.kernel.consensus_verifier.db_commit"):
        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await broadcast_global_revocation(
                mock_session,
                "decision-789",
                "Test revocation",
                config,
            )

            assert result["notified_nodes"] == 2
