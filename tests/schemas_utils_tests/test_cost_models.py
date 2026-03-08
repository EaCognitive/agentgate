"""Tests for Cost models."""

from server.models.schemas import BlockBreakdown, CostBreakdown, OverviewStats


class TestCostModels:
    """Test Cost-related model classes."""

    def test_overview_stats(self):
        """Test OverviewStats model."""
        stats = OverviewStats(
            total_calls=100,
            success_count=90,
            blocked_count=5,
            failed_count=5,
            success_rate=0.9,
            total_cost=10.50,
            budget_limit=100.0,
            pending_approvals=3,
        )

        assert stats.total_calls == 100
        assert stats.success_rate == 0.9
        assert stats.budget_limit == 100.0

    def test_cost_breakdown(self):
        """Test CostBreakdown model."""
        breakdown = CostBreakdown(tool="openai_chat", total_cost=5.25, call_count=50)

        assert breakdown.tool == "openai_chat"
        assert breakdown.total_cost == 5.25
        assert breakdown.call_count == 50

    def test_block_breakdown(self):
        """Test BlockBreakdown model."""
        breakdown = BlockBreakdown(middleware="rate_limit", count=10)

        assert breakdown.middleware == "rate_limit"
        assert breakdown.count == 10
