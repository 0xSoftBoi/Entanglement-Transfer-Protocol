"""
Tests for the LTP economic incentive layer.

Covers:
  - Network phase detection
  - Bootstrap subsidy tapering
  - Dynamic fee pricing
  - Fee split (operator / burn / insurance)
  - Reward computation (storage, availability, audit bonus, subsidy, fees)
  - Progressive slashing tiers
  - Epoch processing end-to-end
  - Minimum stake scaling across phases
  - Capacity scaling recommendations
  - Monad L1 backend integration with economics engine
"""

import pytest

from src.ltp.economics import (
    EconomicsConfig,
    EconomicsEngine,
    EpochSnapshot,
    NetworkPhase,
    NodeEconomics,
    RewardBreakdown,
    SlashingTier,
    SLASHING_RATES,
    WEI_PER_LTP,
    tier_for_offense_count,
)
from src.ltp.backends import BackendConfig, create_backend


# ---------------------------------------------------------------------------
# Network phase detection
# ---------------------------------------------------------------------------

class TestNetworkPhase:
    def test_bootstrap_phase(self):
        engine = EconomicsEngine()
        assert engine.network_phase(0) == NetworkPhase.BOOTSTRAP
        assert engine.network_phase(100) == NetworkPhase.BOOTSTRAP
        assert engine.network_phase(2159) == NetworkPhase.BOOTSTRAP

    def test_growth_phase(self):
        engine = EconomicsEngine()
        assert engine.network_phase(2160) == NetworkPhase.GROWTH
        assert engine.network_phase(10000) == NetworkPhase.GROWTH
        assert engine.network_phase(17519) == NetworkPhase.GROWTH

    def test_maturity_phase(self):
        engine = EconomicsEngine()
        assert engine.network_phase(17520) == NetworkPhase.MATURITY
        assert engine.network_phase(100000) == NetworkPhase.MATURITY

    def test_custom_boundaries(self):
        cfg = EconomicsConfig(bootstrap_end_epoch=10, growth_end_epoch=50)
        engine = EconomicsEngine(cfg)
        assert engine.network_phase(5) == NetworkPhase.BOOTSTRAP
        assert engine.network_phase(10) == NetworkPhase.GROWTH
        assert engine.network_phase(50) == NetworkPhase.MATURITY


# ---------------------------------------------------------------------------
# Bootstrap subsidy multiplier
# ---------------------------------------------------------------------------

class TestBootstrapMultiplier:
    def test_starts_at_3x(self):
        engine = EconomicsEngine()
        # Epoch 0 → multiplier should be 3.0
        assert engine.bootstrap_multiplier(0) == 3.0

    def test_tapers_to_1x(self):
        engine = EconomicsEngine()
        # At bootstrap end → multiplier should be 1.0
        assert engine.bootstrap_multiplier(2160) == 1.0

    def test_midpoint_is_between(self):
        engine = EconomicsEngine()
        mid = engine.bootstrap_multiplier(1080)
        assert 1.0 < mid < 3.0

    def test_after_bootstrap_always_1x(self):
        engine = EconomicsEngine()
        assert engine.bootstrap_multiplier(5000) == 1.0
        assert engine.bootstrap_multiplier(100000) == 1.0

    def test_monotonically_decreasing(self):
        engine = EconomicsEngine()
        prev = engine.bootstrap_multiplier(0)
        for epoch in range(100, 2200, 100):
            curr = engine.bootstrap_multiplier(epoch)
            assert curr <= prev
            prev = curr


# ---------------------------------------------------------------------------
# Dynamic fee pricing
# ---------------------------------------------------------------------------

class TestDynamicFee:
    def test_zero_utilization_gives_min_fee(self):
        engine = EconomicsEngine()
        fee = engine.compute_commit_fee(0.0)
        expected = int(engine.config.base_commit_fee * engine.config.min_fee_multiplier)
        assert fee == expected

    def test_target_utilization_gives_base_fee(self):
        engine = EconomicsEngine()
        fee = engine.compute_commit_fee(0.5)
        # At target, exponent = 0, multiplier = e^0 = 1.0
        assert fee == engine.config.base_commit_fee

    def test_high_utilization_increases_fee(self):
        engine = EconomicsEngine()
        base = engine.compute_commit_fee(0.5)
        high = engine.compute_commit_fee(0.9)
        assert high > base

    def test_low_utilization_decreases_fee(self):
        engine = EconomicsEngine()
        base = engine.compute_commit_fee(0.5)
        low = engine.compute_commit_fee(0.1)
        assert low < base

    def test_fee_clamped_to_max(self):
        engine = EconomicsEngine()
        fee = engine.compute_commit_fee(10.0)  # extreme utilization
        max_fee = int(engine.config.base_commit_fee * engine.config.max_fee_multiplier)
        assert fee == max_fee

    def test_fee_never_negative(self):
        engine = EconomicsEngine()
        fee = engine.compute_commit_fee(-1.0)
        assert fee > 0


# ---------------------------------------------------------------------------
# Fee split
# ---------------------------------------------------------------------------

class TestFeeSplit:
    def test_split_sums_to_total(self):
        engine = EconomicsEngine()
        fee = 1_000_000
        operator, burn, insurance = engine.split_fee(fee)
        assert operator + burn + insurance == fee

    def test_split_ratios(self):
        engine = EconomicsEngine()
        fee = 10_000
        operator, burn, insurance = engine.split_fee(fee)
        assert operator == 6000  # 60%
        assert burn == 2500      # 25%
        assert insurance == 1500  # 15%

    def test_invalid_split_raises(self):
        with pytest.raises(ValueError, match="10000 bps"):
            EconomicsConfig(
                fee_operator_share_bps=5000,
                fee_burn_share_bps=5000,
                fee_insurance_share_bps=5000,  # total = 15000
            )

    def test_zero_fee_split(self):
        engine = EconomicsEngine()
        operator, burn, insurance = engine.split_fee(0)
        assert operator == 0
        assert burn == 0
        assert insurance == 0


# ---------------------------------------------------------------------------
# Minimum stake scaling
# ---------------------------------------------------------------------------

class TestMinStake:
    def test_bootstrap_min_stake(self):
        engine = EconomicsEngine()
        assert engine.min_stake_for_epoch(0) == 100 * WEI_PER_LTP

    def test_growth_ramps_up(self):
        engine = EconomicsEngine()
        start = engine.min_stake_for_epoch(2160)  # growth start
        end = engine.min_stake_for_epoch(17519)    # growth end
        assert start < end
        assert start >= 100 * WEI_PER_LTP
        assert end <= 1000 * WEI_PER_LTP

    def test_maturity_min_stake(self):
        engine = EconomicsEngine()
        assert engine.min_stake_for_epoch(17520) == 10_000 * WEI_PER_LTP


# ---------------------------------------------------------------------------
# Progressive slashing
# ---------------------------------------------------------------------------

class TestSlashing:
    def test_tier_progression(self):
        assert tier_for_offense_count(0) == SlashingTier.WARNING
        assert tier_for_offense_count(1) == SlashingTier.WARNING
        assert tier_for_offense_count(2) == SlashingTier.MINOR
        assert tier_for_offense_count(3) == SlashingTier.MINOR
        assert tier_for_offense_count(4) == SlashingTier.MAJOR
        assert tier_for_offense_count(5) == SlashingTier.MAJOR
        assert tier_for_offense_count(6) == SlashingTier.CRITICAL
        assert tier_for_offense_count(100) == SlashingTier.CRITICAL

    def test_tier_boundaries_exact(self):
        """Verify exact offense count → tier mapping at boundaries."""
        assert tier_for_offense_count(1) == SlashingTier.WARNING   # 1st offense
        assert tier_for_offense_count(2) == SlashingTier.MINOR     # 2nd offense
        assert tier_for_offense_count(4) == SlashingTier.MAJOR     # 4th offense
        assert tier_for_offense_count(6) == SlashingTier.CRITICAL  # 6th offense

    def test_slash_amounts_escalate(self):
        engine = EconomicsEngine()
        stake = 10_000 * WEI_PER_LTP

        # 1st offense
        node = NodeEconomics(node_id="n", stake=stake, offense_count=1)
        amt1, _ = engine.compute_slash(node)

        # 3rd offense
        node.offense_count = 3
        amt3, _ = engine.compute_slash(node)

        # 6th offense
        node.offense_count = 6
        amt6, _ = engine.compute_slash(node)

        assert amt1 < amt3 < amt6

    def test_warning_is_1_percent(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", stake=10_000, offense_count=1)
        amt, tier = engine.compute_slash(node)
        assert tier == SlashingTier.WARNING
        assert amt == 100  # 1% of 10000

    def test_critical_is_30_percent(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", stake=10_000, offense_count=6)
        amt, tier = engine.compute_slash(node)
        assert tier == SlashingTier.CRITICAL
        assert amt == 3000  # 30% of 10000

    def test_should_evict_at_threshold(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", offense_count=5)
        assert not engine.should_evict(node)
        node.offense_count = 6
        assert engine.should_evict(node)


# ---------------------------------------------------------------------------
# Reward computation
# ---------------------------------------------------------------------------

class TestRewardComputation:
    def test_basic_storage_reward(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n1", stake=1000 * WEI_PER_LTP, shards_stored=100)
        reward = engine.compute_node_reward(node, epoch=0, fee_pool_share=0)
        assert reward.storage_reward == 100 * engine.config.base_storage_reward_per_shard
        assert reward.storage_reward > 0

    def test_availability_reward(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n1", stake=1000 * WEI_PER_LTP, shards_stored=0)
        reward = engine.compute_node_reward(node, epoch=0, fee_pool_share=0)
        assert reward.availability_reward == engine.config.base_availability_reward

    def test_audit_bonus_for_perfect_score(self):
        engine = EconomicsEngine()
        node = NodeEconomics(
            node_id="n1", stake=1000 * WEI_PER_LTP,
            shards_stored=100, audit_score=100,
        )
        reward = engine.compute_node_reward(node, epoch=0, fee_pool_share=0)
        assert reward.audit_bonus > 0

    def test_no_audit_bonus_for_imperfect_score(self):
        engine = EconomicsEngine()
        node = NodeEconomics(
            node_id="n1", stake=1000 * WEI_PER_LTP,
            shards_stored=100, audit_score=90,
        )
        reward = engine.compute_node_reward(node, epoch=0, fee_pool_share=0)
        assert reward.audit_bonus == 0

    def test_bootstrap_subsidy_at_epoch_0(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n1", stake=1000 * WEI_PER_LTP, shards_stored=50)
        reward = engine.compute_node_reward(node, epoch=0, fee_pool_share=0)
        assert reward.bootstrap_subsidy > 0
        assert reward.phase == NetworkPhase.BOOTSTRAP

    def test_no_subsidy_after_bootstrap(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n1", stake=1000 * WEI_PER_LTP, shards_stored=50)
        reward = engine.compute_node_reward(node, epoch=3000, fee_pool_share=0)
        assert reward.bootstrap_subsidy == 0

    def test_fee_share_included(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n1", stake=1000 * WEI_PER_LTP, shards_stored=10)
        reward = engine.compute_node_reward(node, epoch=5000, fee_pool_share=50000)
        assert reward.fee_share == 50000
        assert reward.total >= 50000

    def test_cooldown_blocks_rewards(self):
        engine = EconomicsEngine()
        node = NodeEconomics(
            node_id="n1", stake=1000 * WEI_PER_LTP,
            shards_stored=100, cooldown_until_epoch=10,
        )
        reward = engine.compute_node_reward(node, epoch=5, fee_pool_share=10000)
        assert reward.total == 0

    def test_evicted_node_earns_nothing(self):
        engine = EconomicsEngine()
        node = NodeEconomics(
            node_id="n1", stake=1000 * WEI_PER_LTP,
            shards_stored=100, evicted=True,
        )
        reward = engine.compute_node_reward(node, epoch=0, fee_pool_share=10000)
        assert reward.total == 0

    def test_total_equals_sum_of_components(self):
        engine = EconomicsEngine()
        node = NodeEconomics(
            node_id="n1", stake=1000 * WEI_PER_LTP,
            shards_stored=100, audit_score=100,
        )
        r = engine.compute_node_reward(node, epoch=0, fee_pool_share=5000)
        expected = (
            r.storage_reward + r.availability_reward
            + r.audit_bonus + r.bootstrap_subsidy + r.fee_share
        )
        assert r.total == expected


# ---------------------------------------------------------------------------
# Epoch processing
# ---------------------------------------------------------------------------

class TestEpochProcessing:
    def _make_nodes(self, count: int, shards: int = 100) -> list[NodeEconomics]:
        return [
            NodeEconomics(
                node_id=f"node-{i}",
                stake=1000 * WEI_PER_LTP,
                shards_stored=shards,
                audit_score=100,
            )
            for i in range(count)
        ]

    def test_epoch_snapshot_fields(self):
        engine = EconomicsEngine()
        nodes = self._make_nodes(4)
        snap = engine.process_epoch(epoch=0, nodes=nodes, total_commitments_this_epoch=100)
        assert isinstance(snap, EpochSnapshot)
        assert snap.epoch == 0
        assert snap.phase == NetworkPhase.BOOTSTRAP
        assert snap.active_nodes == 4
        assert snap.total_staked > 0

    def test_rewards_distributed_to_all_active_nodes(self):
        engine = EconomicsEngine()
        nodes = self._make_nodes(5)
        snap = engine.process_epoch(epoch=0, nodes=nodes, total_commitments_this_epoch=50)
        assert len(snap.rewards) == 5
        assert all(r.total > 0 for r in snap.rewards)

    def test_evicted_nodes_excluded(self):
        engine = EconomicsEngine()
        nodes = self._make_nodes(3)
        nodes[2].evicted = True
        snap = engine.process_epoch(epoch=0, nodes=nodes, total_commitments_this_epoch=10)
        assert snap.active_nodes == 2
        assert len(snap.rewards) == 2

    def test_fees_burned_and_insured(self):
        engine = EconomicsEngine()
        nodes = self._make_nodes(3)
        snap = engine.process_epoch(
            epoch=5000, nodes=nodes,
            total_commitments_this_epoch=500,
            network_capacity=10000,
        )
        assert snap.total_fees_collected > 0
        assert snap.total_fees_burned > 0
        assert snap.total_fees_to_insurance > 0

    def test_cumulative_burn_tracking(self):
        engine = EconomicsEngine()
        nodes = self._make_nodes(3)
        engine.process_epoch(epoch=0, nodes=nodes, total_commitments_this_epoch=100)
        burn1 = engine.total_burned
        engine.process_epoch(epoch=1, nodes=nodes, total_commitments_this_epoch=100)
        burn2 = engine.total_burned
        assert burn2 > burn1

    def test_empty_network_returns_snapshot(self):
        engine = EconomicsEngine()
        snap = engine.process_epoch(epoch=0, nodes=[], total_commitments_this_epoch=0)
        assert snap.active_nodes == 0
        assert snap.total_rewards_distributed == 0

    def test_high_utilization_increases_fees(self):
        engine = EconomicsEngine()
        nodes = self._make_nodes(3)
        snap_low = engine.process_epoch(
            epoch=0, nodes=nodes,
            total_commitments_this_epoch=10,
            network_capacity=10000,
        )
        snap_high = engine.process_epoch(
            epoch=1, nodes=nodes,
            total_commitments_this_epoch=9000,
            network_capacity=10000,
        )
        assert snap_high.fee_multiplier > snap_low.fee_multiplier

    def test_fee_share_proportional_to_effective_stake(self):
        engine = EconomicsEngine()
        nodes = [
            NodeEconomics(node_id="big", stake=9000 * WEI_PER_LTP, shards_stored=100),
            NodeEconomics(node_id="small", stake=1000 * WEI_PER_LTP, shards_stored=100),
        ]
        snap = engine.process_epoch(
            epoch=5000, nodes=nodes,
            total_commitments_this_epoch=1000,
            network_capacity=10000,
        )
        big_reward = next(r for r in snap.rewards if r.node_id == "big")
        small_reward = next(r for r in snap.rewards if r.node_id == "small")
        # Big staker should get more fee share
        assert big_reward.fee_share > small_reward.fee_share


# ---------------------------------------------------------------------------
# Capacity scaling
# ---------------------------------------------------------------------------

class TestCapacityScaling:
    def test_overloaded_node(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", shards_stored=20000)
        assert engine.is_node_overloaded(node)

    def test_not_overloaded_node(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", shards_stored=5000)
        assert not engine.is_node_overloaded(node)

    def test_recommended_node_count(self):
        engine = EconomicsEngine()
        assert engine.recommended_node_count(0) == 1
        assert engine.recommended_node_count(10000) == 1
        assert engine.recommended_node_count(10001) == 2
        assert engine.recommended_node_count(100000) == 10


# ---------------------------------------------------------------------------
# NodeEconomics properties
# ---------------------------------------------------------------------------

class TestNodeEconomics:
    def test_effective_stake_with_perfect_score(self):
        node = NodeEconomics(node_id="n", stake=10000, audit_score=100)
        assert node.effective_stake == 10000

    def test_effective_stake_degraded(self):
        node = NodeEconomics(node_id="n", stake=10000, audit_score=50)
        assert node.effective_stake == 5000

    def test_slashing_tier_property(self):
        node = NodeEconomics(node_id="n", offense_count=0)
        assert node.slashing_tier == SlashingTier.WARNING
        node.offense_count = 6
        assert node.slashing_tier == SlashingTier.CRITICAL


# ---------------------------------------------------------------------------
# Monad L1 backend integration
# ---------------------------------------------------------------------------

class TestMonadEconomicsIntegration:
    def _create_backend(self):
        return create_backend(BackendConfig(
            backend_type="monad-l1",
            enable_economics_engine=True,
            min_stake_wei=100 * WEI_PER_LTP,
        ))

    def test_economics_engine_initialized(self):
        backend = self._create_backend()
        assert backend.economics_engine is not None

    def test_register_node_creates_economics_entry(self):
        backend = self._create_backend()
        backend.register_node("node-0", "US-East", stake_wei=200 * WEI_PER_LTP)
        assert "node-0" in backend.node_economics
        assert backend.node_economics["node-0"].stake == 200 * WEI_PER_LTP

    def test_register_node_respects_dynamic_min_stake(self):
        backend = self._create_backend()
        # During bootstrap, min stake is 100 LTP
        result = backend.register_node("node-0", "US-East", stake_wei=50 * WEI_PER_LTP)
        assert result is False  # below min stake

    def test_pricing_includes_dynamic_fields(self):
        backend = self._create_backend()
        backend.register_node("node-0", "US-East", stake_wei=200 * WEI_PER_LTP)
        pricing = backend.get_pricing()
        assert "dynamic_commit_fee" in pricing
        assert "network_phase" in pricing
        assert pricing["network_phase"] == "bootstrap"
        assert "min_stake_required" in pricing
        assert "bootstrap_multiplier" in pricing

    def test_process_epoch_distributes_rewards(self):
        backend = self._create_backend()
        backend.register_node("node-0", "US-East", stake_wei=500 * WEI_PER_LTP)
        backend.register_node("node-1", "US-West", stake_wei=500 * WEI_PER_LTP)

        # Update shard counts
        backend.update_node_shards("node-0", 50)
        backend.update_node_shards("node-1", 50)

        initial_stake_0 = backend.node_economics["node-0"].stake

        snap = backend.process_epoch(epoch=0, commitments_this_epoch=100)
        assert snap is not None
        assert snap["phase"] == "bootstrap"
        assert snap["active_nodes"] == 2
        assert snap["total_rewards_distributed"] > 0

        # Rewards should have been auto-compounded into stake
        assert backend.node_economics["node-0"].stake > initial_stake_0

    def test_slash_uses_progressive_tiers(self):
        backend = self._create_backend()
        initial_stake = 1000 * WEI_PER_LTP
        backend.register_node("node-0", "US-East", stake_wei=initial_stake)

        # First slash: WARNING (1%)
        amt1 = backend.slash_node("node-0", b"evidence-1")
        assert amt1 == initial_stake * 100 // 10_000  # 1% of 1000 LTP

        # Verify offense count incremented and tier escalated
        node_econ = backend.node_economics["node-0"]
        assert node_econ.offense_count == 1
        # After 1st offense, next will be offense_count=2 → MINOR tier

        # Second slash: MINOR (5% of reduced stake)
        remaining_stake = node_econ.stake
        amt2 = backend.slash_node("node-0", b"evidence-2")
        expected_amt2 = remaining_stake * 500 // 10_000  # 5%
        assert amt2 == expected_amt2
        assert node_econ.offense_count == 2

    def test_slash_auto_evicts_at_critical(self):
        backend = self._create_backend()
        backend.register_node("node-0", "US-East", stake_wei=10000 * WEI_PER_LTP)

        # Slash 6 times to reach CRITICAL
        for i in range(6):
            backend.slash_node("node-0", f"evidence-{i}".encode())

        assert backend.node_economics["node-0"].evicted is True

    def test_process_epoch_returns_none_without_engine(self):
        backend = create_backend(BackendConfig(
            backend_type="monad-l1",
            enable_economics_engine=False,
        ))
        assert backend.process_epoch(epoch=0) is None

    def test_epoch_commitment_counter_resets(self):
        backend = self._create_backend()
        backend.register_node("node-0", "US-East", stake_wei=500 * WEI_PER_LTP)

        from src.ltp.primitives import H
        eid = H(b"test-entity-1")
        backend.append_commitment(
            eid, b'{"test":true}', b"\x00" * 64, b"\x01" * 32
        )
        assert backend._epoch_commitment_count == 1

        backend.process_epoch(epoch=0)
        assert backend._epoch_commitment_count == 0

    def test_multiple_epochs_accumulate_snapshots(self):
        backend = self._create_backend()
        backend.register_node("node-0", "US-East", stake_wei=500 * WEI_PER_LTP)
        backend.update_node_shards("node-0", 10)

        for i in range(5):
            backend.process_epoch(epoch=i, commitments_this_epoch=50)

        assert len(backend.epoch_snapshots) == 5
        # Each epoch should have distributing rewards
        assert all(s["total_rewards_distributed"] > 0 for s in backend.epoch_snapshots)
