"""
Economic incentive layer for the LTP commitment network (Monad L1 fork).

Designed to bootstrap a healthy network from day one and scale with growth.

Three-phase economic model:

  Phase 1 — BOOTSTRAP (epochs 0–BOOTSTRAP_END):
    High inflationary subsidies attract early node operators. Storage rewards
    are multiplied by a tapering bootstrap multiplier (3x → 1x). Minimum
    stake is low to reduce entry barrier.

  Phase 2 — GROWTH (epochs BOOTSTRAP_END–GROWTH_END):
    Subsidies taper to zero. Fee revenue from commitments becomes the primary
    income source. Dynamic pricing adjusts fees based on network utilization.
    Minimum stake increases to ensure skin-in-the-game.

  Phase 3 — MATURITY (epochs > GROWTH_END):
    No subsidies. Pure fee-driven economics. Fee burn mechanism creates
    deflationary pressure on the LTP token. Stake requirements track
    network value to maintain security budget.

Core mechanisms:
  - Epoch-based reward distribution (storage + availability + audit)
  - Bootstrap subsidy with linear taper
  - Storage-weighted staking (rewards ∝ shards_stored × stake)
  - Audit score multiplier (perfect audits earn 1.5x)
  - Dynamic commitment fee pricing (utilization-responsive)
  - Progressive slashing (escalating penalties for repeat offenders)
  - Fee split: operator share + burn + insurance fund
  - Capacity-aware minimum stake scaling

Whitepaper reference: §6 Network Economics
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "EconomicsConfig",
    "EconomicsEngine",
    "EpochSnapshot",
    "NodeEconomics",
    "NetworkPhase",
    "RewardBreakdown",
    "SlashingTier",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WEI_PER_LTP = 10**18  # 1 LTP token = 10^18 wei (same convention as ETH)


# ---------------------------------------------------------------------------
# Network phase
# ---------------------------------------------------------------------------

class NetworkPhase(Enum):
    """Which economic phase the network is in, based on current epoch."""
    BOOTSTRAP = "bootstrap"
    GROWTH = "growth"
    MATURITY = "maturity"


# ---------------------------------------------------------------------------
# Slashing tiers
# ---------------------------------------------------------------------------

class SlashingTier(Enum):
    """Progressive slashing severity."""
    WARNING = "warning"         # First offense: 1% slash
    MINOR = "minor"             # 2nd–3rd offense: 5% slash
    MAJOR = "major"             # 4th–5th offense: 15% slash
    CRITICAL = "critical"       # 6+ offenses: 30% slash + eviction


SLASHING_RATES = {
    SlashingTier.WARNING: 100,    # basis points (1%)
    SlashingTier.MINOR: 500,      # 5%
    SlashingTier.MAJOR: 1500,     # 15%
    SlashingTier.CRITICAL: 3000,  # 30%
}

SLASHING_OFFENSE_THRESHOLDS = [
    (1, SlashingTier.WARNING),
    (2, SlashingTier.MINOR),
    (4, SlashingTier.MAJOR),
    (6, SlashingTier.CRITICAL),
]


def tier_for_offense_count(count: int) -> SlashingTier:
    """Determine slashing tier from cumulative offense count."""
    tier = SlashingTier.WARNING
    for threshold, t in SLASHING_OFFENSE_THRESHOLDS:
        if count >= threshold:
            tier = t
    return tier


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class EconomicsConfig:
    """Tunable parameters for L1 economics."""

    # --- Phase boundaries (epoch numbers) ---
    bootstrap_end_epoch: int = 2_160     # ~90 days at 1-hour epochs
    growth_end_epoch: int = 17_520       # ~2 years at 1-hour epochs
    epoch_seconds: int = 3_600           # 1 hour per epoch

    # --- Bootstrap subsidy ---
    bootstrap_subsidy_per_epoch: int = 500 * WEI_PER_LTP  # 500 LTP/epoch
    bootstrap_multiplier_start: float = 3.0                # 3x rewards at genesis
    bootstrap_multiplier_end: float = 1.0                  # tapers to 1x

    # --- Base rewards per epoch ---
    base_storage_reward_per_shard: int = 10**14   # 0.0001 LTP per shard/epoch
    base_availability_reward: int = 10**15        # 0.001 LTP per epoch if 100% uptime
    audit_bonus_multiplier: float = 1.5           # 1.5x for perfect audit score

    # --- Staking ---
    min_stake_bootstrap: int = 100 * WEI_PER_LTP     # 100 LTP during bootstrap
    min_stake_growth: int = 1_000 * WEI_PER_LTP      # 1,000 LTP during growth
    min_stake_maturity: int = 10_000 * WEI_PER_LTP   # 10,000 LTP at maturity
    max_stake_cap: int = 1_000_000 * WEI_PER_LTP     # cap to prevent centralization

    # --- Fee model ---
    base_commit_fee: int = 10**15          # 0.001 LTP per commitment
    fee_utilization_target: float = 0.5    # target 50% network utilization
    fee_elasticity: float = 2.0            # fee doubles per 2x over target
    max_fee_multiplier: float = 10.0       # fee can't exceed 10x base
    min_fee_multiplier: float = 0.1        # fee floor at 0.1x base

    # --- Fee split (basis points, must sum to 10000) ---
    fee_operator_share_bps: int = 6000     # 60% to node operators
    fee_burn_share_bps: int = 2500         # 25% burned (deflationary)
    fee_insurance_share_bps: int = 1500    # 15% to insurance fund

    # --- Slashing ---
    eviction_offense_threshold: int = 6    # offenses before forced eviction
    cooldown_epochs_per_offense: int = 24  # 24 epochs (1 day) penalty cooldown

    # --- Capacity scaling ---
    target_shards_per_node: int = 10_000   # ideal shard density
    overload_threshold: float = 1.5        # 1.5x target → discourage more shards

    def __post_init__(self) -> None:
        total_bps = (
            self.fee_operator_share_bps
            + self.fee_burn_share_bps
            + self.fee_insurance_share_bps
        )
        if total_bps != 10_000:
            raise ValueError(
                f"Fee split must sum to 10000 bps, got {total_bps}"
            )


# ---------------------------------------------------------------------------
# Per-node economic state
# ---------------------------------------------------------------------------

@dataclass
class NodeEconomics:
    """Tracks a node's economic state across epochs."""
    node_id: str
    stake: int = 0
    total_rewards_earned: int = 0
    total_fees_earned: int = 0
    total_slashed: int = 0
    shards_stored: int = 0
    audit_score: int = 100          # 0–100
    offense_count: int = 0
    epochs_active: int = 0
    last_reward_epoch: int = -1
    cooldown_until_epoch: int = 0   # can't earn rewards until this epoch
    evicted: bool = False

    @property
    def effective_stake(self) -> int:
        """Stake after accounting for audit score degradation."""
        return int(self.stake * (self.audit_score / 100))

    @property
    def slashing_tier(self) -> SlashingTier:
        return tier_for_offense_count(self.offense_count)


# ---------------------------------------------------------------------------
# Reward breakdown (for transparency / dashboards)
# ---------------------------------------------------------------------------

@dataclass
class RewardBreakdown:
    """Itemized reward for a single node in a single epoch."""
    node_id: str
    epoch: int
    storage_reward: int = 0
    availability_reward: int = 0
    audit_bonus: int = 0
    bootstrap_subsidy: int = 0
    fee_share: int = 0
    total: int = 0
    phase: NetworkPhase = NetworkPhase.BOOTSTRAP


# ---------------------------------------------------------------------------
# Epoch snapshot
# ---------------------------------------------------------------------------

@dataclass
class EpochSnapshot:
    """Network-wide economic state at end of an epoch."""
    epoch: int
    phase: NetworkPhase
    active_nodes: int
    total_shards: int
    total_staked: int
    total_rewards_distributed: int
    total_fees_collected: int
    total_fees_burned: int
    total_fees_to_insurance: int
    fee_multiplier: float
    utilization: float
    min_stake_required: int
    rewards: list[RewardBreakdown] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Economics engine
# ---------------------------------------------------------------------------

class EconomicsEngine:
    """
    Computes rewards, fees, and slashing for the LTP commitment network.

    Stateless computation: takes node states + config → produces reward/slash
    amounts. The backend is responsible for applying state changes.

    Usage:
        engine = EconomicsEngine(config)

        # Each epoch:
        snapshot = engine.process_epoch(
            epoch=42,
            nodes=node_economics_list,
            total_commitments_this_epoch=150,
            network_capacity=10000,
        )

        # On audit failure:
        slash_amount, new_tier = engine.compute_slash(node_econ)

        # Dynamic fee:
        fee = engine.compute_commit_fee(utilization=0.7)
    """

    def __init__(self, config: EconomicsConfig | None = None) -> None:
        self.config = config or EconomicsConfig()
        self._total_burned: int = 0
        self._total_insurance: int = 0

    # --- Phase detection ---

    def network_phase(self, epoch: int) -> NetworkPhase:
        """Determine network phase from epoch number."""
        if epoch < self.config.bootstrap_end_epoch:
            return NetworkPhase.BOOTSTRAP
        elif epoch < self.config.growth_end_epoch:
            return NetworkPhase.GROWTH
        return NetworkPhase.MATURITY

    # --- Minimum stake ---

    def min_stake_for_epoch(self, epoch: int) -> int:
        """Minimum stake required to participate, scales with network phase."""
        phase = self.network_phase(epoch)
        if phase == NetworkPhase.BOOTSTRAP:
            return self.config.min_stake_bootstrap
        elif phase == NetworkPhase.GROWTH:
            # Linear ramp from bootstrap to growth min stake
            progress = (epoch - self.config.bootstrap_end_epoch) / max(
                1, self.config.growth_end_epoch - self.config.bootstrap_end_epoch
            )
            low = self.config.min_stake_bootstrap
            high = self.config.min_stake_growth
            return int(low + (high - low) * progress)
        return self.config.min_stake_maturity

    # --- Bootstrap multiplier ---

    def bootstrap_multiplier(self, epoch: int) -> float:
        """Tapering multiplier for bootstrap subsidies. Returns 1.0 after bootstrap."""
        if epoch >= self.config.bootstrap_end_epoch:
            return 1.0
        progress = epoch / max(1, self.config.bootstrap_end_epoch)
        start = self.config.bootstrap_multiplier_start
        end = self.config.bootstrap_multiplier_end
        return start + (end - start) * progress

    # --- Dynamic fee pricing ---

    def compute_commit_fee(self, utilization: float) -> int:
        """
        Compute dynamic commitment fee based on network utilization.

        utilization = commitments_this_epoch / network_capacity

        Fee adjusts exponentially around the target utilization:
          - Below target: fee decreases (attract more usage)
          - Above target: fee increases (prevent congestion)
          - Clamped to [min_fee_multiplier, max_fee_multiplier] × base_fee
        """
        cfg = self.config
        if utilization <= 0:
            return int(cfg.base_commit_fee * cfg.min_fee_multiplier)

        # Exponential adjustment: fee = base × e^(elasticity × (util - target))
        exponent = cfg.fee_elasticity * (utilization - cfg.fee_utilization_target)
        multiplier = math.exp(exponent)
        multiplier = max(cfg.min_fee_multiplier, min(cfg.max_fee_multiplier, multiplier))
        return int(cfg.base_commit_fee * multiplier)

    def split_fee(self, fee: int) -> tuple[int, int, int]:
        """
        Split a commitment fee into (operator_share, burn, insurance).

        Returns three amounts that sum to the original fee.
        """
        cfg = self.config
        operator = fee * cfg.fee_operator_share_bps // 10_000
        burn = fee * cfg.fee_burn_share_bps // 10_000
        insurance = fee - operator - burn  # remainder to insurance (avoids rounding loss)
        return operator, burn, insurance

    # --- Reward computation ---

    def compute_node_reward(
        self,
        node: NodeEconomics,
        epoch: int,
        fee_pool_share: int,
    ) -> RewardBreakdown:
        """
        Compute reward for a single node in a single epoch.

        Components:
          1. Storage reward: proportional to shards stored
          2. Availability reward: base reward for being online
          3. Audit bonus: 1.5x multiplier for perfect audit score (100)
          4. Bootstrap subsidy: share of epoch subsidy (bootstrap phase only)
          5. Fee share: proportional share of operator fee pool

        Nodes in cooldown (from recent slashing) earn zero rewards.
        """
        cfg = self.config
        phase = self.network_phase(epoch)
        breakdown = RewardBreakdown(node_id=node.node_id, epoch=epoch, phase=phase)

        # Cooldown check: slashed nodes can't earn for a period
        if epoch < node.cooldown_until_epoch:
            return breakdown

        # Evicted nodes earn nothing
        if node.evicted:
            return breakdown

        # 1. Storage reward (shards × base rate)
        breakdown.storage_reward = node.shards_stored * cfg.base_storage_reward_per_shard

        # 2. Availability reward (flat rate for active nodes)
        breakdown.availability_reward = cfg.base_availability_reward

        # 3. Audit bonus (perfect score = 1.5x on storage + availability)
        if node.audit_score == 100:
            bonus_base = breakdown.storage_reward + breakdown.availability_reward
            breakdown.audit_bonus = int(bonus_base * (cfg.audit_bonus_multiplier - 1.0))

        # 4. Bootstrap subsidy (tapering, shared equally among active nodes)
        if phase == NetworkPhase.BOOTSTRAP:
            multiplier = self.bootstrap_multiplier(epoch)
            # Subsidy is applied as a multiplier on base rewards
            base = breakdown.storage_reward + breakdown.availability_reward
            breakdown.bootstrap_subsidy = int(base * (multiplier - 1.0))

        # 5. Fee share (proportional to effective stake)
        breakdown.fee_share = fee_pool_share

        breakdown.total = (
            breakdown.storage_reward
            + breakdown.availability_reward
            + breakdown.audit_bonus
            + breakdown.bootstrap_subsidy
            + breakdown.fee_share
        )
        return breakdown

    # --- Slashing ---

    def compute_slash(self, node: NodeEconomics) -> tuple[int, SlashingTier]:
        """
        Compute slash amount for a node based on its offense history.

        Progressive slashing:
          1st offense:  1% of stake (WARNING)
          2nd–3rd:      5% of stake (MINOR)
          4th–5th:      15% of stake (MAJOR)
          6+:           30% of stake + eviction (CRITICAL)

        Returns: (slash_amount_wei, tier)
        """
        tier = tier_for_offense_count(node.offense_count)
        rate_bps = SLASHING_RATES[tier]
        slash_amount = node.stake * rate_bps // 10_000
        return slash_amount, tier

    def should_evict(self, node: NodeEconomics) -> bool:
        """Whether a node should be forcibly evicted based on offense count."""
        return node.offense_count >= self.config.eviction_offense_threshold

    # --- Epoch processing ---

    def process_epoch(
        self,
        epoch: int,
        nodes: list[NodeEconomics],
        total_commitments_this_epoch: int = 0,
        network_capacity: int = 10_000,
    ) -> EpochSnapshot:
        """
        Process end-of-epoch economics for the entire network.

        Steps:
          1. Compute utilization and dynamic fee
          2. Compute total fees collected this epoch
          3. Split fees: operator pool, burn, insurance
          4. Distribute operator pool proportional to effective stake
          5. Compute per-node rewards (storage + availability + audit + subsidy + fees)
          6. Return EpochSnapshot for transparency

        The caller (backend) is responsible for actually applying the rewards
        to node balances.
        """
        phase = self.network_phase(epoch)
        active_nodes = [n for n in nodes if not n.evicted]
        if not active_nodes:
            return EpochSnapshot(
                epoch=epoch,
                phase=phase,
                active_nodes=0,
                total_shards=0,
                total_staked=0,
                total_rewards_distributed=0,
                total_fees_collected=0,
                total_fees_burned=0,
                total_fees_to_insurance=0,
                fee_multiplier=1.0,
                utilization=0.0,
                min_stake_required=self.min_stake_for_epoch(epoch),
            )

        # 1. Utilization and fee
        utilization = total_commitments_this_epoch / max(1, network_capacity)
        commit_fee = self.compute_commit_fee(utilization)
        fee_multiplier = commit_fee / max(1, self.config.base_commit_fee)

        # 2. Total fees
        total_fees = commit_fee * total_commitments_this_epoch

        # 3. Fee split
        operator_pool, burn, insurance = self.split_fee(total_fees)
        self._total_burned += burn
        self._total_insurance += insurance

        # 4. Distribute operator pool proportional to effective stake
        total_effective_stake = sum(n.effective_stake for n in active_nodes)
        fee_shares: dict[str, int] = {}
        if total_effective_stake > 0:
            for n in active_nodes:
                share = operator_pool * n.effective_stake // total_effective_stake
                fee_shares[n.node_id] = share
        else:
            # Equal split if no stake info
            per_node = operator_pool // max(1, len(active_nodes))
            for n in active_nodes:
                fee_shares[n.node_id] = per_node

        # 5. Compute rewards
        rewards = []
        total_distributed = 0
        total_shards = 0
        total_staked = 0

        for n in active_nodes:
            total_shards += n.shards_stored
            total_staked += n.stake
            reward = self.compute_node_reward(
                n, epoch, fee_shares.get(n.node_id, 0)
            )
            rewards.append(reward)
            total_distributed += reward.total

        return EpochSnapshot(
            epoch=epoch,
            phase=phase,
            active_nodes=len(active_nodes),
            total_shards=total_shards,
            total_staked=total_staked,
            total_rewards_distributed=total_distributed,
            total_fees_collected=total_fees,
            total_fees_burned=burn,
            total_fees_to_insurance=insurance,
            fee_multiplier=fee_multiplier,
            utilization=utilization,
            min_stake_required=self.min_stake_for_epoch(epoch),
            rewards=rewards,
        )

    @property
    def total_burned(self) -> int:
        """Cumulative fees burned across all epochs."""
        return self._total_burned

    @property
    def total_insurance(self) -> int:
        """Cumulative insurance fund across all epochs."""
        return self._total_insurance

    # --- Capacity scaling ---

    def is_node_overloaded(self, node: NodeEconomics) -> bool:
        """Whether a node has too many shards relative to target density."""
        threshold = int(
            self.config.target_shards_per_node * self.config.overload_threshold
        )
        return node.shards_stored > threshold

    def recommended_node_count(self, total_shards: int) -> int:
        """Recommended number of nodes for the current shard count."""
        return max(1, math.ceil(total_shards / self.config.target_shards_per_node))
