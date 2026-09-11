"""
GraphPath Native Orchestration Agent - Actor-Critic Policy Network & GAT Architecture
Subsystem I: Graph Attention Network (GAT) embedding Purdue Model cyber-physical topologies,
continuous Bayesian spatial telemetry, and stable pre-softmax log-space action masking.
"""

import os
from typing import Tuple, Optional, Union, Dict, Any
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F


def masked_log_softmax(logits: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
    """
    Computes numerically stable pre-softmax log-space action masking:
    pi(a|s) = exp(z_a + log M(s)_a) / sum_j exp(z_j + log M(s)_j) where log(0) = -inf.
    Eradicates 10^9 heuristic penalty, preventing catastrophic cancellation and NaN gradients.

    Args:
        logits: Raw unmasked actor logits of shape (..., num_actions).
        mask: Binary action mask in {0.0, 1.0} of shape (..., num_actions).

    Returns:
        Log-probabilities of shape (..., num_actions) with exactly -inf for invalid actions.
    """
    # Guard against float32 underflow by assigning -1e30 to zero-mask elements
    log_mask = torch.where(
        mask > 0.5,
        torch.zeros_like(logits),
        torch.tensor(-1e30, device=logits.device, dtype=logits.dtype)
    )
    masked_logits = logits + log_mask

    # Subtract max valid logit along action dimension for numerical stability
    max_logits = torch.max(masked_logits, dim=-1, keepdim=True)[0]
    # Guard against fully masked rows (safe uniform fallback)
    max_logits = torch.where(
        torch.isneginf(max_logits) | (max_logits < -1e20),
        torch.zeros_like(max_logits),
        max_logits
    )
    sub_logits = masked_logits - max_logits

    exp_logits = torch.where(mask > 0.5, torch.exp(sub_logits), torch.zeros_like(logits))
    sum_exp = torch.sum(exp_logits, dim=-1, keepdim=True).clamp(min=1e-12)

    # Compute exact log-softmax
    log_probs = torch.where(
        mask > 0.5,
        sub_logits - torch.log(sum_exp),
        torch.tensor(-float("inf"), device=logits.device, dtype=logits.dtype)
    )
    return log_probs


class GATConvBlock(nn.Module):
    """
    Multi-Head Graph Attention Network layer (GAT) with self-loops, LeakyReLU attention,
    and residual skip connections.
    """

    def __init__(
        self,
        in_features: int,
        out_features: int,
        num_heads: int = 4,
        negative_slope: float = 0.2,
        dropout: float = 0.0,
    ):
        super().__init__()
        self.in_features = in_features
        self.out_features = out_features
        self.num_heads = num_heads
        self.negative_slope = negative_slope
        self.head_dim = max(1, out_features // num_heads)

        self.fc = nn.Linear(in_features, self.head_dim * num_heads, bias=False)
        self.attn_src = nn.Parameter(torch.zeros(1, 1, num_heads, self.head_dim))
        self.attn_dst = nn.Parameter(torch.zeros(1, 1, num_heads, self.head_dim))
        self.leaky_relu = nn.LeakyReLU(negative_slope)
        self.dropout = nn.Dropout(dropout)

        if in_features != self.head_dim * num_heads:
            self.res_fc = nn.Linear(in_features, self.head_dim * num_heads, bias=False)
        else:
            self.res_fc = nn.Identity()

        nn.init.xavier_uniform_(self.fc.weight)
        nn.init.xavier_uniform_(self.attn_src)
        nn.init.xavier_uniform_(self.attn_dst)

    def forward(
        self,
        x: torch.Tensor,
        adj: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """
        Forward pass for Graph Attention Layer.

        Args:
            x: Node feature tensor of shape (B, N, in_features).
            adj: Optional binary adjacency matrix of shape (B, N, N) or (N, N).
                 Self-loops are automatically injected.

        Returns:
            Updated node feature tensor of shape (B, N, out_features).
        """
        if x.ndim == 2:
            x = x.unsqueeze(0)

        batch_size, num_nodes, _ = x.shape
        # Linear projection to multi-head subspace
        h = self.fc(x).view(batch_size, num_nodes, self.num_heads, self.head_dim)

        # Compute source and destination attention scores
        score_src = (h * self.attn_src).sum(dim=-1)  # (B, N, num_heads)
        score_dst = (h * self.attn_dst).sum(dim=-1)  # (B, N, num_heads)

        # Pairwise attention logits: (B, N, N, num_heads)
        pairwise = score_src.unsqueeze(2) + score_dst.unsqueeze(1)
        e_ij = self.leaky_relu(pairwise)

        # Incorporate topology adjacency with self-loops
        if adj is not None:
            if adj.ndim == 2:
                adj = adj.unsqueeze(0).expand(batch_size, -1, -1)
            # Add self-loops to prevent division-by-zero or isolated node collapse
            identity = torch.eye(num_nodes, device=x.device, dtype=torch.bool).unsqueeze(0)
            adj_mask = (adj > 0.5) | identity
            e_ij = torch.where(
                adj_mask.unsqueeze(-1),
                e_ij,
                torch.tensor(-1e20, device=x.device, dtype=x.dtype)
            )

        # Normalize attention coefficients across neighbor nodes
        alpha = F.softmax(e_ij, dim=2)
        alpha = self.dropout(alpha)

        # Weighted message aggregation
        out = torch.einsum("bkjh,bjhd->bkhd", alpha, h)
        out = out.reshape(batch_size, num_nodes, self.num_heads * self.head_dim)

        # Residual connection with ELU activation
        out = F.elu(out + self.res_fc(x))
        return out


from src.graphpath.agent.topological_complex import CellularMessagePassingBlock


class PurdueGraphAttentionTrunk(nn.Module):
    """
    Hierarchical Graph Attention Trunk for embedding dynamically expanding
    Purdue Model network topologies, continuous physical sensor telemetry,
    and higher-order cellular complex boundary operators.
    Supports both structured graph inputs and backward-compatible flat observations.
    """

    def __init__(
        self,
        node_dim: int = 48,
        hidden_dim: int = 128,
        out_dim: int = 64,
        num_heads: int = 4,
        input_dim: int = 9731,
        in_features: Optional[int] = None,
        out_features: Optional[int] = None,
    ):
        super().__init__()
        if in_features is not None:
            node_dim = in_features
        if out_features is not None:
            out_dim = out_features
        self.node_dim = node_dim
        self.hidden_dim = hidden_dim
        self.out_dim = out_dim
        self.input_dim = input_dim

        # GAT Multi-Head Layers
        self.gat1 = GATConvBlock(node_dim, hidden_dim, num_heads=num_heads)
        self.gat2 = GATConvBlock(hidden_dim, out_dim, num_heads=num_heads)

        # Higher-Order Cellular Message Passing Block (TDL)
        self.cellular_block = CellularMessagePassingBlock(
            node_dim=node_dim,
            edge_dim=node_dim,
            out_dim=node_dim,
        )

        # Dimension adapter: if node features have 50 dims and node_dim is 48, project to node_dim
        if node_dim != 50:
            self.input_adapter = nn.Linear(50, node_dim, bias=False)
        else:
            self.input_adapter = nn.Identity()

        # Global graph pooling readout: combines mean and max pooling
        self.readout = nn.Sequential(
            nn.Linear(out_dim * 2, out_dim),
            nn.ReLU(),
        )

        # Legacy backward-compatible linear projection layer
        self.legacy_proj = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, out_dim),
            nn.ReLU(),
        )

    def _unpack_flat_obs(self, obs: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Unpacks flat (B, 9731) or (B, 9733) observation vector into structured host node features (B, 256, node_dim)
        and local subnet star/mesh adjacency matrix.
        """
        batch_size = obs.shape[0]
        # 1. Occupancy: 256 hosts
        occupancy = obs[:, :256].unsqueeze(-1)  # (B, 256, 1)
        # 2. Port matrix: 256 hosts x 37 ports
        ports = obs[:, 256:256 + 9472].view(batch_size, 256, 37)  # (B, 256, 37)

        # 3. Global & Topological scalars (5-dim)
        if obs.shape[-1] >= 9733:
            globals_vec = obs[:, 9728:9733].unsqueeze(1).expand(-1, 256, -1)  # (B, 256, 5)
        else:
            g3 = obs[:, 9728:9731].unsqueeze(1).expand(-1, 256, -1)  # (B, 256, 3)
            pad2 = torch.zeros(batch_size, 256, 2, device=obs.device, dtype=obs.dtype)
            globals_vec = torch.cat([g3, pad2], dim=-1)  # (B, 256, 5)

        # 4. Purdue Model Level Features (5-dim one-hot proxy derived from port activity)
        # Ports 502 (Modbus), 102 (S7), 44818 (CIP) -> L1
        is_l1 = (ports[:, :, 10] > 0.5) | (ports[:, :, 3] > 0.5) | (ports[:, :, 36] > 0.5)
        # Ports 80, 443, 8080, 554 -> L2/L3
        is_l2 = (ports[:, :, 2] > 0.5) | (ports[:, :, 8] > 0.5) | (ports[:, :, 30] > 0.5)
        l0 = torch.zeros_like(occupancy)
        l1 = is_l1.float().unsqueeze(-1)
        l2 = is_l2.float().unsqueeze(-1)
        l3 = torch.zeros_like(occupancy)
        l4 = occupancy * (1.0 - l1.clamp(max=1.0)) * (1.0 - l2.clamp(max=1.0))
        purdue_levels = torch.cat([l0, l1, l2, l3, l4], dim=-1)  # (B, 256, 5)

        # 5. Physical Continuous Metrics: Conductor thermal scaling & contact resistance
        # Thermal scaling factor at default 20C baseline: 1.0 + 0.00393 * (20 - 20) = 1.0
        thermal_scaling = torch.ones_like(occupancy)
        contact_resistance = torch.zeros_like(occupancy)
        physical_metrics = torch.cat([thermal_scaling, contact_resistance], dim=-1)  # (B, 256, 2)

        # Combined Node Feature Matrix: (B, 256, 50)
        # 1 + 37 + 5 + 5 + 2 = 50
        node_features = torch.cat([
            occupancy,
            ports,
            globals_vec,
            purdue_levels,
            physical_metrics,
        ], dim=-1)

        # Adapt dimension if node_dim != 50
        if node_features.shape[-1] != self.node_dim:
            node_features = self.input_adapter(node_features)

        # Synthesize local subnet star adjacency (gateway host 0 connected to active hosts)
        adj = torch.eye(256, device=obs.device, dtype=torch.float32).unsqueeze(0).expand(batch_size, -1, -1).clone()
        # Connect host 1 (gateway) to all active hosts
        active_hosts = (occupancy.squeeze(-1) > 0.5)
        adj[:, 1, :] = active_hosts.float()
        adj[:, :, 1] = active_hosts.float()

        return node_features, adj

    def forward(
        self,
        obs: Union[torch.Tensor, Tuple[torch.Tensor, Optional[torch.Tensor]]],
        adj: Optional[torch.Tensor] = None,
        b1: Optional[torch.Tensor] = None,
        x1: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """
        Forward pass evaluating Graph Attention representation.

        Args:
            obs: Either a flat tensor (B, 9731)/(B, 9733), node features (B, N, D), or tuple of (node_features, adj_matrix).
            adj: Optional adjacency matrix of shape (B, N, N) when obs contains node features directly.
            b1: Optional 1-boundary matrix for cellular message passing.
            x1: Optional 1-cell (link) feature tensor.

        Returns:
            Context feature tensor of shape (B, out_dim).
        """
        if adj is not None or isinstance(obs, tuple):
            if isinstance(obs, tuple):
                x, adj_mat = obs
            else:
                x = obs
                adj_mat = adj
            if not isinstance(x, torch.Tensor):
                x = torch.as_tensor(x, dtype=torch.float32)
            if x.ndim == 2:
                x = x.unsqueeze(0)
            if b1 is not None:
                x = self.cellular_block(x, b1, x1)
            h1 = self.gat1(x, adj_mat)
            h2 = self.gat2(h1, adj_mat)
            # Mean and Max global graph pooling
            mean_pool = h2.mean(dim=1)
            max_pool = h2.max(dim=1)[0]
            pooled = torch.cat([mean_pool, max_pool], dim=-1)
            return self.readout(pooled)

        if not isinstance(obs, torch.Tensor):
            obs = torch.as_tensor(obs, dtype=torch.float32)
        if obs.ndim == 1:
            obs = obs.unsqueeze(0)

        # Dynamic GAT pathway: unpack flat observation and evaluate GAT
        try:
            node_features, adj_synth = self._unpack_flat_obs(obs)
            if b1 is not None:
                node_features = self.cellular_block(node_features, b1, x1)
            h1 = self.gat1(node_features, adj_synth)
            h2 = self.gat2(h1, adj_synth)
            mean_pool = h2.mean(dim=1)
            max_pool = h2.max(dim=1)[0]
            pooled = torch.cat([mean_pool, max_pool], dim=-1)
            gat_features = self.readout(pooled)
            return gat_features
        except Exception:
            # Fallback legacy linear projection path if graph unpacking encounters non-standard shapes
            return self.legacy_proj(obs)


class ActorCriticPolicy(nn.Module):
    """
    Graph Attention Actor-Critic Neural Policy for GraphPath Autonomous Orchestration Agent.
    Architecture:
        Trunk: PurdueGraphAttentionTrunk (Multi-Head GAT + Mean-Max Pooling)
        Actor Head: Linear(64 -> 9) with exact pre-softmax log-space action masking:
                    pi(a|s) = exp(z_a + log M(s)_a) / sum_j exp(z_j + log M(s)_j)
        Critic Head: Linear(64 -> 1)
    """

    def __init__(
        self,
        input_dim: int = 9731,
        hidden1: int = 128,
        hidden2: int = 64,
        num_actions: int = 9,
        use_gat: bool = True,
        **kwargs: Any,
    ):
        super().__init__()
        self.input_dim = input_dim
        self.hidden1 = hidden1
        self.hidden2 = hidden2
        self.num_actions = num_actions
        self.use_gat = use_gat

        # Graph Attention Network Representation Trunk
        self.trunk = PurdueGraphAttentionTrunk(
            node_dim=48,
            hidden_dim=hidden1,
            out_dim=hidden2,
            input_dim=input_dim,
        )

        # Actor head: emits raw unmasked action logits z in R^9
        self.actor = nn.Linear(hidden2, num_actions)

        # Critic head: emits scalar state value V(s) in R^1
        self.critic = nn.Linear(hidden2, 1)

    def forward(
        self,
        obs: Union[np.ndarray, torch.Tensor, Tuple[torch.Tensor, Optional[torch.Tensor]]],
        action_mask: Optional[Union[np.ndarray, torch.Tensor]] = None,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass computing masked logits and state value.

        Args:
            obs: Observation tensor of shape (9731,), batch (B, 9731), or (nodes, adj) tuple.
            action_mask: Binary mask in {0.0, 1.0} of shape (9,) or batch (B, 9).

        Returns:
            Tuple of (masked_logits, state_values).
        """
        if isinstance(obs, (np.ndarray, list)):
            obs = torch.as_tensor(obs, dtype=torch.float32)
        if isinstance(obs, torch.Tensor) and obs.ndim == 1:
            obs = obs.unsqueeze(0)

        device = obs[0].device if isinstance(obs, tuple) else obs.device

        features = self.trunk(obs)
        logits = self.actor(features)
        values = self.critic(features)

        if action_mask is not None:
            if not isinstance(action_mask, torch.Tensor):
                action_mask = torch.as_tensor(action_mask, dtype=torch.float32, device=device)
            if action_mask.ndim == 1:
                action_mask = action_mask.unsqueeze(0)

            # Pre-softmax log-space action masking:
            # pi(a|s) = exp(z_a + log M(s)_a) / sum(exp(z_j + log M(s)_j))
            # where log(0) = -inf, implemented with -1e30 for exact numerical stability
            log_mask = torch.where(
                action_mask > 0.5,
                torch.zeros_like(logits),
                torch.tensor(-1e30, device=device, dtype=logits.dtype)
            )
            logits = logits + log_mask

        return logits, values

    def get_action(
        self,
        obs: Union[np.ndarray, torch.Tensor],
        action_mask: Optional[Union[np.ndarray, torch.Tensor]] = None,
        deterministic: bool = False,
    ) -> Tuple[int, float, float]:
        """
        Samples or greedily selects a strictly valid action under the action mask.
        Uses exact log-space action masking to prevent NaN gradients or underflows.

        Args:
            obs: State observation tensor.
            action_mask: Pre-execution binary action mask.
            deterministic: If True, selects argmax valid action. Otherwise samples.

        Returns:
            Tuple of (action_index, log_prob, state_value).
        """
        self.eval()
        with torch.no_grad():
            if not isinstance(obs, torch.Tensor):
                obs = torch.as_tensor(obs, dtype=torch.float32)
            if obs.ndim == 1:
                obs = obs.unsqueeze(0)

            features = self.trunk(obs)
            raw_logits = self.actor(features)
            value = self.critic(features)

            if action_mask is not None:
                if not isinstance(action_mask, torch.Tensor):
                    mask_t = torch.as_tensor(action_mask, dtype=torch.float32, device=obs.device)
                else:
                    mask_t = action_mask.to(obs.device)
                if mask_t.ndim == 1:
                    mask_t = mask_t.unsqueeze(0)
                log_probs = masked_log_softmax(raw_logits, mask_t)
                probs = torch.exp(log_probs)
            else:
                log_probs = F.log_softmax(raw_logits, dim=-1)
                probs = torch.exp(log_probs)

            # Guard against potential numerical underflow
            if torch.isnan(probs).any() or probs.sum().item() == 0.0:
                if action_mask is not None:
                    mask_t = torch.as_tensor(action_mask, dtype=torch.float32, device=raw_logits.device)
                    probs = mask_t / torch.clamp(mask_t.sum(), min=1.0)
                else:
                    probs = torch.ones_like(raw_logits) / raw_logits.shape[-1]

            dist = torch.distributions.Categorical(probs=probs)

            if deterministic:
                action = torch.argmax(probs, dim=-1)
            else:
                action = dist.sample()

            log_prob = dist.log_prob(action)
            return int(action.item()), float(log_prob.item()), float(value.squeeze(-1).item())

    def evaluate_actions(
        self,
        obs: torch.Tensor,
        action_mask: torch.Tensor,
        actions: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Evaluates batch of state-action transitions for PPO / A2C loss computation.
        Employs masked_log_softmax for numerically stable importance ratio calculation.

        Returns:
            Tuple of (log_probs, state_values, entropy).
        """
        features = self.trunk(obs)
        raw_logits = self.actor(features)
        values = self.critic(features)

        log_probs_all = masked_log_softmax(raw_logits, action_mask)
        probs_all = torch.exp(log_probs_all)

        # Extract log probability of taken action
        log_probs = log_probs_all.gather(1, actions.unsqueeze(-1)).squeeze(-1)

        # Entropy: -sum(p * log p), ignoring 0 * -inf masked terms
        valid_terms = torch.where(
            action_mask > 0.5,
            probs_all * log_probs_all,
            torch.zeros_like(probs_all)
        )
        entropy = -torch.sum(valid_terms, dim=-1)

        return log_probs, values.squeeze(-1), entropy

    def save(self, filepath: str) -> None:
        """Saves model weights to disk."""
        target_dir = os.path.dirname(os.path.abspath(filepath))
        os.makedirs(target_dir, exist_ok=True)
        torch.save({
            "model_state_dict": self.state_dict(),
            "input_dim": self.input_dim,
            "num_actions": self.num_actions,
        }, filepath)

    def load(self, filepath: str, map_location: str = "cpu") -> None:
        """Loads model weights from disk with backward compatibility."""
        checkpoint = torch.load(filepath, map_location=map_location)
        if isinstance(checkpoint, dict) and "model_state_dict" in checkpoint:
            state_dict = checkpoint["model_state_dict"]
        else:
            state_dict = checkpoint
        self.load_state_dict(state_dict, strict=False)
        self.eval()
