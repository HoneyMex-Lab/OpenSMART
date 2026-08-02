"""iptables engine for the Firewall module — mirrors firewall_nft.py's shape
(pure render + host-specific validate/live-query/apply-script), dispatched to
by firewall.py based on a profile's `engine` column.

Integration point, confirmed live on the reference host: this host's `iptables`
is the iptables-nft compatibility layer (classic syntax, nf_tables kernel
backend), sharing the nf_tables subsystem with the nftables engine but through
a completely separate userspace grammar and in-kernel representation — the
two engines' artifacts never collide, but only one is ever meant to be
enforced at a time (see teardown_fragment() and firewall.py's apply()).

Real `INPUT`/`FORWARD`/`OUTPUT` base-chain policies are never touched (they
stay ACCEPT — host-owned, shared state this module doesn't own). Instead,
this engine's rules live in three dedicated custom chains —
`OPENSMART-INPUT`, `OPENSMART-FORWARD`, `OPENSMART-OUTPUT` — reached via
exactly one jump rule inserted into the real `INPUT` and `OUTPUT` chains, and
into Docker's own `DOCKER-USER` chain for `FORWARD` (Docker's documented,
permanent, safe-for-admins insertion point — confirmed present and empty on
the reference host; never inserted directly into the real `FORWARD` chain,
which would compete with Docker's own chain ordering there). A profile's
declared chain "policy" (accept/drop) is realised as an explicit terminal
rule at the end of our own custom chain, never a change to the real chain's
policy.
"""

STATE_EXT = "iptables"

CUSTOM_CHAINS = ("OPENSMART-INPUT", "OPENSMART-FORWARD", "OPENSMART-OUTPUT")

# Renderer, validate(), live_query() land in a later phase (Phase 3 of
# design notes); apply support (APPLY_SCRIPT) in the
# phase after that. Until then, firewall.py's dispatch surfaces a clear
# "not yet supported" error for any iptables-engine profile.
APPLY_SCRIPT = None


def teardown_fragment() -> str:
    """Bash, safe to embed inside another engine's apply script to
    defensively remove this engine's artifacts before that engine's own
    ruleset is applied. Idempotent; a no-op if nothing of ours is loaded.
    Defined ahead of this engine's own apply pipeline (Phase 4) so the
    nftables engine's "at most one engine enforced at a time" invariant is
    real starting now, not only once iptables can apply anything itself."""
    lines = [f'iptables -F "{chain}" 2>/dev/null || true' for chain in CUSTOM_CHAINS]
    lines += [
        'iptables -D INPUT -j OPENSMART-INPUT 2>/dev/null || true',
        'iptables -D OUTPUT -j OPENSMART-OUTPUT 2>/dev/null || true',
        'iptables -D DOCKER-USER -j OPENSMART-FORWARD 2>/dev/null || true',
    ]
    lines += [f'iptables -X "{chain}" 2>/dev/null || true' for chain in CUSTOM_CHAINS]
    return "\n".join(lines)
