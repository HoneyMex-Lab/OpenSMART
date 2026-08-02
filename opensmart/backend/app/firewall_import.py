"""Ruleset import for the Firewall module: parses a deliberately bounded
subset of each engine's native export format into DRAFT structured rows —
never saved directly, always reviewed and explicitly confirmed by an admin
before becoming a real profile (see routes/firewall.py's import endpoints).

Scope, on purpose (see design notes's Decisions):
- iptables: only the canonical `iptables-save` block format (`*filter` /
  `:CHAIN POLICY [pkts:bytes]` / `-A CHAIN <matches> -j <target>` / `COMMIT`).
  Raw `iptables -A ...` shell-command lists are out of scope — reliably
  parsing shell quoting/escaping is a much larger, riskier problem.
- nftables: only `nft -j list ruleset` JSON — nft's free-text grammar is
  ambiguous to parse reliably; JSON has an unambiguous structure.
- Only rules in INPUT/FORWARD/OUTPUT (iptables) or chains with hook
  input/forward/output (nft) are considered; anything else (nat/mangle/raw
  tables, custom chains, Docker's own chains) is skipped with a warning,
  never guessed at.
- Anything using a match/target this parser doesn't recognize is reported
  as unsupported and NOT imported as an approximation — a parser that
  quietly mis-translates a rule is a security bug, not a UX one.
"""
import json
import re
import shlex

_OUR_CHAINS = {
    "INPUT": "input", "FORWARD": "forward", "OUTPUT": "output",
    "OPENSMART-INPUT": "input", "OPENSMART-FORWARD": "forward", "OPENSMART-OUTPUT": "output",
}
_MANAGEMENT_JUMP_TARGETS = {"OPENSMART-INPUT", "OPENSMART-FORWARD", "OPENSMART-OUTPUT"}
_STATE_UPPER_TO_LOWER = {"NEW": "new", "ESTABLISHED": "established", "RELATED": "related", "INVALID": "invalid", "UNTRACKED": "untracked"}
_REJECT_IPTABLES_TO_OURS = {
    "tcp-reset": "tcp reset",
    "icmp-port-unreachable": "icmp port-unreachable",
    "icmp-admin-prohibited": "icmp admin-prohibited",
}
_SUPPORTED_PROTOCOLS = {"tcp", "udp", "icmp", "all"}
_OSFW_ID_COMMENT_RE = re.compile(r"^osfw:\d+$")
_OSFW_LOG_PREFIX_RE = re.compile(r"^osfw-\d+:\s?")
# Matches database.py's seeded-profile default — a chain policy from the
# SOURCE ruleset is never carried into the imported profile (this schema's
# "policy" is a per-profile setting the admin sets separately), so a
# non-default source policy is worth calling out explicitly rather than
# silently landing on a different effective policy than the file had.
_DEFAULT_POLICIES = {"input": "drop", "forward": "drop", "output": "accept"}

_EMPTY_RULE = {
    "enabled": True, "action": "", "reject_with": "", "family": "inet", "protocol": "any",
    "iif": "", "oif": "", "src": "", "src_negate": False, "dst": "", "dst_negate": False,
    "sport": "", "dport": "", "ct_state": "", "icmp_type": "", "log": False, "log_prefix": "",
    "rate_limit": "", "description": "",
}


class FirewallImportError(Exception):
    """User-facing import failure — the file doesn't look like the expected format at all."""


def _interfaces_of(rule: dict) -> set[str]:
    found = set()
    for value in (rule["iif"], rule["oif"]):
        if value:
            found.update(part.strip() for part in value.split(",") if part.strip())
    return found


def _parse_iptables_rule_tokens(tokens: list[str]) -> dict | None:
    """tokens = everything after '-A <chain>'. Returns a structured rule
    (schema matching firewall.create_rule()'s fields) or None if the rule
    uses anything this parser doesn't recognize — including index errors
    from a truncated/malformed flag, which are just another shape of
    "not recognized", not a crash."""
    rule = dict(_EMPTY_RULE)
    negate_next = False
    i = 0
    n = len(tokens)
    try:
        while i < n:
            tok = tokens[i]
            if tok == "!":
                negate_next = True
                i += 1
                continue
            if tok == "-i":
                rule["iif"] = tokens[i + 1]
                i += 2
            elif tok == "-o":
                rule["oif"] = tokens[i + 1]
                i += 2
            elif tok == "-p":
                if negate_next:
                    return None  # negated protocol has no equivalent in our schema
                proto = tokens[i + 1]
                if proto not in _SUPPORTED_PROTOCOLS:
                    return None
                rule["protocol"] = "any" if proto == "all" else proto
                i += 2
            elif tok == "-s":
                rule["src"] = tokens[i + 1]
                rule["src_negate"] = negate_next
                i += 2
            elif tok == "-d":
                rule["dst"] = tokens[i + 1]
                rule["dst_negate"] = negate_next
                i += 2
            elif tok in ("--sport", "--sports"):
                rule["sport"] = tokens[i + 1].replace(":", "-")
                i += 2
            elif tok in ("--dport", "--dports"):
                rule["dport"] = tokens[i + 1].replace(":", "-")
                i += 2
            elif tok == "--icmp-type":
                rule["icmp_type"] = tokens[i + 1]
                i += 2
            elif tok == "-m":
                module = tokens[i + 1]
                if module == "comment" and tokens[i + 2] == "--comment":
                    rule["description"] = tokens[i + 3]
                    i += 4
                elif module == "conntrack" and tokens[i + 2] == "--ctstate":
                    states = tokens[i + 3].split(",")
                    if any(s not in _STATE_UPPER_TO_LOWER for s in states):
                        return None
                    rule["ct_state"] = ",".join(_STATE_UPPER_TO_LOWER[s] for s in states)
                    i += 4
                elif module == "multiport":
                    i += 2  # the actual --sports/--dports token is handled above
                elif module == "limit" and tokens[i + 2] == "--limit":
                    rate = tokens[i + 3]
                    j = i + 4
                    burst = None
                    if j < n and tokens[j] == "--limit-burst":
                        burst = tokens[j + 1]
                        j += 2
                    rule["rate_limit"] = f"{rate} burst {burst} packets" if burst else rate
                    i = j
                else:
                    return None  # unrecognized -m module/option combination
            elif tok == "-j":
                target = tokens[i + 1]
                i += 2
                if target == "ACCEPT":
                    rule["action"] = "accept"
                elif target == "DROP":
                    rule["action"] = "drop"
                elif target == "REJECT":
                    rule["action"] = "reject"
                    if i < n and tokens[i] == "--reject-with":
                        mapped = _REJECT_IPTABLES_TO_OURS.get(tokens[i + 1])
                        if mapped is None:
                            return None
                        rule["reject_with"] = mapped
                        i += 2
                else:
                    return None  # LOG, a custom target chain, or anything else — v1 doesn't import these
            else:
                return None  # unrecognized flag
            negate_next = False
    except IndexError:
        return None
    if not rule["action"]:
        return None
    return rule


def parse_iptables_save(text: str) -> dict:
    rules: list[dict] = []
    warnings: list[str] = []
    unsupported: list[dict] = []
    interfaces_found: set[str] = set()
    position = {"input": 0, "forward": 0, "output": 0}

    saw_filter_table = False
    in_filter = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "*filter":
            in_filter = True
            saw_filter_table = True
            continue
        if line.startswith("*"):
            in_filter = False  # a different table (nat/mangle/raw) — skip its rules entirely
            continue
        if not in_filter:
            continue
        if line == "COMMIT":
            in_filter = False
            continue
        if line.startswith(":"):
            parts = line[1:].split()
            if len(parts) >= 2:
                our_chain = _OUR_CHAINS.get(parts[0])
                policy_word = parts[1].lower()
                if our_chain and policy_word != "-" and policy_word != _DEFAULT_POLICIES[our_chain]:
                    warnings.append(
                        f"Chain '{parts[0]}' policy '{parts[1]}' was not imported — the new profile will use "
                        f"this app's default policy '{_DEFAULT_POLICIES[our_chain]}' for '{our_chain}'; adjust it after import if needed."
                    )
            continue  # chain declaration/policy line — nothing else to import from this
        if not line.startswith("-A "):
            unsupported.append({"line": raw_line, "reason": "not a -A rule or recognized directive"})
            continue
        try:
            tokens = shlex.split(line)
        except ValueError as error:
            unsupported.append({"line": raw_line, "reason": f"could not tokenize (unbalanced quotes?): {error}"})
            continue
        if len(tokens) < 2 or tokens[0] != "-A":
            unsupported.append({"line": raw_line, "reason": "malformed -A line"})
            continue
        chain_name = tokens[1]
        rest = tokens[2:]
        if chain_name in ("INPUT", "OUTPUT", "DOCKER-USER") and rest == ["-j", rest[-1] if rest else ""] and rest[-1:] and rest[-1] in _MANAGEMENT_JUMP_TARGETS:
            continue  # this app's own management jump rule — internal plumbing, not a rule to import
        if chain_name not in _OUR_CHAINS:
            warnings.append(f"Skipped rule in chain '{chain_name}' — only INPUT/FORWARD/OUTPUT (or this app's own OPENSMART-* chains) are imported.")
            continue
        chain = _OUR_CHAINS[chain_name]
        try:
            parsed = _parse_iptables_rule_tokens(rest)
        except Exception as error:  # noqa: BLE001 — fail closed per-line, never crash the whole import (mirrors parse_nft_json's same backstop)
            unsupported.append({"line": raw_line, "reason": f"could not parse ({type(error).__name__}) — not imported"})
            continue
        if parsed is None:
            unsupported.append({"line": raw_line, "reason": "uses a match/target this importer doesn't recognize"})
            continue
        position[chain] += 1
        parsed["chain"] = chain
        parsed["position"] = position[chain]
        interfaces_found.update(_interfaces_of(parsed))
        rules.append(parsed)

    if not saw_filter_table:
        raise FirewallImportError("No '*filter' table found — this doesn't look like iptables-save output.")
    return {"rules": rules, "warnings": warnings, "unsupported": unsupported, "interfaces_found": sorted(interfaces_found)}


# ── nftables JSON import (`nft -j list ruleset`) ────────────────────────────
#
# Shapes below are taken from REAL `nft -j list ruleset` output (verified
# live against nft 1.1.3 on the reference host, both the actual seeded profile
# and a scratch table covering every field this importer handles), not
# guessed at — nft's JSON is more particular than it first looks:
# - A rule's description is a top-level `rule.comment` string, NOT part of
#   `expr` (unlike this app's own comment tag, which nft also puts there).
# - A multi-value match (address set, port set, tcp+udp) wraps its values
#   as `{"set": [...]}`; a single value is a bare scalar or an addr/port
#   compound (`{"prefix": ...}`, `{"range": [...]}`) — never both shapes
#   for the same match, so `_unwrap_set()` normalizes both to a list.
# - `ct state` is the one list-valued match that is NOT set-wrapped — nft
#   emits a bare list (or bare string for a single state) directly.
# - icmp/icmpv6 `type` values come back as canonical NAMES ("echo-request"),
# not the numeric value this schema stores — mapped back via a fixed table;
#   an unrecognized name is unsupported, not guessed at.
# - `reject` with no explicit "with" clause reports nft's own default
#   (icmp port-unreachable) explicitly rather than omitting it — mapped
#   back to this schema's blank/default reject_with, which renders
#   identically on re-export.

_NFT_CHAIN_HOOKS = {"input": "input", "forward": "forward", "output": "output"}

_ICMP_NAME_TO_NUM = {
    "echo-reply": "0", "destination-unreachable": "3", "source-quench": "4",
    "redirect": "5", "echo-request": "8", "router-advertisement": "9",
    "router-solicitation": "10", "time-exceeded": "11", "parameter-problem": "12",
    "timestamp-request": "13", "timestamp-reply": "14",
}
_ICMPV6_NAME_TO_NUM = {
    "destination-unreachable": "1", "packet-too-big": "2", "time-exceeded": "3",
    "parameter-problem": "4", "echo-request": "128", "echo-reply": "129",
}


def _unwrap_set(value):
    """nft wraps a multi-value right-hand side as {'set': [...]}; a single
    value is the bare scalar/compound itself. Normalizes both to a list so
    callers handle one shape."""
    if isinstance(value, dict) and "set" in value:
        return value["set"]
    return [value]


def _nft_addr_value(item) -> str | None:
    if isinstance(item, str):
        return item
    if isinstance(item, dict) and "prefix" in item:
        prefix = item["prefix"]
        return f"{prefix.get('addr')}/{prefix.get('len')}"
    return None


def _nft_addr_expr(expr: dict) -> tuple[str, bool] | None:
    """Returns (value, negate) for a saddr/daddr match, or None if the
    shape isn't one this importer recognizes."""
    op = expr.get("op")
    if op not in ("==", "!="):
        return None
    parts = [_nft_addr_value(item) for item in _unwrap_set(expr.get("right"))]
    if not parts or any(p is None for p in parts):
        return None
    return ",".join(parts), op == "!="


def _nft_port_value(item) -> str | None:
    if isinstance(item, int):
        return str(item)
    if isinstance(item, dict) and "range" in item:
        lo, hi = item["range"]
        return f"{lo}-{hi}"
    return None


def _nft_port_expr(expr: dict) -> str | None:
    if expr.get("op") != "==":
        return None
    parts = [_nft_port_value(item) for item in _unwrap_set(expr.get("right"))]
    if not parts or any(p is None for p in parts):
        return None
    return ",".join(parts)


def _parse_nft_rule_expr(expr_list: list[dict]) -> dict | None:
    rule = dict(_EMPTY_RULE)
    protocol_from_meta = None
    # A dport/sport match's own `protocol` field implies tcp/udp — our own
    # renderer skips the separate `meta l4proto` statement in exactly this
    # case (redundant otherwise), so this is the ONLY source of protocol
    # for a plain tcp/udp rule with a port match. An explicit meta l4proto
    # match (checked below), when present, is authoritative over this.
    protocol_from_payload = None
    for item in expr_list:
        if "counter" in item:
            continue
        if "match" in item:
            match = item["match"]
            left = match.get("left")
            if not isinstance(left, dict):
                return None
            if "payload" in left:
                payload = left["payload"]
                field = payload.get("field")
                proto_field = payload.get("protocol")
                if field == "saddr" and proto_field in ("ip", "ip6"):
                    parsed = _nft_addr_expr(match)
                    if parsed is None:
                        return None
                    rule["src"], rule["src_negate"] = parsed
                    if proto_field == "ip6":
                        rule["family"] = "ip6"
                elif field == "daddr" and proto_field in ("ip", "ip6"):
                    parsed = _nft_addr_expr(match)
                    if parsed is None:
                        return None
                    rule["dst"], rule["dst_negate"] = parsed
                    if proto_field == "ip6":
                        rule["family"] = "ip6"
                elif field == "sport" and proto_field in ("tcp", "udp", "th"):
                    value = _nft_port_expr(match)
                    if value is None:
                        return None
                    rule["sport"] = value
                    if proto_field in ("tcp", "udp"):
                        protocol_from_payload = proto_field
                    elif proto_field == "th":
                        protocol_from_payload = "tcp+udp"
                elif field == "dport" and proto_field in ("tcp", "udp", "th"):
                    value = _nft_port_expr(match)
                    if value is None:
                        return None
                    rule["dport"] = value
                    if proto_field in ("tcp", "udp"):
                        protocol_from_payload = proto_field
                    elif proto_field == "th":
                        protocol_from_payload = "tcp+udp"
                elif field == "type" and proto_field in ("icmp", "icmpv6"):
                    right = match.get("right")
                    table = _ICMP_NAME_TO_NUM if proto_field == "icmp" else _ICMPV6_NAME_TO_NUM
                    if isinstance(right, int):
                        value = str(right)
                    elif isinstance(right, str):
                        value = table.get(right)
                        if value is None:
                            return None
                    else:
                        return None
                    rule["icmp_type"] = value
                    rule["protocol"] = proto_field
                else:
                    return None
            elif "meta" in left and left["meta"].get("key") == "l4proto":
                values = _unwrap_set(match.get("right"))
                if set(values) == {"tcp", "udp"}:
                    protocol_from_meta = "tcp+udp"
                elif len(values) == 1 and values[0] in ("tcp", "udp", "icmp", "icmpv6"):
                    protocol_from_meta = values[0]
                else:
                    return None
            elif "ct" in left and left["ct"].get("key") == "state":
                # NOT set-wrapped — nft emits a bare list (or bare string
                # for one state) directly for ct state, unlike addr/port/
                # iface matches.
                right = match.get("right")
                values = right if isinstance(right, list) else [right]
                if match.get("op") not in ("==", "in") or any(v not in ("new", "established", "related", "invalid", "untracked") for v in values):
                    return None
                rule["ct_state"] = ",".join(values)
            elif "meta" in left and left["meta"].get("key") in ("iifname", "oifname"):
                if match.get("op") != "==":
                    return None
                values = _unwrap_set(match.get("right"))
                if not all(isinstance(v, str) for v in values):
                    return None
                if left["meta"]["key"] == "iifname":
                    rule["iif"] = ",".join(values)
                else:
                    rule["oif"] = ",".join(values)
            else:
                return None
        elif "accept" in item:
            rule["action"] = "accept"
        elif "drop" in item:
            rule["action"] = "drop"
        elif "reject" in item:
            rule["action"] = "reject"
            reject = item.get("reject") or {}
            rtype = reject.get("type")
            rexpr = reject.get("expr")
            if rtype == "tcp reset":
                rule["reject_with"] = "tcp reset"
            elif rtype in ("icmp", "icmpx") and rexpr in ("port-unreachable", None):
                rule["reject_with"] = ""  # nft's own default — round-trips identically blank
            elif rtype == "icmp" and rexpr == "admin-prohibited":
                rule["reject_with"] = "icmp admin-prohibited"
            elif rtype in ("icmp6", "icmpv6") and rexpr == "port-unreachable":
                rule["reject_with"] = "icmpv6 port-unreachable"
            elif rtype in ("icmp6", "icmpv6") and rexpr == "admin-prohibited":
                rule["reject_with"] = "icmpv6 admin-prohibited"
            else:
                return None
        elif "log" in item:
            rule["log"] = True
            prefix = (item.get("log") or {}).get("prefix", "")
            # Strip this app's own "osfw-<id>: " tag (see firewall_nft.py's
            # renderer) so a round-tripped import doesn't accumulate a new
            # tag on top of the old one.
            rule["log_prefix"] = _OSFW_LOG_PREFIX_RE.sub("", prefix, count=1)
        elif "limit" in item:
            limit = item["limit"]
            rate = limit.get("rate")
            if rate is None:
                return None
            unit = limit.get("per", "second")
            burst = limit.get("burst")
            rule["rate_limit"] = f"{rate}/{unit} burst {burst} packets" if burst else f"{rate}/{unit}"
        else:
            return None  # unrecognized statement/expression
    if protocol_from_meta:
        rule["protocol"] = protocol_from_meta
    elif protocol_from_payload:
        rule["protocol"] = protocol_from_payload
    if not rule["action"]:
        return None
    return rule


def parse_nft_json(text: str) -> dict:
    # A pathologically deeply-nested JSON document (a "JSON bomb" of nested
    # arrays) can blow the interpreter's recursion limit inside json.loads
    # itself — that's a shape of "not valid JSON we can handle", not a
    # crash, so it's reported the same way as a JSONDecodeError.
    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        raise FirewallImportError(f"Not valid JSON: {error}") from error
    except RecursionError as error:
        raise FirewallImportError("JSON is too deeply nested to parse.") from error
    entries = data.get("nftables") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise FirewallImportError("Not `nft -j list ruleset` output — expected a top-level 'nftables' array.")

    chain_hooks: dict[tuple, str] = {}  # (table, chain-name) -> our chain key
    rules: list[dict] = []
    warnings: list[str] = []
    unsupported: list[dict] = []
    interfaces_found: set[str] = set()
    position = {"input": 0, "forward": 0, "output": 0}

    for entry in entries:
        chain = entry.get("chain") if isinstance(entry, dict) else None
        if isinstance(chain, dict) and chain.get("hook") in _NFT_CHAIN_HOOKS:
            our_chain = _NFT_CHAIN_HOOKS[chain["hook"]]
            chain_hooks[(chain.get("table"), chain.get("name"))] = our_chain
            policy = chain.get("policy")
            if isinstance(policy, str) and policy != _DEFAULT_POLICIES[our_chain]:
                warnings.append(
                    f"Chain '{chain.get('name')}' policy '{policy}' was not imported — the new profile will use "
                    f"this app's default policy '{_DEFAULT_POLICIES[our_chain]}' for '{our_chain}'; adjust it after import if needed."
                )

    for entry in entries:
        rule_obj = entry.get("rule") if isinstance(entry, dict) else None
        if not isinstance(rule_obj, dict):
            continue
        # This importer's contract is "recognized shapes become rules,
        # anything else is reported as unsupported" — never an unhandled
        # exception. _parse_nft_rule_expr() and its helpers return None for
        # every shape they anticipated (see their own docstrings/comments),
        # but the sheer variety of what a hand-edited or differently-
        # versioned nft JSON file could contain makes a residual
        # try/except the honest backstop for that contract, not a
        # substitute for the None-returning checks already in place.
        try:
            key = (rule_obj.get("table"), rule_obj.get("chain"))
            our_chain = chain_hooks.get(key)
            if our_chain is None:
                warnings.append(f"Skipped rule in chain '{rule_obj.get('chain')}' (table {rule_obj.get('table')}) — only input/forward/output base chains are imported.")
                continue
            expr = rule_obj.get("expr")
            if not isinstance(expr, list):
                unsupported.append({"line": json.dumps(rule_obj)[:2000], "reason": "rule has no expr array"})
                continue
            parsed = _parse_nft_rule_expr(expr)
            if parsed is None:
                unsupported.append({"line": json.dumps(rule_obj)[:2000], "reason": "uses a match/statement this importer doesn't recognize"})
                continue
            # A rule's description is a top-level `rule.comment` field, not
            # part of `expr` — this app's own id tag ("osfw:<id>") isn't a
            # real description and is dropped rather than imported as one.
            comment = rule_obj.get("comment")
            if isinstance(comment, str) and comment and not _OSFW_ID_COMMENT_RE.match(comment):
                parsed["description"] = comment
            position[our_chain] += 1
            parsed["chain"] = our_chain
            parsed["position"] = position[our_chain]
            interfaces_found.update(_interfaces_of(parsed))
            rules.append(parsed)
        except Exception as error:  # noqa: BLE001 — see comment above: fail closed per-rule, never crash the whole import
            unsupported.append({"line": json.dumps(rule_obj)[:2000], "reason": f"could not parse ({type(error).__name__}) — not imported"})

    return {"rules": rules, "warnings": warnings, "unsupported": unsupported, "interfaces_found": sorted(interfaces_found)}


def parse(engine: str, text: str) -> dict:
    if engine == "iptables":
        return parse_iptables_save(text)
    if engine == "nftables":
        return parse_nft_json(text)
    raise FirewallImportError(f"Unknown engine '{engine}'.")
