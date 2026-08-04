"""Shared test support: an in-memory fake RPC client (no network).

Models the real B20 interface: eth_call responses keyed by calldata, role
holders programmed as RoleGranted/RoleRevoked logs (range-aware eth_getLogs),
plus helpers for the activation gate and isB20 preflight.
"""

from __future__ import annotations

from typing import Optional

from acpsec_api.b20 import constants as C
from acpsec_api.b20 import reader as R


def abi_string(s: str) -> str:
    """Encode a Python str as a standard ABI dynamic string return ("0x"...)."""
    raw = s.encode("utf-8")
    pad = (-len(raw)) % 32
    data = (raw + b"\x00" * pad).hex()
    return "0x" + R.enc_uint(32) + R.enc_uint(len(raw)) + data


def _bool_word(b: bool) -> str:
    return "0x" + R.enc_uint(1 if b else 0)


def _topic_addr(addr: str) -> str:
    return "0x" + R.enc_address(addr)


class FakeRpc:
    def __init__(self, chain_id: int = 8453) -> None:
        self.chain_id = chain_id
        self.responses: dict[str, Optional[str]] = {}   # calldata -> result hex
        self.code: dict[str, Optional[str]] = {}        # address -> code hex
        self.txcounts: dict[str, Optional[str]] = {}    # address -> count hex
        self.block_number: int = 100
        self.role_logs: dict[str, list] = {}            # role (lower) -> [log]
        self.announcement_logs: list = []
        self.logs_fail: bool = False                    # simulate eth_getLogs failure
        # Provider block-range cap emulation: when set, a getLogs whose
        # (toBlock - fromBlock) exceeds it is REJECTED exactly as the real
        # RpcClient classifies it — None + last_error_kind == "getlogs_range_cap".
        self.max_getlogs_range: Optional[int] = None
        self.range_cap_error: str = (
            '{"code":-32600,"message":"Under the Free tier plan, you can make '
            'eth_getLogs requests with up to a 10 block range."}'
        )
        # Mirror the RpcClient diagnostic surface the reader now consumes.
        self.last_error: Optional[str] = None
        self.last_error_kind: Optional[str] = None
        self.getlogs_calls: list[dict] = []             # every getLogs filter (for assertions)
        self.calls: list[str] = []
        # eth_getCode-by-block support (creation-block binary search):
        # token (lower) -> (creation_block, code_hex); code appears at >= block.
        self.creation_code: dict[str, tuple[int, str]] = {}
        self.getcode_fail: bool = False                 # by-block eth_getCode -> None
        self.getcode_calls: list[str] = []              # blocks probed (for assertions)

    # --- RpcClient surface ------------------------------------------------
    def eth_call(self, to: str, data: str, block: str = "latest") -> Optional[str]:
        self.calls.append(data)
        return self.responses.get(data)

    def eth_get_code(self, addr: str, block: str = "latest") -> Optional[str]:
        self.getcode_calls.append(block)
        key = addr.lower()
        if key in self.creation_code:
            cb, code = self.creation_code[key]
            if block != "latest" and self.getcode_fail:
                return None
            b = self.block_number if block == "latest" else int(block, 16)
            return code if b >= cb else "0x"
        return self.code.get(key)

    def eth_get_transaction_count(self, addr: str, block: str = "latest") -> Optional[str]:
        return self.txcounts.get(addr.lower())

    def eth_block_number(self) -> Optional[int]:
        return self.block_number

    def eth_get_logs(self, filter_obj: dict) -> Optional[list]:
        self.getlogs_calls.append(filter_obj)
        frm = int(filter_obj.get("fromBlock", "0x0"), 16)
        to_raw = filter_obj.get("toBlock", "latest")
        to = self.block_number if to_raw == "latest" else int(to_raw, 16)
        # Provider range cap: a too-wide window is rejected + classified, exactly
        # as RpcClient would — the reader must then fall back to the chunk walk.
        if self.max_getlogs_range is not None and to - frm > self.max_getlogs_range:
            self.last_error = f"rpc error: {self.range_cap_error}"
            self.last_error_kind = "getlogs_range_cap"
            return None
        if self.logs_fail:
            self.last_error = "getlogs failed"
            self.last_error_kind = None
            return None
        topics = filter_obj.get("topics", [])
        t0 = topics[0] if topics else None
        if isinstance(t0, list):  # role query
            if len(topics) > 1:                       # per-role: [[GRANTED, REVOKED], role]
                role = str(topics[1]).lower()
                cand = self.role_logs.get(role, [])
            else:                                     # MERGED: [[GRANTED, REVOKED]] — all roles
                cand = [lg for logs in self.role_logs.values() for lg in logs]
        elif t0 == C.B20_EVENT_ANNOUNCEMENT:
            cand = self.announcement_logs
        else:
            cand = []
        self.last_error = None
        self.last_error_kind = None
        return [lg for lg in cand if frm <= int(lg["blockNumber"], 16) <= to]

    def set_max_getlogs_range(self, n: Optional[int]) -> "FakeRpc":
        self.max_getlogs_range = n
        return self

    # --- ergonomic programming helpers -----------------------------------
    def set_call(self, calldata_hex: str, result_hex: Optional[str]) -> "FakeRpc":
        self.responses[calldata_hex] = result_hex
        return self

    def set_selector(self, selector: str, result_hex: Optional[str]) -> "FakeRpc":
        self.responses[R.calldata(selector)] = result_hex
        return self

    def set_code(self, addr: str, code_hex: Optional[str]) -> "FakeRpc":
        self.code[addr.lower()] = code_hex
        return self

    def set_txcount(self, addr: str, count_hex: Optional[str]) -> "FakeRpc":
        self.txcounts[addr.lower()] = count_hex
        return self

    def set_block_number(self, n: int) -> "FakeRpc":
        self.block_number = n
        return self

    # --- role-event mocking ----------------------------------------------
    def add_role_event(self, role: str, event_topic: str, account: str, block: int, log_index: int = 0) -> "FakeRpc":
        self.role_logs.setdefault(role.lower(), []).append({
            "topics": [event_topic, role, _topic_addr(account), _topic_addr(account)],
            "blockNumber": hex(block),
            "logIndex": hex(log_index),
        })
        return self

    def grant_role(self, role: str, account: str, block: int, log_index: int = 0) -> "FakeRpc":
        return self.add_role_event(role, C.B20_EVENT_ROLE_GRANTED, account, block, log_index)

    def revoke_role(self, role: str, account: str, block: int, log_index: int = 0) -> "FakeRpc":
        return self.add_role_event(role, C.B20_EVENT_ROLE_REVOKED, account, block, log_index)

    def set_role_holders(self, role: str, holders: list[str]) -> "FakeRpc":
        """Program current holders as one grant event each (ascending blocks)."""
        for i, h in enumerate(holders, start=1):
            self.grant_role(role, h, block=i, log_index=0)
        return self

    def set_logs_fail(self, fail: bool = True) -> "FakeRpc":
        self.logs_fail = fail
        return self

    def set_announcements(self, count: int) -> "FakeRpc":
        self.announcement_logs = [
            {"topics": [C.B20_EVENT_ANNOUNCEMENT], "blockNumber": hex(i + 1), "logIndex": "0x0"}
            for i in range(count)
        ]
        return self

    def set_creation_code(self, token: str, creation_block: int, code: str = "0xef") -> "FakeRpc":
        """Program eth_getCode so ``token`` has ``code`` at blocks >= creation_block
        and "0x" before it — the boundary the creation-block binary search finds."""
        self.creation_code[token.lower()] = (creation_block, code)
        return self

    def set_getcode_fail(self, fail: bool = True) -> "FakeRpc":
        self.getcode_fail = fail
        return self

    # --- preflight mocking -----------------------------------------------
    def set_is_b20(self, token: str, value: bool) -> "FakeRpc":
        self.responses[R.calldata(C.B20_SELECTOR_IS_B20, R.enc_address(token))] = _bool_word(value)
        return self

    def set_is_b20_initialized(self, token: str, value: bool) -> "FakeRpc":
        self.responses[R.calldata(C.B20_SELECTOR_IS_B20_INITIALIZED, R.enc_address(token))] = _bool_word(value)
        return self

    def set_activated(self, variant: str, value: bool) -> "FakeRpc":
        feature = C.B20_FEATURE_ASSET if variant == "ASSET" else C.B20_FEATURE_STABLECOIN
        self.responses[R.calldata(C.B20_SELECTOR_IS_ACTIVATED, R.word(feature))] = _bool_word(value)
        return self
