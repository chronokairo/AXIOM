"""Security regression tests for MCP server resource-consumption guards.

Covers the fixes for the code scanning alerts of issue #7 (uncontrolled
resource consumption, CWE-400/CWE-770): stdio rate limiting, bounded
JSON-RPC message size, and capped tool parameters (ADR-0033).

Zero mocks: rate limiting is exercised against real server subprocesses
and the parameter caps against the real dispatch layer.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

# Ensure `src/` is importable when running `python -m unittest` from repo root
_SRC_DIR = str(Path(__file__).resolve().parent.parent / "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from axiom import dispatch_tool  # noqa: E402
from axiom.mcp_server import (  # noqa: E402
    MAX_PLOT_POINTS,
    TokenBucketRateLimiter,
    _capped_int_arg,
    _read_bounded_line,
)


def _child_env(**overrides: str) -> dict[str, str]:
    """Environment for `python -m axiom.mcp_server` subprocesses."""
    env = dict(os.environ)
    env["PYTHONPATH"] = _SRC_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env.update(overrides)
    return env


class TestTokenBucketRateLimiter(unittest.TestCase):
    def test_burst_then_deny_then_refill(self) -> None:
        limiter = TokenBucketRateLimiter(rate_per_second=100, burst=2)
        self.assertTrue(limiter.allow())
        self.assertTrue(limiter.allow())
        self.assertFalse(limiter.allow())
        time.sleep(0.05)  # at 100 tokens/s this refills well past one token
        self.assertTrue(limiter.allow())

    def test_zero_rate_disables_limiting(self) -> None:
        limiter = TokenBucketRateLimiter(rate_per_second=0, burst=1)
        for _ in range(100):
            self.assertTrue(limiter.allow())


class TestReadBoundedLine(unittest.TestCase):
    def test_normal_lines(self) -> None:
        stream = io.StringIO("hello\nworld\n")
        self.assertEqual(_read_bounded_line(stream, 10), ("hello\n", False))
        self.assertEqual(_read_bounded_line(stream, 10), ("world\n", False))
        self.assertEqual(_read_bounded_line(stream, 10), (None, False))

    def test_oversized_line_is_drained_and_next_line_intact(self) -> None:
        stream = io.StringIO("a" * 15 + "\n" + "next\n")
        line, oversized = _read_bounded_line(stream, 10)
        self.assertTrue(oversized)
        self.assertEqual(line, "a" * 11)  # truncated chunk; must not be processed
        self.assertEqual(_read_bounded_line(stream, 10), ("next\n", False))

    def test_final_line_without_newline(self) -> None:
        stream = io.StringIO("abc")
        self.assertEqual(_read_bounded_line(stream, 10), ("abc", False))
        self.assertEqual(_read_bounded_line(stream, 10), (None, False))

    def test_empty_stream(self) -> None:
        self.assertEqual(_read_bounded_line(io.StringIO(""), 10), (None, False))


class TestCappedIntArg(unittest.TestCase):
    def test_missing_key_uses_default(self) -> None:
        self.assertEqual(_capped_int_arg({}, "points", 101, 10_000), (101, ""))

    def test_valid_value_passes(self) -> None:
        self.assertEqual(
            _capped_int_arg({"points": 500}, "points", 101, 10_000), (500, "")
        )

    def test_value_equal_to_cap_passes(self) -> None:
        self.assertEqual(
            _capped_int_arg({"points": MAX_PLOT_POINTS}, "points", 101, MAX_PLOT_POINTS),
            (MAX_PLOT_POINTS, ""),
        )

    def test_value_above_cap_fails_closed(self) -> None:
        value, err = _capped_int_arg({"points": 10**9}, "points", 101, 10_000)
        self.assertIsNone(value)
        self.assertIn("safety cap", err)

    def test_non_integer_fails_closed(self) -> None:
        value, err = _capped_int_arg({"points": "many"}, "points", 101, 10_000)
        self.assertIsNone(value)
        self.assertIn("must be an integer", err)


class TestDispatchParameterCaps(unittest.TestCase):
    """Oversized resource parameters must be rejected fail-closed at dispatch."""

    def _assert_capped(self, tool: str, args: dict) -> None:
        res = dispatch_tool(tool, args)
        self.assertFalse(res.ok)
        self.assertIn("safety cap", res.error or "")

    def _assert_not_capped(self, tool: str, args: dict) -> None:
        res = dispatch_tool(tool, args)
        self.assertNotIn("safety cap", res.error or "")

    def test_plot_points_cap(self) -> None:
        self._assert_capped("math_plot", {"expression": "sin(x)", "points": 10**9})

    def test_plot_points_valid_not_capped(self) -> None:
        self._assert_not_capped("math_plot", {"expression": "sin(x)", "points": 101})

    def test_evaluate_precision_cap(self) -> None:
        self._assert_capped("math_evaluate", {"expression": "pi", "precision": 10**9})

    def test_evaluate_precision_valid(self) -> None:
        res = dispatch_tool("math_evaluate", {"expression": "1/4", "precision": 50})
        self.assertTrue(res.ok)

    def test_evaluate_precision_none_still_works(self) -> None:
        res = dispatch_tool("math_evaluate", {"expression": "1/4"})
        self.assertTrue(res.ok)

    def test_differentiate_order_cap(self) -> None:
        self._assert_capped("math_differentiate", {"expression": "x^3", "order": 10**9})

    def test_differentiate_order_valid(self) -> None:
        res = dispatch_tool("math_differentiate", {"expression": "x^3", "order": 2})
        self.assertTrue(res.ok)

    def test_explore_samples_cap(self) -> None:
        self._assert_capped("math_explore", {"expression": "x^3 - 3*x", "samples": 10**9})

    def test_explore_samples_valid_not_capped(self) -> None:
        self._assert_not_capped("math_explore", {"expression": "x^3 - 3*x", "samples": 7})

    def test_search_mathlib_max_results_cap(self) -> None:
        self._assert_capped(
            "math_search_mathlib", {"query": "binomial square", "max_results": 10**9}
        )

    def test_search_mathlib_max_results_valid(self) -> None:
        res = dispatch_tool(
            "math_search_mathlib", {"query": "binomial square", "max_results": 8}
        )
        self.assertTrue(res.ok)

    def test_search_literature_max_results_cap(self) -> None:
        self._assert_capped(
            "math_search_literature", {"query": "zeta", "max_results": 10**9}
        )

    def test_search_literature_max_results_valid_not_capped(self) -> None:
        self._assert_not_capped(
            "math_search_literature",
            {"query": "zeta", "max_results": 8, "online": False},
        )


class TestStdioServerGuards(unittest.TestCase):
    """End-to-end guards against a real `python -m axiom.mcp_server` subprocess."""

    @staticmethod
    def _tools_list(req_id: int) -> str:
        return json.dumps({"jsonrpc": "2.0", "id": req_id, "method": "tools/list"})

    def test_rate_limit_denies_flood(self) -> None:
        requests = "\n".join(self._tools_list(i) for i in range(1, 13)) + "\n"
        proc = subprocess.run(
            [sys.executable, "-m", "axiom.mcp_server"],
            input=requests,
            capture_output=True,
            text=True,
            timeout=60,
            env=_child_env(AXIOM_MCP_RATE_LIMIT="1", AXIOM_MCP_RATE_LIMIT_BURST="1"),
        )
        self.assertEqual(proc.returncode, 0)
        responses = [json.loads(ln) for ln in proc.stdout.splitlines() if ln.strip()]
        self.assertEqual(len(responses), 12)
        denied = [r for r in responses if r.get("error", {}).get("code") == -32000]
        self.assertGreaterEqual(len(denied), 1)

    def test_oversized_message_rejected_and_server_keeps_serving(self) -> None:
        oversized = (
            '{"jsonrpc": "2.0", "id": 99, "method": "tools/list", '
            '"params": {"pad": "' + "a" * 2048 + '"}}'
        )
        requests = (
            self._tools_list(1)
            + "\n"
            + oversized
            + "\n"
            + self._tools_list(2)
            + "\n"
        )
        proc = subprocess.run(
            [sys.executable, "-m", "axiom.mcp_server"],
            input=requests,
            capture_output=True,
            text=True,
            timeout=60,
            env=_child_env(AXIOM_MCP_MAX_MESSAGE_BYTES="1024"),
        )
        self.assertEqual(proc.returncode, 0)
        responses = [json.loads(ln) for ln in proc.stdout.splitlines() if ln.strip()]
        self.assertEqual(len(responses), 3)
        self.assertNotIn("error", responses[0])
        self.assertEqual(responses[1].get("error", {}).get("code"), -32600)
        self.assertNotIn("error", responses[2])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
