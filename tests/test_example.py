#!/usr/bin/env pytest -vs
"""Tests for example."""

import logging
import sys
from unittest.mock import patch

import pytest

import example

div_params = [
    (1, 1, 1),
    (2, 2, 1),
    (0, 1, 0),
    (8, 2, 4),
    pytest.param(0, 0, 0, marks=pytest.mark.xfail(raises=ZeroDivisionError)),
]

log_levels = (
    "debug",
    "info",
    "warning",
    "error",
    "critical",
    pytest.param("critical2", marks=pytest.mark.xfail),
)


def test_version(capsys):
    """Verify that version string sent to stdout, and agrees with the module."""
    with pytest.raises(SystemExit):
        with patch.object(sys, "argv", ["bogus", "--version"]):
            example.example.main()
    captured = capsys.readouterr()
    assert (
        captured.out == f"{example.__version__}\n"
    ), "standard output by '--version' should agree with module.__version__"


@pytest.mark.parametrize("level", log_levels)
def test_log_levels(level):
    """Validate commandline log-level arguments."""
    with patch.object(sys, "argv", ["bogus", f"--log-level={level}"]):
        with patch.object(logging.root, "handlers", []):
            assert (
                logging.root.hasHandlers() is False
            ), "root logger should not have handlers yet"
            return_code = example.example.main()
            assert (
                logging.root.hasHandlers() is True
            ), "root logger should now have a handler"
            assert return_code == 0, "main() should return success (0)"


@pytest.mark.parametrize("dividend, divisor, quotient", div_params)
def test_division(dividend, divisor, quotient):
    """Verify division results."""
    result = example.example_div(dividend, divisor)
    assert result == quotient, "result should equal quotient"  # nosec


def test_zero_division():
    """Verify that division by zero throws the correct exception."""
    with pytest.raises(ZeroDivisionError):
        example.example_div(1, 0)
