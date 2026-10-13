"""The guard that keeps the test suite off the network must itself work."""

from __future__ import annotations

import socket

import pytest


def test_a_connection_to_a_public_address_is_refused_before_it_leaves() -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client,
        pytest.raises(AssertionError, match="loopback only"),
    ):
        client.connect(("93.184.216.34", 80))


def test_a_loopback_connection_is_permitted() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect(server.getsockname())
