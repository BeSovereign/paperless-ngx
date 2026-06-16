from unittest import mock

import httpx
import pytest
from pytest_mock import MockerFixture

from paperless.network import PinnedHostHTTPTransport
from paperless.network import make_pinned_async_transport
from paperless.network import make_pinned_transport


def test_pinned_host_transport_blocks_internal_rebinding():
    transport = PinnedHostHTTPTransport(allow_internal=False)
    request = httpx.Request("GET", "http://example.com/test")

    with (
        mock.patch(
            "paperless.network.resolve_hostname_ips",
            return_value=["127.0.0.1"],
        ),
        pytest.raises(httpx.ConnectError, match="non-public address"),
    ):
        transport.handle_request(request)


def test_pinned_host_transport_rewrites_to_vetted_ip():
    transport = PinnedHostHTTPTransport(allow_internal=False)
    request = httpx.Request("GET", "https://example.com:8443/test")

    def assert_rewritten_request(
        self,
        rewritten_request,
    ):
        assert str(rewritten_request.url) == "https://93.184.216.34:8443/test"
        assert rewritten_request.headers["Host"] == "example.com:8443"
        assert rewritten_request.extensions["sni_hostname"] == "example.com"
        return httpx.Response(200, request=rewritten_request)

    with (
        mock.patch(
            "paperless.network.resolve_hostname_ips",
            return_value=["93.184.216.34"],
        ),
        mock.patch.object(
            httpx.HTTPTransport,
            "handle_request",
            autospec=True,
            side_effect=assert_rewritten_request,
        ),
    ):
        response = transport.handle_request(request)

    assert response.status_code == 200


class TestPinnedTransportFactories:
    """Covers only the chokepoint behavior the call-site tests can't reach.

    The sync reject and happy-path construction are already exercised end-to-end
    by ``test_get_llm_ollama`` and the ``*_blocks_internal_endpoint_when_disallowed``
    tests in ``test_client.py`` / ``test_embedding.py``, so they are not repeated
    here. What those can't reach: the *async* factory validating on its own (every
    real call site builds the sync transport first and raises before the async one),
    the ``defer_internal_check_to_transport`` webhook policy, and ``allowed_ports``
    forwarding.
    """

    def test_async_factory_validates_independently_of_sync(
        self,
        mocker: MockerFixture,
    ) -> None:
        mocker.patch(
            "paperless.network.resolve_hostname_ips",
            return_value=["10.0.0.1"],
        )
        with pytest.raises(ValueError, match="non-public address"):
            make_pinned_async_transport("http://internal.example/api")

    def test_defer_internal_check_skips_upfront_but_pins_transport(
        self,
        mocker: MockerFixture,
    ) -> None:
        # Webhook policy: the upfront internal-address check is skipped (no raise on
        # an internal IP), but the transport still pins with allow_internal=False so
        # the block happens at connect time as a ConnectError.
        mocker.patch(
            "paperless.network.resolve_hostname_ips",
            return_value=["10.0.0.1"],
        )
        transport = make_pinned_transport(
            "http://internal.example",
            allow_internal=False,
            defer_internal_check_to_transport=True,
        )
        assert transport.allow_internal is False

    def test_allowed_ports_enforced_before_construction(
        self,
        mocker: MockerFixture,
    ) -> None:
        mocker.patch(
            "paperless.network.resolve_hostname_ips",
            return_value=["93.184.216.34"],
        )
        with pytest.raises(ValueError, match="port not permitted"):
            make_pinned_transport("https://example.com:9999", allowed_ports={443})
