import ipaddress
import socket
from collections.abc import Collection
from urllib.parse import ParseResult
from urllib.parse import urlparse

import httpx


def is_public_ip(ip: str | int) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return not (
            obj.is_private
            or obj.is_loopback
            or obj.is_link_local
            or obj.is_multicast
            or obj.is_unspecified
        )
    except ValueError:  # pragma: no cover
        return False


def resolve_hostname_ips(hostname: str) -> list[str]:
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve hostname: {hostname}") from e

    ips = [info[4][0] for info in addr_info if info and info[4]]
    if not ips:
        raise ValueError(f"Could not resolve hostname: {hostname}")
    return ips


def format_host_for_url(host: str) -> str:
    """
    Format IP address for URL use (wrap IPv6 in brackets).
    """
    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.version == 6:
            return f"[{host}]"
        return host
    except ValueError:
        return host


def validate_outbound_http_url(
    url: str,
    *,
    allowed_schemes: Collection[str] = ("http", "https"),
    allowed_ports: Collection[int] | None = None,
    allow_internal: bool = False,
) -> ParseResult:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()

    if scheme not in allowed_schemes or not parsed.hostname:
        raise ValueError("Invalid URL scheme or hostname.")

    default_port = 443 if scheme == "https" else 80
    try:
        port = parsed.port or default_port
    except ValueError as e:
        raise ValueError("Invalid URL scheme or hostname.") from e

    if allowed_ports and port not in allowed_ports:
        raise ValueError("Destination port not permitted.")

    if not allow_internal:
        for ip_str in resolve_hostname_ips(parsed.hostname):
            if not is_public_ip(ip_str):
                raise ValueError(
                    f"Connection blocked: {parsed.hostname} resolves to a non-public address",
                )

    return parsed


def _rewrite_request_to_pinned_ip(
    request: httpx.Request,
    *,
    allow_internal: bool,
) -> httpx.Request:
    hostname = request.url.host

    if not hostname:
        raise httpx.ConnectError("No hostname in request URL")

    try:
        ips = resolve_hostname_ips(hostname)
    except ValueError as e:
        raise httpx.ConnectError(str(e)) from e

    if not allow_internal:
        for ip_str in ips:
            if not is_public_ip(ip_str):
                raise httpx.ConnectError(
                    f"Connection blocked: {hostname} resolves to a non-public address",
                )

    ip_str = ips[0]
    formatted_ip = format_host_for_url(ip_str)

    new_headers = httpx.Headers(request.headers)
    if "host" in new_headers:
        del new_headers["host"]
    host_header = format_host_for_url(hostname)
    default_port = 443 if request.url.scheme == "https" else 80
    if request.url.port and request.url.port != default_port:
        host_header = f"{host_header}:{request.url.port}"
    new_headers["Host"] = host_header
    new_url = request.url.copy_with(host=formatted_ip)

    rewritten_request = httpx.Request(
        method=request.method,
        url=new_url,
        headers=new_headers,
        content=request.stream,
        extensions=request.extensions,
    )
    rewritten_request.extensions["sni_hostname"] = hostname

    return rewritten_request


class PinnedHostHTTPTransport(httpx.HTTPTransport):
    """
    HTTP transport that resolves/validates hostnames per request and connects to
    a vetted IP while preserving the original Host header and TLS SNI hostname.
    """

    def __init__(
        self,
        *args,
        allow_internal: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.allow_internal = allow_internal

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        request = _rewrite_request_to_pinned_ip(
            request,
            allow_internal=self.allow_internal,
        )
        return super().handle_request(request)


class PinnedHostAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    """
    Async variant of PinnedHostHTTPTransport.
    """

    def __init__(
        self,
        *args,
        allow_internal: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.allow_internal = allow_internal

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        request = _rewrite_request_to_pinned_ip(
            request,
            allow_internal=self.allow_internal,
        )
        return await super().handle_async_request(request)


def _validate_and_resolve_allow_internal(
    url: str,
    *,
    allowed_schemes: Collection[str],
    allowed_ports: Collection[int] | None,
    allow_internal: bool,
    defer_internal_check_to_transport: bool,
) -> bool:
    """Validate ``url`` against outbound policy and return the ``allow_internal``
    flag the pinned transport should enforce per request.

    The "is a non-public/internal address allowed" decision has two enforcement
    layers, normally driven by the same ``allow_internal`` value:

    * **upfront**, in ``validate_outbound_http_url`` — fails fast with ``ValueError``;
    * **per-request**, in the pinned transport — fails with ``httpx.ConnectError``.

    Set ``defer_internal_check_to_transport=True`` to skip *only* the upfront
    internal-address check (scheme and port are still validated) and let the
    transport be the sole enforcer. Webhooks use this so a blocked internal target
    surfaces as a retryable ``ConnectError`` rather than a ``ValueError``.

    This is the single chokepoint pairing URL validation with pinned-transport
    construction: code outside this module must use the ``make_pinned_*`` /
    ``create_pinned_*`` factories and must NOT construct ``PinnedHost*Transport``
    (or a plain ``httpx`` client) directly for a user-influenced URL.
    """
    validate_outbound_http_url(
        url,
        allowed_schemes=allowed_schemes,
        allowed_ports=allowed_ports,
        allow_internal=allow_internal or defer_internal_check_to_transport,
    )
    return allow_internal


def make_pinned_transport(
    url: str,
    *,
    allowed_schemes: Collection[str] = ("http", "https"),
    allowed_ports: Collection[int] | None = None,
    allow_internal: bool = False,
    defer_internal_check_to_transport: bool = False,
) -> PinnedHostHTTPTransport:
    """Validate ``url`` and return a sync pinned transport.

    See :func:`_validate_and_resolve_allow_internal` for ``allow_internal`` and
    ``defer_internal_check_to_transport``.
    """
    return PinnedHostHTTPTransport(
        allow_internal=_validate_and_resolve_allow_internal(
            url,
            allowed_schemes=allowed_schemes,
            allowed_ports=allowed_ports,
            allow_internal=allow_internal,
            defer_internal_check_to_transport=defer_internal_check_to_transport,
        ),
    )


def make_pinned_async_transport(
    url: str,
    *,
    allowed_schemes: Collection[str] = ("http", "https"),
    allowed_ports: Collection[int] | None = None,
    allow_internal: bool = False,
    defer_internal_check_to_transport: bool = False,
) -> PinnedHostAsyncHTTPTransport:
    """Async counterpart of :func:`make_pinned_transport`."""
    return PinnedHostAsyncHTTPTransport(
        allow_internal=_validate_and_resolve_allow_internal(
            url,
            allowed_schemes=allowed_schemes,
            allowed_ports=allowed_ports,
            allow_internal=allow_internal,
            defer_internal_check_to_transport=defer_internal_check_to_transport,
        ),
    )


def create_pinned_httpx_client(
    url: str,
    *,
    allow_internal: bool = False,
    **kwargs,
) -> httpx.Client:
    return httpx.Client(
        transport=make_pinned_transport(url, allow_internal=allow_internal),
        **kwargs,
    )


def create_pinned_async_httpx_client(
    url: str,
    *,
    allow_internal: bool = False,
    **kwargs,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=make_pinned_async_transport(url, allow_internal=allow_internal),
        **kwargs,
    )
