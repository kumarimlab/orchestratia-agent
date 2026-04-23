"""Shared TLS configuration for hub connections.

Centralises SSL-context construction so every outbound connection — HTTP
via httpx, WebSocket via websockets — respects the same verification
policy. Default is strict CA validation via the OS trust store (or the
certifi bundle as a fallback). The `insecure_tls` config knob disables
verification for dev hubs using self-signed certs; when set, a loud
warning is emitted so it's obvious the agent is in a non-hardened mode.

Policy precedence (highest first):
  1. Function arg `insecure` (explicit override from a caller)
  2. Environment variable ORCHESTRATIA_INSECURE_TLS=1
  3. DaemonState.config['insecure_tls'] (config.yaml key)
  4. Default: verified
"""

from __future__ import annotations

import logging
import os
import ssl
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from orchestratia_agent.main import DaemonState

log = logging.getLogger("orchestratia-agent")

_WARNING_EMITTED = False


def _env_opt_out() -> bool:
    """True if ORCHESTRATIA_INSECURE_TLS is set to a truthy value."""
    val = os.environ.get("ORCHESTRATIA_INSECURE_TLS", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def is_insecure(state: Optional["DaemonState"] = None, explicit: Optional[bool] = None) -> bool:
    """Resolve the effective insecure-TLS setting."""
    if explicit is not None:
        return bool(explicit)
    if _env_opt_out():
        return True
    if state is not None and isinstance(getattr(state, "config", None), dict):
        return bool(state.config.get("insecure_tls", False))
    return False


def build_ssl_context(
    state: Optional["DaemonState"] = None,
    explicit_insecure: Optional[bool] = None,
) -> ssl.SSLContext:
    """Return an SSL context for outbound hub connections.

    - Default (secure): ssl.create_default_context() — validates CA chain
      against the OS trust store and checks hostname. Honors the
      SSL_CERT_FILE / SSL_CERT_DIR env vars that admins set for custom
      CAs (e.g. corporate TLS-inspection proxies).
    - Insecure (opt-in): check_hostname=False + verify_mode=CERT_NONE.
      Emits a one-time warning at startup so operators can see the agent
      is running unprotected against MITM.
    """
    insecure = is_insecure(state=state, explicit=explicit_insecure)

    ctx = ssl.create_default_context()
    if insecure:
        _warn_once_insecure()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def httpx_verify(
    state: Optional["DaemonState"] = None,
    explicit_insecure: Optional[bool] = None,
):
    """Return the correct `verify=` argument for httpx clients.

    - Secure: True (use httpx's default, which matches ssl.create_default_context)
    - Insecure: False (disables verification)

    Using True/False here rather than the SSL context lets httpx use
    certifi by default on platforms where the system CA bundle is not
    in the expected location (older macOS, some Windows configs).
    """
    return not is_insecure(state=state, explicit=explicit_insecure)


def _warn_once_insecure() -> None:
    """Emit a loud, explicit warning the first time we go insecure."""
    global _WARNING_EMITTED
    if _WARNING_EMITTED:
        return
    _WARNING_EMITTED = True
    log.warning("=" * 60)
    log.warning("TLS certificate verification DISABLED (insecure_tls=true)")
    log.warning("  Any network attacker can intercept and modify agent")
    log.warning("  traffic, including the API key. Only use for local dev")
    log.warning("  hubs with self-signed certs.")
    log.warning("=" * 60)
