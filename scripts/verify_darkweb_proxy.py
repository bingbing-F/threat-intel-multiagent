"""Verify the dark-web source can reach the configured SOCKS proxy.

Safe-by-design: this only reads config, checks the SOCKS endpoint is listening,
and (if a whitelist URL is set) does a read-only GET through the proxy. It never
discovers new addresses and stops if the proxy is missing (fail-closed).
"""
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config_loader import get_settings
from src.sources.dark_web_source import DarkWebSource


def main() -> None:
    settings = get_settings()
    dw = settings.get("darkweb", {})
    proxy = dw.get("proxy", {})

    print("== DarkWeb config (from settings.yaml) ==")
    print(f"enabled          : {dw.get('enabled', False)}")
    print(f"proxy            : {proxy.get('type', 'socks5h')}://{proxy.get('host', '')}:{proxy.get('port', '')}")
    print(f"whitelist        : {dw.get('whitelist', [])}")
    print(f"keywords         : {dw.get('keywords', [])}")
    print()

    host = str(proxy.get("host", "")).strip()
    port = str(proxy.get("port", "") or "").strip()

    # 1) Proxy must be configured (fail-closed).
    if not dw.get("enabled", False):
        print("[SKIP] darkweb.enabled=false (default). Set enabled:true to proceed.")
        return
    if not (host and port):
        print("[FAIL] proxy host/port empty. Configure darkweb.proxy first.")
        return

    # 2) SOCKS endpoint must actually be listening (Tor Browser sits on 9150;
    #    standalone tor daemon on 9050).
    try:
        sock = socket.create_connection((host, int(port)), timeout=5)
        sock.close()
        print(f"[OK]   SOCKS proxy {host}:{port} is reachable.")
    except OSError as e:
        print(f"[FAIL] cannot reach SOCKS proxy {host}:{port}: {e}")
        print("       Is Tor Browser open and connected? Is the port correct?")
        return

    wl = [u for u in dw.get("whitelist", []) if u]
    if not wl:
        print("[SKIP] whitelist empty (refusing to fetch anything).")
        return

    # 3) Read-only fetch of the FIRST whitelist entry through the proxy.
    src = DarkWebSource(
        name="darkweb",
        enabled=True,
        whitelist=wl,
        keywords=dw.get("keywords", []),
        proxy_host=host,
        proxy_port=port,
        proxy_type=proxy.get("type", "socks5h"),
        max_capture_chars=dw.get("max_capture_chars", 2000),
        max_items=dw.get("max_items", 20),
        timeout=dw.get("timeout", 15),
    )
    items = src.fetch()
    print()
    print(f"[RESULT] {len(items)} item(s) captured from whitelist through proxy.")
    for it in items:
        print(f"   - {it.url}  ({len(it.content)} chars, tier={it.metadata['tier']})")


if __name__ == "__main__":
    main()