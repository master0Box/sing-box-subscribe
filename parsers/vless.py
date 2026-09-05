import tool
import re
from urllib.parse import urlparse, parse_qs, unquote


# ============================================================
# VLESS -> sing-box parser
#
# Target:
#   Official sing-box Android / Google Play 1.14.0
#
# Important:
#   Official upstream sing-box did NOT have XHTTP in the normal
#   upstream build at the time this parser was written.
#   Therefore XHTTP is NOT silently converted to HTTP.
#
#   If a future/third-party core explicitly supports:
#       "transport": {"type": "xhttp", ...}
#   set ENABLE_XHTTP = True.
# ============================================================

ENABLE_XHTTP = False


def _value(query, key, default=None):
    """Return a normalized scalar value from parse_qs output."""
    value = query.get(key, default)
    if isinstance(value, list):
        return value[0] if value else default
    return value


def _clean(value):
    if value is None:
        return None
    value = str(value).strip()
    if value.lower() in ("", "none", "null"):
        return None
    return value


def _as_list(value):
    """Parse comma/pipe separated values, preserving an existing list."""
    if value is None:
        return None
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    value = str(value)
    return [x.strip() for x in re.split(r"[,|]", value) if x.strip()]


def _parse_server(netloc):
    """
    Parse:
        uuid@host:port
        uuid@[IPv6]:port

    Return (uuid, server, port), or None.
    """
    if "@" not in netloc:
        return None

    uuid, address = netloc.rsplit("@", 1)
    uuid = uuid.strip()
    if not uuid:
        return None

    address = address.strip()

    # [IPv6]:port
    if address.startswith("["):
        match = re.match(r"^\[([^\]]+)\]:(\d+)$", address)
        if not match:
            return None
        server = match.group(1)
        server_port = int(match.group(2))
    else:
        # Normal hostname/IPv4:port
        match = re.match(r"^(.+):(\d+)$", address)
        if not match:
            return None
        server = match.group(1)
        server_port = int(match.group(2))

    if not 1 <= server_port <= 65535:
        return None

    return uuid, server, server_port


def _add_packet_encoding(node, query):
    """
    Xray/Mihomo:
        packetEncoding=none
        packetEncoding=xudp
        packetEncoding=packetaddr

    sing-box:
        ""           = disabled
        xudp
        packetaddr

    Do NOT omit an explicit `none`, because omission means the
    sing-box default rather than an explicit disabled value.
    """
    packet_encoding = _clean(_value(query, "packetEncoding"))

    if packet_encoding is None:
        return

    packet_encoding = packet_encoding.lower()

    if packet_encoding in ("none", "disabled"):
        node["packet_encoding"] = ""
    elif packet_encoding in ("xudp", "packetaddr"):
        node["packet_encoding"] = packet_encoding


def _add_flow(node, query):
    """
    Preserve the actual VLESS flow instead of assuming that every
    non-empty flow means Vision.
    """
    flow = _clean(_value(query, "flow"))
    if flow:
        node["flow"] = flow


def _add_tls(node, query):
    security = (_clean(_value(query, "security")) or "").lower()
    tls_flag = str(_value(query, "tls", "")).lower()

    tls_enabled = (
        security not in ("", "none", "false", "0")
        or tls_flag in ("1", "true", "yes")
    )

    if not tls_enabled:
        return

    tls = {
        "enabled": True,
        "insecure": str(_value(query, "allowInsecure", "0")).lower()
        in ("1", "true", "yes")
    }

    server_name = _clean(
        _value(query, "sni", _value(query, "peer", None))
    )
    if server_name:
        tls["server_name"] = server_name

    # ALPN belongs inside TLS, not transport.
    alpn = _as_list(_value(query, "alpn"))
    if alpn:
        tls["alpn"] = alpn

    # Reality
    public_key = _clean(_value(query, "pbk"))
    short_id = _clean(_value(query, "sid"))

    if security == "reality" or public_key:
        if public_key:
            reality = {
                "enabled": True,
                "public_key": public_key
            }
            if short_id:
                reality["short_id"] = short_id
            tls["reality"] = reality

        # Do not invent uTLS if the source did not provide fp.
        fingerprint = _clean(_value(query, "fp"))
        if fingerprint:
            tls["utls"] = {
                "enabled": True,
                "fingerprint": fingerprint
            }

    node["tls"] = tls


def _add_ws_transport(node, query):
    path = _value(query, "path", "/") or "/"
    host = _clean(_value(query, "host"))

    # Xray early-data notation: /path?ed=xxx
    matches = re.search(r"\?ed=(\d+)$", path)
    clean_path = path.rsplit("?ed=", 1)[0] if matches else path

    transport = {
        "type": "ws",
        "path": clean_path
    }

    if host:
        transport["headers"] = {"Host": host}

        if node.get("tls") and not node["tls"].get("server_name"):
            node["tls"]["server_name"] = host

    if matches:
        transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
        transport["max_early_data"] = int(matches.group(1))

    node["transport"] = transport


def _add_transport(node, query):
    """
    Return False only when the source transport cannot be represented
    safely for the selected target.
    """
    network = (_clean(_value(query, "type")) or "").lower()

    if network in ("xhttp", "splithttp"):
        if not ENABLE_XHTTP:
            # Never downgrade XHTTP to HTTP.
            # They are different wire protocols.
            return False

        transport = {
            "type": "xhttp"
        }

        path = _clean(_value(query, "path"))
        host = _clean(_value(query, "host"))
        mode = _clean(_value(query, "mode"))

        if path:
            transport["path"] = path
        if host:
            transport["host"] = host
        if mode:
            transport["mode"] = mode

        node["transport"] = transport
        return True

    if network in ("http", "h2"):
        transport = {
            "type": "http"
        }

        host = _as_list(_value(query, "host"))
        path = _clean(_value(query, "path"))
        method = _clean(_value(query, "method"))

        if host:
            transport["host"] = host
        if path:
            transport["path"] = path
        if method:
            transport["method"] = method

        node["transport"] = transport
        return True

    if network == "ws":
        _add_ws_transport(node, query)
        return True

    if network == "grpc":
        transport = {
            "type": "grpc"
        }

        service_name = _clean(_value(query, "serviceName"))
        if service_name:
            transport["service_name"] = service_name

        node["transport"] = transport
        return True

    return True


def _add_obfs_websocket(node, query):
    path = _value(query, "path", "/") or "/"
    matches = re.search(r"\?ed=(\d+)$", path)

    transport = {
        "type": "ws",
        "path": path.rsplit("?ed=", 1)[0] if matches else path
    }

    host = _clean(
        _value(
            query,
            "peer",
            _value(query, "obfsParam", _value(query, "sni"))
        )
    )

    if host:
        transport["headers"] = {"Host": host}
        if node.get("tls") and not node["tls"].get("server_name"):
            node["tls"]["server_name"] = host

    if matches:
        transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
        transport["max_early_data"] = int(matches.group(1))

    node["transport"] = transport


def _add_multiplex(node, query):
    protocol = _clean(_value(query, "protocol"))
    if protocol not in ("smux", "yamux", "h2mux"):
        return

    multiplex = {
        "enabled": True,
        "protocol": protocol
    }

    max_streams = _clean(_value(query, "max-streams"))
    max_connections = _clean(_value(query, "max-connections"))
    min_streams = _clean(_value(query, "min-streams"))

    if max_streams:
        try:
            multiplex["max_streams"] = int(max_streams)
        except ValueError:
            pass

    if max_connections:
        try:
            multiplex["max_connections"] = int(max_connections)
        except ValueError:
            pass

    if min_streams:
        try:
            multiplex["min_streams"] = int(min_streams)
        except ValueError:
            pass

    padding = _clean(_value(query, "padding"))
    if padding and padding.lower() == "true":
        multiplex["padding"] = True

    node["multiplex"] = multiplex


def parse(data):
    info = data[:]
    server_info = urlparse(info)

    # Some subscriptions base64-encode uuid@host:port.
    try:
        netloc = tool.b64Decode(server_info.netloc).decode("utf-8")
    except Exception:
        netloc = server_info.netloc

    parsed_server = _parse_server(netloc)
    if not parsed_server:
        return None

    uuid, server, server_port = parsed_server

    netquery = {
        key: value if len(value) > 1 else value[0]
        for key, value in parse_qs(
            server_info.query,
            keep_blank_values=True
        ).items()
    }

    remarks = _value(netquery, "remarks", server_info.fragment)

    node = {
        "tag": unquote(remarks) if remarks else tool.genName() + "_vless",
        "type": "vless",
        "server": server,
        "server_port": server_port,
        "uuid": uuid
    }

    # VLESS packet encoding
    _add_packet_encoding(node, netquery)

    # Preserve actual flow value.
    _add_flow(node, netquery)

    # TLS / Reality / uTLS / ALPN
    _add_tls(node, netquery)

    # V2Ray transport
    if _value(netquery, "type"):
        if not _add_transport(node, netquery):
            # XHTTP cannot be safely represented by official upstream
            # sing-box 1.14.0, so do not generate a broken node.
            return None
    elif (_clean(_value(netquery, "obfs")) or "").lower() == "websocket":
        _add_obfs_websocket(node, netquery)

    # Multiplex
    _add_multiplex(node, netquery)

    return node
