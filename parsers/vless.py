import tool
import re
from urllib.parse import urlparse, parse_qs, unquote


def _query_value(query, key, default=None):
    value = query.get(key, default)
    if isinstance(value, list):
        return value[0] if value else default
    return value


def _split_host(value):
    """Return a clean host string/list from Clash/Xray-style host query values."""
    if not value or value == "None":
        return None
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return None


def parse(data):
    info = data[:]
    server_info = urlparse(info)

    try:
        netloc = tool.b64Decode(server_info.netloc).decode("utf-8")
    except Exception:
        netloc = server_info.netloc

    _netloc = netloc.split("@", 1)
    if len(_netloc) != 2:
        return None

    # Parse server:port, including IPv6 literals.
    address = _netloc[1]
    if address.startswith("["):
        match = re.match(r"^\[([^\]]+)\]:(\d+)$", address)
        if not match:
            return None
        server = match.group(1)
        server_port = int(match.group(2))
    else:
        try:
            server, port_text = address.rsplit(":", 1)
        except ValueError:
            return None
        if not port_text.isdigit():
            return None
        server = server.strip("[]")
        server_port = int(port_text)

    netquery = {
        k: v if len(v) > 1 else v[0]
        for k, v in parse_qs(server_info.query, keep_blank_values=True).items()
    }

    remarks = _query_value(netquery, "remarks", server_info.fragment)

    node = {
        "tag": unquote(remarks) if remarks else tool.genName() + "_vless",
        "type": "vless",
        "server": server,
        "server_port": server_port,
        "uuid": _netloc[0].split(":", 1)[-1],
    }

    # sing-box packet_encoding accepts the actual encodings only.
    # "none" means disabled in source URLs and must NOT be emitted as
    # packet_encoding: "none" for the user's sing-box 1.14 client.
    packet_encoding = str(
        _query_value(netquery, "packetEncoding", "") or ""
    ).strip().lower()

    if packet_encoding in ("xudp", "packetaddr"):
        node["packet_encoding"] = packet_encoding

    # Only emit a VLESS flow that sing-box actually supports.
    flow = str(_query_value(netquery, "flow", "") or "").strip().lower()
    if flow == "xtls-rprx-vision":
        node["flow"] = "xtls-rprx-vision"

    # TLS / Reality.
    security = str(_query_value(netquery, "security", "") or "").strip().lower()
    tls_enabled = security not in ("", "none") or _query_value(netquery, "tls") == "1"

    if tls_enabled:
        tls = {
            "enabled": True,
            "insecure": _query_value(netquery, "allowInsecure") == "1",
        }

        server_name = _query_value(netquery, "sni", _query_value(netquery, "peer", ""))
        if server_name and server_name != "None":
            tls["server_name"] = server_name

        if security == "reality" or _query_value(netquery, "pbk"):
            public_key = _query_value(netquery, "pbk")
            if public_key:
                reality = {
                    "enabled": True,
                    "public_key": public_key,
                }

                sid = _query_value(netquery, "sid")
                if sid and str(sid).strip().lower() != "none":
                    reality["short_id"] = sid

                tls["reality"] = reality

                # uTLS is used when a fingerprint is supplied.
                fingerprint = _query_value(netquery, "fp")
                if fingerprint and str(fingerprint).strip().lower() != "none":
                    tls["utls"] = {
                        "enabled": True,
                        "fingerprint": fingerprint,
                    }

        # Clash's alpn is represented inside sing-box's TLS object.
        alpn = _query_value(netquery, "alpn")
        if alpn:
            if isinstance(alpn, str):
                alpn_list = [
                    item.strip()
                    for item in re.split(r"[,|]", alpn)
                    if item.strip()
                ]
            else:
                alpn_list = [str(item) for item in alpn if str(item).strip()]
            if alpn_list:
                tls["alpn"] = alpn_list

        node["tls"] = tls

    # Transport conversion.
    transport_type = str(_query_value(netquery, "type", "") or "").strip().lower()

    if transport_type in ("xhttp", "splithttp"):
        # Official upstream sing-box 1.14 does not provide XHTTP transport.
        # Do NOT silently convert XHTTP to ordinary HTTP: that changes the
        # wire protocol and produces a node that can be displayed but cannot
        # connect to an XHTTP server. Returning None lets the caller skip it.
        return None

    if transport_type in ("http", "h2"):
        transport = {"type": "http"}

        host_val = _split_host(_query_value(netquery, "host"))
        if host_val:
            transport["host"] = host_val

        path = _query_value(netquery, "path")
        if path:
            transport["path"] = path

        # Clash h2/http transport may specify a method.
        method = _query_value(netquery, "method")
        if method:
            transport["method"] = method

        node["transport"] = transport

    elif transport_type == "ws":
        path = _query_value(netquery, "path", "/") or "/"
        matches = re.search(r"\?ed=(\d+)$", path)

        node["transport"] = {
            "type": "ws",
            "path": path.rsplit("?ed=", 1)[0] if matches else path,
        }

        host_val = _query_value(
            netquery, "host", _query_value(netquery, "sni", "")
        )
        if host_val and host_val != "None":
            node["transport"]["headers"] = {"Host": host_val}
            if node.get("tls") and not node["tls"].get("server_name"):
                node["tls"]["server_name"] = host_val

        if matches:
            node["transport"]["early_data_header_name"] = "Sec-WebSocket-Protocol"
            node["transport"]["max_early_data"] = int(matches.group(1))

    elif transport_type == "grpc":
        node["transport"] = {
            "type": "grpc",
            "service_name": _query_value(netquery, "serviceName", "") or "",
        }

    elif _query_value(netquery, "obfs") == "websocket":
        path = _query_value(netquery, "path", "/") or "/"
        matches = re.search(r"\?ed=(\d+)$", path)

        node["transport"] = {
            "type": "ws",
            "path": path.rsplit("?ed=", 1)[0] if matches else path,
        }

        host_val = _query_value(
            netquery,
            "peer",
            _query_value(
                netquery,
                "obfsParam",
                _query_value(netquery, "sni", ""),
            ),
        )

        if host_val and host_val != "None":
            node["transport"]["headers"] = {"Host": host_val}
            if node.get("tls") and not node["tls"].get("server_name"):
                node["tls"]["server_name"] = host_val

        if matches:
            node["transport"]["early_data_header_name"] = "Sec-WebSocket-Protocol"
            node["transport"]["max_early_data"] = int(matches.group(1))

    # Multiplex conversion. Do not emit fields whose source value is absent.
    protocol = str(_query_value(netquery, "protocol", "") or "").lower()
    if protocol in ("smux", "yamux", "h2mux"):
        multiplex = {
            "enabled": True,
            "protocol": protocol,
        }

        max_streams = _query_value(netquery, "max-streams")
        max_connections = _query_value(netquery, "max-connections")
        min_streams = _query_value(netquery, "min-streams")

        if max_streams not in (None, ""):
            multiplex["max_streams"] = int(max_streams)
        else:
            if max_connections not in (None, ""):
                multiplex["max_connections"] = int(max_connections)
            if min_streams not in (None, ""):
                multiplex["min_streams"] = int(min_streams)

        if str(_query_value(netquery, "padding", "")).lower() == "true":
            multiplex["padding"] = True

        node["multiplex"] = multiplex

    # Do not emit empty TLS server_name.
    if node.get("tls") and not node["tls"].get("server_name"):
        node["tls"].pop("server_name", None)

    return node
