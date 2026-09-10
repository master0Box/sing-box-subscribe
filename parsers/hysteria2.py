import re
import ipaddress
import hashlib
from urllib.parse import urlsplit, parse_qs, unquote


# ============================================================
# Hysteria2 URI -> sing-box 1.14.0
#
# 支持：
#   hysteria2://
#   hy2://
#
# 支持：
#   host:443
#   host
#   host:1234,5678,9012
#   host:20000-30000
#   host:1234,5000-6000,7044,8000-9000
#
# 兼容常见机场扩展：
#   auth
#   sni / peer
#   insecure / allowInsecure
#   alpn
#   obfs / obfs-password
#   upmbps / downmbps
#   mport
#
# sing-box 1.14.0：
#   server_ports 使用 "start:end" 格式
#   hop_interval
#   hop_interval_max
#   bbr_profile
#   brutal_debug
#   disable_chrome_parrot
# ============================================================


DEFAULT_PORT = 443

VALID_OBFS = {"salamander", "gecko"}
VALID_NETWORK = {"tcp", "udp"}
VALID_BBR_PROFILE = {"conservative", "standard", "aggressive"}


def _first(query, *keys, default=None):
    """
    从 parse_qs() 得到的 dict 中取第一个非空值。

    例如：
        ?sni=a&sni=b
    返回：
        a
    """
    for key in keys:
        values = query.get(key)

        if values is None:
            continue

        if isinstance(values, list):
            for value in values:
                if value is not None and str(value).strip() != "":
                    return str(value).strip()
        else:
            value = str(values).strip()
            if value:
                return value

    return default


def _all(query, *keys):
    """
    获取 query 参数的全部值，并展开逗号分隔形式。

    例如：
        alpn=h3&alpn=hq
    ->
        ["h3", "hq"]

    以及：
        alpn=h3,hq
    ->
        ["h3", "hq"]
    """
    result = []

    for key in keys:
        values = query.get(key)

        if values is None:
            continue

        if not isinstance(values, list):
            values = [values]

        for value in values:
            if value is None:
                continue

            value = str(value).strip()

            if not value:
                continue

            for item in value.split(","):
                item = item.strip()

                if item:
                    result.append(item)

    return result


def _parse_bool(value, default=False):
    """
    严格解析 boolean。

    支持：
        1 / true / yes / on
        0 / false / no / off

    未提供 -> default
    非法值 -> default
    """
    if value is None:
        return default

    value = str(value).strip().lower()

    if value in {"1", "true", "yes", "on"}:
        return True

    if value in {"0", "false", "no", "off"}:
        return False

    return default


def _parse_positive_int(value, field_name, minimum=1, maximum=None):
    """
    严格解析正整数。

    不再使用：
        re.search(r'\\d+', value)

    防止：
        100Mbps -> 100
        abc123 -> 123

    这种错误截断。
    """
    if value is None:
        return None

    value = str(value).strip()

    if not re.fullmatch(r"\d+", value):
        raise ValueError(
            f"Invalid {field_name}: {value!r}"
        )

    number = int(value)

    if number < minimum:
        raise ValueError(
            f"Invalid {field_name}: {number}"
        )

    if maximum is not None and number > maximum:
        raise ValueError(
            f"Invalid {field_name}: {number}"
        )

    return number


def _parse_bandwidth(value, field_name):
    """
    解析 upmbps / downmbps。

    这里要求最终值必须是 Mbps 整数。

    接受：
        100
        "100"

    不接受：
        100Mbps
        100.5
        abc100
    """
    if value is None:
        return None

    value = str(value).strip()

    if not re.fullmatch(r"\d+", value):
        raise ValueError(
            f"Invalid {field_name}: {value!r}; "
            f"expected an integer Mbps value"
        )

    number = int(value)

    if number < 0:
        raise ValueError(
            f"Invalid {field_name}: {number}"
        )

    return number


def _split_host_port(netloc):
    """
    从 URI netloc 中严格拆分：
        [userinfo@]host[:port-spec]

    返回：
        host
        port_spec

    port_spec 可以是：
        None
        443
        1234,5678,9012
        20000-30000
        1234,5000-6000
    """

    netloc = netloc.strip()

    if not netloc:
        raise ValueError("Missing Hysteria2 server address")

    # --------------------------------------------------------
    # userinfo
    # --------------------------------------------------------
    if "@" in netloc:
        # 必须使用最后一个 @。
        # @ 如果出现在密码中，正常 URI 应该进行 percent-encoding。
        userinfo, hostpart = netloc.rsplit("@", 1)
    else:
        userinfo = None
        hostpart = netloc

    if not hostpart:
        raise ValueError("Missing Hysteria2 server host")

    # --------------------------------------------------------
    # IPv6：
    #   [2001:db8::1]:443
    #   [2001:db8::1]
    # --------------------------------------------------------
    if hostpart.startswith("["):
        close = hostpart.find("]")

        if close == -1:
            raise ValueError(
                f"Invalid IPv6 server address: {hostpart!r}"
            )

        host = hostpart[1:close]

        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise ValueError(
                f"Invalid IPv6 server address: {host!r}"
            )

        remainder = hostpart[close + 1:]

        if not remainder:
            port_spec = None

        elif remainder.startswith(":"):
            port_spec = remainder[1:]

        else:
            raise ValueError(
                f"Invalid IPv6 server address: {hostpart!r}"
            )

        return (
            unquote(host),
            port_spec,
            userinfo
        )

    # --------------------------------------------------------
    # 普通 hostname / IPv4
    # --------------------------------------------------------

    # 未加 [] 的 IPv6 不允许直接作为 URI host。
    if hostpart.count(":") > 1:
        raise ValueError(
            "IPv6 address in Hysteria2 URI must be enclosed "
            "in brackets, e.g. [2001:db8::1]:443"
        )

    if ":" in hostpart:
        host, port_spec = hostpart.rsplit(":", 1)

        if not host:
            raise ValueError("Missing Hysteria2 server host")

    else:
        host = hostpart
        port_spec = None

    host = unquote(host).strip()

    if not host:
        raise ValueError("Missing Hysteria2 server host")

    return host, port_spec, userinfo


def _parse_port_spec(port_spec):
    """
    将 Hysteria2 官方 multi-port 格式：

        1234
        1234,5678,9012
        20000-30000
        1234,5000-6000,7044,8000-9000

    转换为 sing-box 1.14.0：

        单端口：
            server_port = 1234

        多端口 / 范围：
            server_ports = [
                "1234:1234",
                "5000:6000"
            ]

    sing-box 1.14.0 文档使用：
        "start:end"

    官方 Hysteria2 URI 则使用：
        "start-end"
    """

    if port_spec is None or not str(port_spec).strip():
        return DEFAULT_PORT, None

    port_spec = unquote(str(port_spec)).strip()

    parts = [
        item.strip()
        for item in port_spec.split(",")
        if item.strip()
    ]

    if not parts:
        return DEFAULT_PORT, None

    parsed = []

    for item in parts:

        # ----------------------------------------------------
        # 单端口
        # ----------------------------------------------------
        if re.fullmatch(r"\d+", item):

            port = int(item)

            if not 1 <= port <= 65535:
                raise ValueError(
                    f"Port out of range: {port}"
                )

            parsed.append((port, port))
            continue

        # ----------------------------------------------------
        # 端口范围
        #
        # 官方 URI：
        #   20000-30000
        # ----------------------------------------------------
        match = re.fullmatch(
            r"(\d+)\s*-\s*(\d+)",
            item
        )

        if not match:
            raise ValueError(
                f"Invalid Hysteria2 port specification: {item!r}"
            )

        start = int(match.group(1))
        end = int(match.group(2))

        if not 1 <= start <= 65535:
            raise ValueError(
                f"Port out of range: {start}"
            )

        if not 1 <= end <= 65535:
            raise ValueError(
                f"Port out of range: {end}"
            )

        if start > end:
            raise ValueError(
                f"Invalid port range: {start}-{end}"
            )

        parsed.append((start, end))

    # --------------------------------------------------------
    # 只有一个单端口：
    #
    #   server_port
    #
    # 不生成 server_ports。
    # --------------------------------------------------------
    if len(parsed) == 1 and parsed[0][0] == parsed[0][1]:
        return parsed[0][0], None

    # --------------------------------------------------------
    # 多端口 / 端口范围
    #
    # sing-box：
    #   server_ports: ["1234:1234", "5000:6000"]
    # --------------------------------------------------------
    server_ports = [
        f"{start}:{end}"
        for start, end in parsed
    ]

    return None, server_ports


def _get_auth(userinfo, query):
    """
    Hysteria2 URI 的 auth 位于 userinfo。

    特别注意：

        hysteria2://username:password@example.com

    官方 Hysteria2 userpass 模式的实际 auth 是：

        username:password

    因此不能简单使用：
        parsed.password

    而应该保留整个 userinfo。

    同时兼容部分机场使用：
        ?auth=xxx
    """

    query_auth = _first(query, "auth")

    if query_auth is not None:
        return unquote(query_auth)

    if userinfo is None:
        return ""

    return unquote(userinfo)


def _parse_alpn(query):
    """
    解析 ALPN。

    默认：
        h3

    支持：
        ?alpn=h3
        ?alpn=h3,hq
        ?alpn=h3&alpn=hq
    """

    values = _all(query, "alpn")

    if not values:
        return ["h3"]

    # 去重，同时保持用户原来的顺序。
    result = []

    for value in values:
        if value not in result:
            result.append(value)

    return result


def _parse_obfs(query):
    """
    Hysteria2 1.14.0：

        salamander
        gecko

    如果 obfs 存在但 password 缺失：
        不再 KeyError。

    这里选择严格拒绝，而不是生成一个肯定无法工作的配置。
    """

    obfs_type = _first(query, "obfs")

    if not obfs_type:
        return None

    obfs_type = obfs_type.strip().lower()

    if obfs_type == "none":
        return None

    if obfs_type not in VALID_OBFS:
        raise ValueError(
            f"Unsupported Hysteria2 obfs type: {obfs_type!r}"
        )

    obfs_password = _first(
        query,
        "obfs-password",
        "obfs_password"
    )

    if obfs_password is None:
        raise ValueError(
            f"Hysteria2 obfs={obfs_type!r} "
            f"requires obfs-password"
        )

    obfs_password = unquote(obfs_password)

    if not obfs_password:
        raise ValueError(
            "Hysteria2 obfs-password must not be empty"
        )

    obfs = {
        "type": obfs_type,
        "password": obfs_password,
    }

    # sing-box 1.14.0 Gecko 专用参数。
    min_packet_size = _first(
        query,
        "obfs-min-packet-size",
        "obfs_min_packet_size"
    )

    max_packet_size = _first(
        query,
        "obfs-max-packet-size",
        "obfs_max_packet_size"
    )

    if min_packet_size is not None:

        if obfs_type != "gecko":
            raise ValueError(
                "obfs-min-packet-size is only valid "
                "for gecko"
            )

        obfs["min_packet_size"] = _parse_positive_int(
            min_packet_size,
            "obfs-min-packet-size",
            1,
            65535
        )

    if max_packet_size is not None:

        if obfs_type != "gecko":
            raise ValueError(
                "obfs-max-packet-size is only valid "
                "for gecko"
            )

        obfs["max_packet_size"] = _parse_positive_int(
            max_packet_size,
            "obfs-max-packet-size",
            1,
            65535
        )

    if (
        "min_packet_size" in obfs
        and "max_packet_size" in obfs
        and obfs["min_packet_size"] > obfs["max_packet_size"]
    ):
        raise ValueError(
            "obfs min_packet_size cannot be greater "
            "than max_packet_size"
        )

    return obfs


def _parse_network(query):
    """
    兼容：
        network=tcp
        network=udp

    如果没有指定，不输出 network。
    sing-box 默认启用两者。
    """

    network = _first(query, "network")

    if not network:
        return None

    network = network.lower()

    if network not in VALID_NETWORK:
        raise ValueError(
            f"Invalid Hysteria2 network: {network!r}"
        )

    return network


def _parse_optional_duration(
    query,
    *keys
):
    """
    duration 参数不自行解释单位。

    例如：
        30s
        1m
        500ms

    交给 sing-box 解析。
    """

    value = _first(query, *keys)

    if value is None:
        return None

    value = value.strip()

    if not value:
        return None

    # 防止把任意垃圾字符串写进 sing-box。
    if not re.fullmatch(
        r"(?:0|[1-9]\d*)(?:ns|us|µs|ms|s|m|h)",
        value
    ):
        raise ValueError(
            f"Invalid duration for {keys[0]}: {value!r}"
        )

    return value


def parse(data):
    """
    Hysteria2 URI -> sing-box 1.14.0 outbound
    """

    if not isinstance(data, str):
        raise ValueError(
            "Hysteria2 URI must be a string"
        )

    data = data.strip()

    if not data:
        raise ValueError(
            "Empty Hysteria2 URI"
        )

    # --------------------------------------------------------
    # URI scheme
    # --------------------------------------------------------
    parsed = urlsplit(data)

    if parsed.scheme.lower() not in {
        "hysteria2",
        "hy2"
    }:
        raise ValueError(
            f"Unsupported URI scheme: {parsed.scheme!r}"
        )

    if not parsed.netloc:
        raise ValueError(
            "Missing Hysteria2 server address"
        )

    # --------------------------------------------------------
    # query
    #
    # keep_blank_values=True：
    # 能正确识别：
    #   ?sni=
    # --------------------------------------------------------
    query = parse_qs(
        parsed.query,
        keep_blank_values=True
    )

    # --------------------------------------------------------
    # host / port
    # --------------------------------------------------------
    host, port_spec, userinfo = _split_host_port(
        parsed.netloc
    )

    server_port, server_ports = _parse_port_spec(
        port_spec
    )

    # --------------------------------------------------------
    # auth
    # --------------------------------------------------------
    password = _get_auth(
        userinfo,
        query
    )

    # --------------------------------------------------------
    # tag
    # --------------------------------------------------------
    tag = unquote(
        parsed.fragment
    ).strip()

    if not tag:
        # 不依赖外部 tool 模块，保证 parser 单独调用时也能工作；
        # 同一 URI 始终生成稳定 tag。
        digest = hashlib.sha256(data.encode("utf-8")).hexdigest()[:10]
        tag = f"Hysteria2_{digest}"

    # --------------------------------------------------------
    # TLS
    # --------------------------------------------------------
    tls = {
        "enabled": True,
        "insecure": False,
        "alpn": _parse_alpn(query),
    }

    # --------------------------------------------------------
    # SNI
    #
    # 官方 Hysteria2：
    # 如果没有指定 SNI，则可以从 server 推导。
    #
    # 因此：
    #   没有 SNI != insecure
    #
    # 绝对不能再：
    #   no SNI -> insecure=true
    # --------------------------------------------------------
    server_name = _first(
        query,
        "sni",
        "peer",
        "server_name"
    )

    if server_name:
        server_name = unquote(
            server_name
        ).strip()

        if server_name.lower() not in {
            "none",
            "null"
        }:
            tls["server_name"] = server_name

    # --------------------------------------------------------
    # insecure
    #
    # 只有订阅明确要求时才开启。
    # --------------------------------------------------------
    insecure_value = _first(
        query,
        "insecure",
        "allowInsecure",
        "allow_insecure"
    )

    tls["insecure"] = _parse_bool(
        insecure_value,
        default=False
    )

    # --------------------------------------------------------
    # ECH
    #
    # Hysteria2 URI 支持 ech。
    #
    # sing-box 1.14.0 也支持 outbound TLS ECH，
    # 但两者的 URI / 配置表示方式并非简单字符串直映射，
    # 因此这里不进行未经验证的强制转换。
    #
    # 这样比生成错误的 ECH 配置安全。
    # --------------------------------------------------------

    # --------------------------------------------------------
    # node
    # --------------------------------------------------------
    node = {
        "tag": tag,
        "type": "hysteria2",
        "server": host,
        "password": password,
        "tls": tls,
    }

    # --------------------------------------------------------
    # server_port / server_ports
    # 两者互斥。
    # --------------------------------------------------------
    if server_ports is not None:
        node["server_ports"] = server_ports
    else:
        node["server_port"] = server_port

    # --------------------------------------------------------
    # bandwidth
    #
    # 官方 Hysteria2 URI 本身不包含 bandwidth，
    # 这里继续兼容机场 / 转换器扩展。
    # --------------------------------------------------------
    up_mbps = _first(
        query,
        "upmbps",
        "up_mbps"
    )

    down_mbps = _first(
        query,
        "downmbps",
        "down_mbps"
    )

    if up_mbps is not None:
        value = _parse_bandwidth(
            up_mbps,
            "up_mbps"
        )

        node["up_mbps"] = value

    if down_mbps is not None:
        value = _parse_bandwidth(
            down_mbps,
            "down_mbps"
        )

        node["down_mbps"] = value

    # --------------------------------------------------------
    # mport
    #
    # 某些转换器不会把端口范围放进 host:port，
    # 而是：
    #
    #   ?mport=20000-30000
    #
    # 仅当 URI 本身没有多端口时才使用。
    # --------------------------------------------------------
    # mport 是某些转换器对端口跳跃的扩展表示。
    # 若 authority 中只有一个 fallback 端口，而 mport 给出了完整端口范围，
    # 必须使用 mport，否则会静默丢失端口跳跃。
    #
    # 若 authority 本身已经是多端口/范围，则 authority 优先。
    mport_values = _all(
        query,
        "mport"
    )

    if mport_values and server_ports is None:
        mport_spec = ",".join(mport_values)

        mport_port, mport_ports = _parse_port_spec(
            mport_spec
        )

        if mport_ports is not None:
            node["server_ports"] = mport_ports
            node.pop(
                "server_port",
                None
            )

        elif mport_port is not None:
            node["server_port"] = mport_port

    # --------------------------------------------------------
    # port hopping interval
    # sing-box 1.11+
    # --------------------------------------------------------
    hop_interval = _parse_optional_duration(
        query,
        "hop_interval",
        "hopInterval"
    )

    if hop_interval:
        node["hop_interval"] = hop_interval

    # --------------------------------------------------------
    # random port hopping upper bound
    # sing-box 1.14.0
    # --------------------------------------------------------
    hop_interval_max = _parse_optional_duration(
        query,
        "hop_interval_max",
        "hopIntervalMax",
        "maxHopInterval"
    )

    if hop_interval_max:
        node["hop_interval_max"] = hop_interval_max

    # --------------------------------------------------------
    # bbr_profile
    # sing-box 1.14.0
    # --------------------------------------------------------
    bbr_profile = _first(
        query,
        "bbr_profile",
        "bbrProfile"
    )

    if bbr_profile:

        bbr_profile = bbr_profile.lower()

        if bbr_profile not in VALID_BBR_PROFILE:
            raise ValueError(
                f"Invalid bbr_profile: {bbr_profile!r}"
            )

        node["bbr_profile"] = bbr_profile

    # --------------------------------------------------------
    # brutal_debug
    # sing-box 1.14.0
    # --------------------------------------------------------
    brutal_debug = _first(
        query,
        "brutal_debug",
        "brutalDebug"
    )

    if brutal_debug is not None:
        node["brutal_debug"] = _parse_bool(
            brutal_debug
        )

    # --------------------------------------------------------
    # disable_chrome_parrot
    # sing-box 1.14.0
    # --------------------------------------------------------
    disable_chrome_parrot = _first(
        query,
        "disable_chrome_parrot",
        "disableChromeParrot"
    )

    if disable_chrome_parrot is not None:
        node["disable_chrome_parrot"] = _parse_bool(
            disable_chrome_parrot
        )

    # --------------------------------------------------------
    # network
    # --------------------------------------------------------
    network = _parse_network(query)

    if network:
        node["network"] = network

    # --------------------------------------------------------
    # obfs
    # --------------------------------------------------------
    obfs = _parse_obfs(query)

    if obfs:
        node["obfs"] = obfs

    # --------------------------------------------------------
    # pinSHA256
    #
    # 注意：
    #
    # Hysteria2:
    #   pinSHA256 = 服务器证书 SHA-256 fingerprint
    #
    # sing-box:
    #   certificate_public_key_sha256 =
    #   服务器证书公钥 SHA-256
    #
    # 两者不是同一个东西。
    #
    # 因此绝不能错误地：
    #
    #   pinSHA256 -> certificate_public_key_sha256
    #
    # 否则会产生错误的证书 pin。
    #
    # 当前版本选择不转换，避免生成错误配置。
    # --------------------------------------------------------

    return node
