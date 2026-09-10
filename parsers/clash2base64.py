import base64
import json
import re
from urllib.parse import quote, unquote


def _is_true(value):
    """严格解析 Clash boolean，避免字符串 'false' 被当成 True。"""
    if value is True:
        return True
    if value is False or value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _quote_uri(value):
    """用于 URI userinfo/query/fragment 的完整 percent-encoding。"""
    return quote(str(value), safe="")


def _format_server(server):
    """为 IPv6 server 补上 URI 要求的方括号。"""
    server = str(server or "").strip()
    if ":" in server and not (server.startswith("[") and server.endswith("]")):
        return f"[{server}]"
    return server


def _first_port_from_spec(value):
    """从 Clash ports 规范中取得第一个端口，仅用于 authority fallback。"""
    text = str(value or "").strip()
    if not text:
        return None
    first = re.split(r"[,-]", text, maxsplit=1)[0].strip()
    if first.isdigit():
        port = int(first)
        if 1 <= port <= 65535:
            return port
    return None


def _format_alpn(value):
    """统一 Clash 的 ALPN list/string 表示。"""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        values = [str(x).strip() for x in value if str(x).strip()]
    else:
        values = [x.strip() for x in str(value).split(",") if x.strip()]
    # 保序去重
    return ",".join(dict.fromkeys(values))


def _format_port_list(value):
    """统一 ports 为字符串；不擅自改变端口范围语义。"""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ",".join(str(x).strip() for x in value if str(x).strip())
    return str(value).strip()


def _format_bandwidth(value):
    """将常见 Clash 带宽表示转换为 Hysteria2 URI 所需的整数 Mbps。"""
    if value is None or str(value).strip() == "":
        return ""
    if isinstance(value, bool):
        return ""
    text = str(value).strip().lower()
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(gbps|gbit|g|mbps|mbit|m|kbps|k)?", text)
    if not m:
        return ""
    number = float(m.group(1))
    unit = m.group(2) or "mbps"
    factor = {"gbps": 1000, "gbit": 1000, "g": 1000,
              "mbps": 1, "mbit": 1, "m": 1,
              "kbps": 0.001, "k": 0.001}[unit]
    mbps = number * factor
    if mbps < 0:
        return ""
    # Hysteria2 URI extension expects integer Mbps.
    return str(max(0, int(round(mbps))))

def clash2v2ray(original_share_link):
    share_link = original_share_link.copy()
    link = ''
    # 端口 fallback 只在确实没有 port 时使用。
    # Hysteria2 的完整 ports 会在专用分支中通过 mport 保留，不能在这里改写掉。
    if 'port' not in share_link and 'ports' in share_link:
        first_port = _first_port_from_spec(share_link.get('ports'))
        if first_port is not None:
            share_link['port'] = first_port
    if share_link['type'] == 'vmess':
        try:
            vmess_info = {
                "v": "2",
                "ps": share_link['name'].encode('utf-8', 'surrogatepass').decode('utf-8'),
                "add": share_link['server'],
                "port": share_link['port'],
                "id": share_link['uuid'],
                "aid": share_link['alterId'],
                "net": share_link.get('network', 'tcp'),
                "scy": share_link.get('cipher', 'auto'),
                "type": "none",
                "host": share_link.get('ws-opts', {}).get('headers', {}).get('Host', '') or share_link.get('ws-headers', {}).get('Host', ''),
                "path": share_link.get('ws-path', '') or share_link.get('ws-opts', {}).get('path', ''),
                "tls": ''
            }
            if share_link.get('skip-cert-verify') == False:
                vmess_info['verify_cert'] = False
            if share_link.get('tls') and share_link['tls'] != False:
                vmess_info['tls'] = 'tls'
                vmess_info["sni"] = share_link.get('servername', '')
            if vmess_info['net'] == 'grpc':
                vmess_info["type"] = share_link.get('grpc-opts', {}).get('grpc-mode')
                if share_link.get('grpc-opts', {}).get('grpc-service-name') != '/':
                    vmess_info["path"] = share_link.get('grpc-opts', {}).get('grpc-service-name')
                else:
                    vmess_info["path"] = ''
            elif vmess_info['net'] == 'h2':
                vmess_info['host'] = share_link.get('h2-opts', {}).get('host', [])
                vmess_info["path"] = share_link.get('h2-opts', {}).get('path', '')
            elif vmess_info['net'] == 'http':
                vmess_info["headers"] = share_link.get('http-opts', {}).get('headers', {})
                vmess_info["host"] = share_link.get('http-opts', {}).get('headers', {}).get('Host', [])
                vmess_info["path"] = share_link.get('http-opts', {}).get('path', [])
            if share_link.get('smux',{}).get('enabled', '') == True:
                vmess_info["protocol"] = share_link['smux']['protocol']
                vmess_info["max_connections"] = share_link['smux'].get('max-connections','')
                vmess_info["min_streams"] = share_link['smux'].get('min-streams','')
                vmess_info["max_streams"] = share_link['smux'].get('max-streams','')
                vmess_info["padding"] = share_link['smux'].get('padding','')

            vmess_json = json.dumps(vmess_info).encode('utf-8')
            vmess_base64 = base64.b64encode(vmess_json).decode('utf-8')
            link = f"vmess://{vmess_base64}"
            return link
        except:
            pass
        # TODO
    elif share_link['type'] == 'ss':
        ss_info = {
            "cipher": share_link['cipher'],
            "password": share_link['password'],
            "server": share_link['server'],
            "port": share_link['port'],
            "name": quote(share_link['name'], 'utf-8')
        }
        base_link = base64.b64encode("{cipher}:{password}".format(**ss_info).encode('utf-8')).decode('utf-8')
        if share_link.get('plugin'):
            ss_info["plugin"] = share_link['plugin']
            if share_link.get('plugin') == 'obfs' or share_link.get('plugin') == 'obfs-local':
                ss_info["mode"] = share_link['plugin-opts']['mode']
                ss_info["host"] = share_link['plugin-opts'].get('host', '')
                url_link = '?plugin=obfs-local%3Bobfs%3D{mode}%3Bobfs-host%3D{host}'.format(**ss_info)
            elif share_link.get('plugin') == 'v2ray-plugin':
                ss_info["obfs"] = share_link['plugin-opts']['mode']
                ss_info["obfs-host"] = share_link['plugin-opts'].get('host','')
                if share_link['plugin-opts'].get('path'):
                    ss_info["path"] = share_link['plugin-opts']['path']
                if share_link['plugin-opts'].get('headers'):
                    ss_info["headers"] = share_link['plugin-opts']['headers']
                if share_link['plugin-opts'].get('fingerprint'):
                    ss_info["fingerprint"] = share_link['plugin-opts']['fingerprint']
                if share_link['plugin-opts'].get('mux') == True:
                    ss_info["mux"] = True
                if share_link['plugin-opts'].get('skip-cert-verify') == True:
                    ss_info["skip-cert-verify"] = True
                if share_link['plugin-opts'].get('tls') == True:
                    ss_info["tls"] = True
                v2ray_plugin = {
                    "mode": ss_info.get("obfs", ""),
                    "host": ss_info.get("obfs-host", ""),
                    "path": ss_info.get("path", ""),
                    "headers": ss_info.get("headers", ""),
                    "fingerprint": ss_info.get("fingerprint", ""),
                    "mux": ss_info.get("mux", False),
                    "skip-cert-verify": ss_info.get("skip-cert-verify", ''),
                    "tls": ss_info.get("tls", ''),
                }
                v2ray_plugin = json.dumps(v2ray_plugin)
                url_link = f'?v2ray-plugin={base64.b64encode(v2ray_plugin.encode()).decode()}'
            elif share_link.get('plugin') == 'shadow-tls':
                ss_info["fingerprint"] = share_link.get("client-fingerprint", "")
                ss_info["shadowtls_password"] = share_link['plugin-opts']['password']
                ss_info["version"] = share_link['plugin-opts']['version']
                ss_info["host"] = share_link['plugin-opts']['host']
                shadowtls = f'{{"version": "{ss_info["version"]}", "host": "{ss_info["host"]}","password": "{ss_info["shadowtls_password"]}","fp": "{ss_info["fingerprint"]}"}}'
                url_link = f'?shadow-tls={base64.b64encode(shadowtls.encode()).decode()}'
            link = "ss://{base_link}@{server}:{port}{url_link}".format(base_link=base_link, url_link=url_link, **ss_info)
        else:
            link = "ss://{base_link}@{server}:{port}".format(base_link=base_link, **ss_info)
        if share_link.get('smux',{}).get('enabled', '') == True:
            ss_info["protocol"] = share_link['smux']['protocol']
            ss_info["max_connections"] = share_link['smux'].get('max-connections','')
            ss_info["min_streams"] = share_link['smux'].get('min-streams','')
            ss_info["max_streams"] = share_link['smux'].get('max-streams','')
            ss_info["padding"] = share_link['smux'].get('padding','')
            link += "&protocol={protocol}&max-connections={max_connections}&min-streams={min_streams}&max-streams={max_streams}&padding={padding}#{name}".format(**ss_info)
        elif share_link.get("udp-over-tcp") == True:
            link += "&uot=1#{name}".format(**ss_info)
        else:
            link += f"#{ss_info['name']}"
        return link
        # TODO
    elif share_link['type'] == 'ssr':
        ssr_info = {
            "server": share_link['server'],
            "port": share_link['port'],
            "protocol": share_link['protocol'],
            "cipher": share_link['cipher'],
            "obfs": share_link['obfs'],
            "password": base64.b64encode(share_link.get('password', '').encode('utf-8')).decode('utf-8'),
            "obfsparam": base64.b64encode(share_link.get('obfs-param').encode('utf-8')).decode('utf-8') if share_link.get('obfs-param') != None else '',
            "protoparam": base64.b64encode(share_link.get('protocol-param', '').encode('utf-8')).decode('utf-8'),
            "remarks": base64.b64encode(share_link.get('name', '').encode('utf-8')).decode('utf-8'),
            "group": base64.b64encode(share_link.get('group', '').encode('utf-8')).decode('utf-8')
        }
        base_link = base64.b64encode("{server}:{port}:{protocol}:{cipher}:{obfs}:{password}/?obfsparam={obfsparam}&protoparam={protoparam}&remarks={remarks}&group={group}".format(**ssr_info).encode('utf-8')).decode('utf-8')
        link = f"ssr://{base_link}"
        return link
        # TODO
    elif share_link['type'] == 'trojan':
        trojan_info = {
            "password": share_link['password'],
            "server": share_link['server'],
            "port": share_link['port'],
            "sni": share_link.get('sni', ''),
            "allowInsecure": '1' if share_link.get('skip-cert-verify') == True else '0',
            "type": share_link.get('network', 'tcp'),
            "fp": share_link.get('client-fingerprint', ''),
            "alpn": quote(','.join(share_link.get('alpn', '')), 'utf-8'),
            "name": quote(share_link['name'], 'utf-8')
        }
        if trojan_info['type'] == 'grpc':
            if share_link.get('grpc-opts', {}).get('grpc-service-name', '') not in ['none', '', '/']:
                trojan_info["serviceName"] = unquote(share_link.get('grpc-opts').get('grpc-service-name'))
            else:
                server_parts = share_link['server'].split('.')
                if len(server_parts) >= 2 and not server_parts[-2].isdigit():
                    trojan_info["serviceName"] = server_parts[-2]
                else:
                    trojan_info["serviceName"] = ''
            link = "trojan://{password}@{server}:{port}?sni={sni}&allowInsecure={allowInsecure}&type={type}&serviceName={serviceName}&fp={fp}&alpn={alpn}".format(**trojan_info)
        elif trojan_info['type'] == 'ws':
            if share_link.get('ws-opts'):
                trojan_info["path"] = quote(share_link['ws-opts'].get('path', ''), 'utf-8')
                trojan_info["host"] = share_link.get('ws-opts', {}).get('headers', {}).get('Host', '')
            else:
                trojan_info["path"] = ''
                trojan_info["host"] = trojan_info["sni"]
            link = "trojan://{password}@{server}:{port}?sni={sni}&allowInsecure={allowInsecure}&type={type}&host={host}&path={path}&fp={fp}&alpn={alpn}".format(**trojan_info)
        elif trojan_info['type'] == 'tcp':
            link = "trojan://{password}@{server}:{port}?sni={sni}&allowInsecure={allowInsecure}&type={type}&fp={fp}&alpn={alpn}".format(**trojan_info)
        if share_link.get('smux',{}).get('enabled', '') == True:
            trojan_info["protocol"] = share_link['smux']['protocol']
            trojan_info["max_connections"] = share_link['smux'].get('max-connections','')
            trojan_info["min_streams"] = share_link['smux'].get('min-streams','')
            trojan_info["max_streams"] = share_link['smux'].get('max-streams','')
            trojan_info["padding"] = share_link['smux'].get('padding','')
            link += "&protocol={protocol}&max-connections={max_connections}&min-streams={min_streams}&max-streams={max_streams}&padding={padding}#{name}".format(**trojan_info)
        else:
            link += f"#{trojan_info['name']}"
        return link
        # TODO
    elif share_link.get('type') == 'vless':
        """
        Clash/Mihomo VLESS -> VLESS share link.
    
        目标：
            vless.py -> sing-box 1.14.x
    
        原则：
            1. 不把 XHTTP 伪装成 HTTP/WS
            2. 保留 TLS / Reality / uTLS / ALPN / flow
            3. 保留 packet-encoding
            4. 正确编码 URI 参数
            5. IPv6 正确加 []
        """
    
        network = str(share_link.get('network', 'tcp') or 'tcp').lower()
    
        # sing-box 1.14.x 无 XHTTP transport。
        # 必须跳过，不能降级成 HTTP。
        if network in ('xhttp', 'splithttp'):
            return None
    
        # 本转换分支明确支持的网络类型。
        if network not in ('tcp', 'ws', 'grpc'):
            return None
    
        server = str(share_link.get('server', '')).strip()
        if not server:
            return None
    
        # IPv6：
        # 2001:db8::1 -> [2001:db8::1]
        if ':' in server and not server.startswith('['):
            uri_server = f'[{server}]'
        else:
            uri_server = server
    
        uuid = str(share_link.get('uuid', '')).strip()
        if not uuid:
            return None
    
        try:
            port = int(share_link.get('port'))
        except (TypeError, ValueError):
            return None
    
        if not 1 <= port <= 65535:
            return None
    
        # --------------------------------------------------------
        # TLS
        # --------------------------------------------------------
    
        tls_enabled = bool(share_link.get('tls'))
    
        if not tls_enabled:
            security = 'none'
        else:
            security = 'tls'
    
        reality_opts = share_link.get('reality-opts') or {}
    
        if reality_opts:
            public_key = str(
                reality_opts.get('public-key', '')
            ).strip()
    
            short_id = str(
                reality_opts.get('short-id', '')
            ).strip()
    
            if not public_key:
                return None
    
            if short_id and not re.fullmatch(
                r'[0-9a-fA-F]{0,8}',
                short_id
            ):
                return None
    
            security = 'reality'
    
        sni = (
            share_link.get('servername')
            or share_link.get('sni')
            or ''
        )
    
        fp = (
            share_link.get('client-fingerprint')
            or ''
        )
    
        flow = (
            share_link.get('flow')
            or ''
        )
    
        skip_cert_verify = (
            share_link.get('skip-cert-verify') is True
        )
    
        params = {
            'encryption': 'none',
            'security': security,
            'sni': str(sni),
            'fp': str(fp),
            'type': network,
            'flow': str(flow),
            'allowInsecure': '1' if skip_cert_verify else '0',
        }
    
        # --------------------------------------------------------
        # 保留 packet-encoding
        # --------------------------------------------------------
    
        packet_encoding = (
            share_link.get('packet-encoding')
            or share_link.get('packetEncoding')
            or ''
        )
    
        if packet_encoding:
            params['packetEncoding'] = str(packet_encoding)
    
        # --------------------------------------------------------
        # TLS ALPN
        # --------------------------------------------------------
    
        alpn = share_link.get('alpn')
    
        if alpn:
            params['alpn'] = alpn
    
        # --------------------------------------------------------
        # Reality
        # --------------------------------------------------------
    
        if reality_opts:
            params['pbk'] = public_key
    
            if short_id:
                params['sid'] = short_id
    
        # --------------------------------------------------------
        # WebSocket
        # --------------------------------------------------------
    
        if network == 'ws':
            ws_opts = share_link.get('ws-opts') or {}
    
            path = (
                ws_opts.get('path')
                or share_link.get('ws-path')
                or '/'
            )
    
            headers = ws_opts.get('headers') or {}
    
            # Clash/Mihomo HTTP Header 不保证一定使用 Host 大小写。
            host = ''
            for key, value in headers.items():
                if str(key).lower() == 'host':
                    host = str(value)
                    break
    
            params['path'] = path
    
            if host:
                params['host'] = host
    
        # --------------------------------------------------------
        # gRPC
        # --------------------------------------------------------
    
        elif network == 'grpc':
            grpc_opts = share_link.get('grpc-opts') or {}
    
            service_name = (
                grpc_opts.get('grpc-service-name')
                or ''
            )
    
            if service_name in ('/', ''):
                service_name = ''
    
            if service_name:
                params['serviceName'] = service_name
    
        # --------------------------------------------------------
        # TCP
        # --------------------------------------------------------
    
        elif network == 'tcp':
            pass
    
        # --------------------------------------------------------
        # 统一构造 Query
        # --------------------------------------------------------
    
        query = urlencode(
            params,
            doseq=True
        )
    
        # --------------------------------------------------------
        # Multiplex / SMUX
        # --------------------------------------------------------
    
        smux = share_link.get('smux') or {}
    
        link = (
            f'vless://'
            f'{quote(uuid, safe="")}@'
            f'{uri_server}:{port}?'
            f'{query}'
        )
    
        if smux.get('enabled') is True:
            smux_params = {
                'protocol': smux.get('protocol', ''),
                'max-connections': smux.get('max-connections', ''),
                'min-streams': smux.get('min-streams', ''),
                'max-streams': smux.get('max-streams', ''),
                'padding': smux.get('padding', ''),
            }
    
            smux_params = {
                key: value
                for key, value in smux_params.items()
                if value not in ('', None)
            }
    
            if smux_params:
                link += '&' + urlencode(smux_params)
    
        # Fragment 必须单独 URL encode。
        name = str(share_link.get('name', '') or '')
        link += '#' + quote(name, safe='')
    
        return link
        # TODO
    elif share_link['type'] == 'tuic':
        # 提取原始多端口
        mport = share_link.get('ports', '') 
        params = {
            "sni": share_link.get('sni', ''),
            "alpn": ','.join(share_link.get('alpn', [])),
            "allow_insecure": '1' if share_link.get('skip-cert-verify') else '0',
            "congestion_control": share_link.get('congestion-controller', 'bbr'),
            "udp_relay_mode": share_link.get('udp-relay-mode', 'native'),
            "mport": mport  # 将多端口注入 URI 查询参数
        }
        query_string = '&'.join([f"{k}={v}" for k, v in params.items() if v])
        link = f"tuic://{share_link['uuid']}:{share_link['password']}@{share_link['server']}:{share_link.get('port', 443)}?{query_string}#{share_link.get('name', '')}"
        return link
        # TODO
    elif share_link['type'] == 'hysteria':
        link = "hysteria://{server}:{port}?protocol={protocol}&auth={auth}&alpn={alpn}&insecure={allowInsecure}&peer={sni}&upmbps={upmbps}&downmbps={downmbps}&obfs={obfs}#{name}".format(
        server = share_link['server'],
        port = share_link['port'],
        protocol = share_link.get('protocol', 'udp'),
        auth = share_link.get('auth_str', share_link.get('auth-str')),
        alpn = quote(','.join(share_link.get('alpn', '')), 'utf-8'),
        allowInsecure = '0' if share_link.get('skip-cert-verify', '') == False else '1',
        sni = share_link.get('sni', ''),
        upmbps = int(re.search(r'\d+', str(share_link.get('up', '')))[0]),
        downmbps = int(re.search(r'\d+', str(share_link.get('down', '')))[0]),
        obfs = share_link.get('obfs', ''),
        name = share_link['name'].encode('utf-8', 'surrogatepass').decode('utf-8')
        )
        return link
        # TODO
    elif share_link['type'] == 'hysteria2':
        # ========================================================
        # Clash Hysteria2 -> 标准 Hysteria2 URI
        #
        # 设计目标：
        # 1. 保留完整 ports/mport，不让端口跳跃在中间层丢失；
        # 2. 正确处理 IPv6；
        # 3. 对 password / query / name 做 URI percent-encoding；
        # 4. 不把字符串 "false" 当成 True；
        # 5. 不输出无意义的 insecure=0；
        # 6. ALPN 同时兼容 list/string。
        # ========================================================

        server = _format_server(share_link.get('server'))
        if not server:
            raise ValueError("Hysteria2 server is missing")

        # Clash 中可能只有 ports，没有 port。
        base_port = share_link.get('port')
        if base_port in (None, ''):
            base_port = _first_port_from_spec(share_link.get('ports'))
        if base_port in (None, ''):
            base_port = 443

        try:
            base_port = int(str(base_port))
        except (TypeError, ValueError):
            base_port = 443

        if not 1 <= base_port <= 65535:
            raise ValueError(f"Invalid Hysteria2 port: {base_port}")

        ports = _format_port_list(share_link.get('ports'))

        query_params = []

        if _is_true(share_link.get('skip-cert-verify')):
            query_params.append(("insecure", "1"))

        obfs = str(share_link.get('obfs') or '').strip()
        if obfs and obfs.lower() != 'none':
            query_params.append(("obfs", obfs))
            obfs_password = share_link.get('obfs-password',
                                           share_link.get('obfs_password', ''))
            if obfs_password not in (None, ''):
                query_params.append(("obfs-password", obfs_password))

        # Hysteria2 URI 的 fingerprint 语义是 pinSHA256。
        # 下游 parser 会保留它，但不会错误映射成 sing-box public-key pin。
        pin_sha256 = share_link.get(
            'pinSHA256',
            share_link.get('pin-sha256',
                           share_link.get('fingerprint', ''))
        )
        if pin_sha256 not in (None, ''):
            query_params.append(("pinSHA256", pin_sha256))

        sni = share_link.get(
            'sni',
            share_link.get('servername',
                           share_link.get('server-name', ''))
        )
        if sni not in (None, ''):
            query_params.append(("sni", sni))

        alpn = _format_alpn(share_link.get('alpn'))
        if alpn:
            query_params.append(("alpn", alpn))

        # 使用扩展 mport 保持兼容；下游 hysteria2.py 会在需要时让
        # mport 覆盖 authority 中仅用于 fallback 的 base_port。
        if ports:
            query_params.append(("mport", ports))

        up_mbps = _format_bandwidth(
            share_link.get('upmbps', share_link.get('up'))
        )
        down_mbps = _format_bandwidth(
            share_link.get('downmbps', share_link.get('down'))
        )
        if up_mbps:
            query_params.append(("upmbps", up_mbps))
        if down_mbps:
            query_params.append(("downmbps", down_mbps))

        # 兼容部分机场直接下发的扩展参数。
        extra_keys = (
            ('hop_interval', ('hop_interval', 'hopInterval')),
            ('hop_interval_max', ('hop_interval_max', 'hopIntervalMax')),
            ('bbr_profile', ('bbr_profile', 'bbrProfile')),
            ('brutal_debug', ('brutal_debug', 'brutalDebug')),
            ('disable_chrome_parrot', ('disable_chrome_parrot', 'disableChromeParrot')),
            ('network', ('network',)),
            ('obfs-min-packet-size', ('obfs-min-packet-size', 'obfs_min_packet_size')),
            ('obfs-max-packet-size', ('obfs-max-packet-size', 'obfs_max_packet_size')),
        )

        for query_name, keys in extra_keys:
            value = None
            for key in keys:
                if share_link.get(key) not in (None, ''):
                    value = share_link.get(key)
                    break
            if value not in (None, ''):
                if query_name in {'brutal_debug', 'disable_chrome_parrot'}:
                    value = '1' if _is_true(value) else '0'
                query_params.append((query_name, value))

        query_string = '&'.join(
            f"{_quote_uri(key)}={_quote_uri(value)}"
            for key, value in query_params
            if value not in (None, '')
        )

        auth = share_link.get('password')
        if auth in (None, ''):
            auth = share_link.get('auth', '')
        auth = _quote_uri(auth) if auth not in (None, '') else ''

        name = share_link.get('name', 'Hysteria2_Node')
        name = _quote_uri(name)

        authority = f"{auth}@{server}:{base_port}" if auth else f"{server}:{base_port}"
        link = f"hysteria2://{authority}"
        if query_string:
            link += f"?{query_string}"
        link += f"#{name}"
        return link
        # TODO
    elif share_link['type'] == 'wireguard':
        warp_info = {
            "server": share_link['server'],
            "port": share_link['port'],
            "publicKey": share_link['public-key'],
            "privateKey": share_link['private-key'],
            "presharedKey": share_link.get('pre-shared-key', ''),
            "ip": share_link['ip'],
            "name": quote(share_link['name'], 'utf-8')
        }
        #warp_info['reserved'] = '0,0,0'
        if type(share_link.get('reserved')) == str:
            warp_info['reserved'] = share_link.get('reserved', '')
        else:
            if type(share_link.get('reserved')) != type(None):
                warp_info['reserved'] = ','.join(str(item) for item in share_link.get('reserved'))
        if share_link.get('ipv6'):
            warp_info['ipv6'] = share_link['ipv6']
            if warp_info.get('reserved'):
                link = "wg://{server}:{port}?publicKey={publicKey}&privateKey={privateKey}&presharedKey={presharedKey}&ip={ip},{ipv6}&udp=1&reserved={reserved}#{name}".format(**warp_info)
            else:
                link = "wg://{server}:{port}?publicKey={publicKey}&privateKey={privateKey}&presharedKey={presharedKey}&ip={ip},{ipv6}&udp=1#{name}".format(**warp_info)
        else:
            if warp_info.get('reserved'):
                link = "wg://{server}:{port}?publicKey={publicKey}&privateKey={privateKey}&presharedKey={presharedKey}&ip={ip}&udp=1&reserved={reserved}#{name}".format(**warp_info)
            else:
                link = "wg://{server}:{port}?publicKey={publicKey}&privateKey={privateKey}&presharedKey={presharedKey}&ip={ip}&udp=1#{name}".format(**warp_info)
        return link
        # TODO
    elif share_link['type'] == 'http':
        http_info = {
            "server": share_link['server'],
            "port": share_link['port'],
        }
        if share_link.get('username'):
            if share_link['password']:
                http_info ["user"] = share_link['username']
                http_info ["password"] = share_link['password']
                base_link = base64.b64encode("{user}:{password}@{server}:{port}".format(**http_info).encode('utf-8')).decode('utf-8')
        else:
            base_link = base64.b64encode("{server}:{port}".format(**http_info).encode('utf-8')).decode('utf-8')
        if share_link.get('sni'):
            base_link += f"&sni={share_link['sni']}"
        link = f"http://{base_link}"
        if share_link.get('name'):
            link += f"#{share_link['name']}"
        return link
        # TODO
    elif share_link['type'] == 'socks5':
        socks5_info = {
            "server": share_link['server'],
            "port": share_link['port'],
        }
        if share_link.get('username'):
            if share_link['password']:
                socks5_info ["user"] = share_link['username']
                socks5_info ["password"] = share_link['password']
                base_link = base64.b64encode("{user}:{password}@{server}:{port}".format(**socks5_info).encode('utf-8')).decode('utf-8')
        else:
            base_link = base64.b64encode("{server}:{port}".format(**socks5_info).encode('utf-8')).decode('utf-8')
        link = f"socks://{base_link}"
        if share_link.get('name'):
            link += f"#{share_link['name']}"
        return link
        # TODO
    elif share_link['type'] == 'anytls':
        link = "anytls://{auth}@{server}:{port}?idleSessionCheckInterval={idleSessionCheckInterval}&idleSessionTimeout={idleSessionTimeout}&minIdleSession={minIdleSession}&alpn={alpn}&fp={fp}&insecure={allowInsecure}&peer={sni}#{name}".format(
        server = share_link['server'],
        port = share_link['port'],
        auth = share_link['password'],
        idleSessionCheckInterval = share_link.get('idle-session-check-interval', ''),
        idleSessionTimeout = share_link.get('idle-session-timeout', ''),
        minIdleSession = share_link.get('min-idle-session', ''),
        alpn = quote(','.join(share_link.get('alpn', '')), 'utf-8'),
        fp = share_link.get('client-fingerprint', ''),
        allowInsecure = '1' if share_link.get('skip-cert-verify', '') == True else '0',
        sni = share_link.get('sni', ''),
        name = share_link['name'].encode('utf-8', 'surrogatepass').decode('utf-8')
        )
        return link
        # TODO
    return link
