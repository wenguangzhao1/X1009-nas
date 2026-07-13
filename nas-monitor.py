#!/usr/bin/env python3
"""NAS 监控仪表盘 — Raspberry Pi 5 NAS 实时监控 Web 页面

零依赖实现，纯 Python 标准库。
启动: python3 nas-monitor.py
安装为系统服务: python3 nas-monitor.py --install
"""

import json
import os
import platform
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler

# ── 配置 ──────────────────────────────────────────────────────────────────────
HOST = "0.0.0.0"
PORT = 8080
CACHE_TTL = 15  # SMART 数据缓存（秒）
DISK_DEVS = ["/dev/sda", "/dev/sdb", "/dev/sdc", "/dev/sdd"]
MOUNT_POINTS = ["/mnt/sda", "/mnt/sdb", "/mnt/sdc", "/mnt/sdd1", "/mnt/sdd5", "/mnt/sdd6", "/mnt/sdd7"]
SERVICES = ["sshd", "smbd", "nmbd"]
ACCESS_LOG_PATH = os.path.expanduser("~/.cache/nas-monitor/access.jsonl")
MAX_LOG_ENTRIES = 500  # 日志文件最大条目数
ACCESS_DISPLAY_COUNT = 30  # 仪表盘显示的最近条目数

# ── 数据缓存 ──────────────────────────────────────────────────────────────────
_cache = {"data": None, "timestamp": 0}
_cache_lock = threading.Lock()

# ── 访问日志 ──────────────────────────────────────────────────────────────────
_access_log_lock = threading.Lock()


def _ensure_log_dir():
    """确保日志目录存在"""
    log_dir = os.path.dirname(ACCESS_LOG_PATH)
    os.makedirs(log_dir, exist_ok=True)


def log_access(client_ip, method, path, status, user_agent, elapsed_ms):
    """写入访问日志（JSONL 格式）"""
    entry = {
        "t": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": client_ip,
        "m": method,
        "p": path,
        "s": status,
        "ua": user_agent[:120] if user_agent else "-",
        "ms": round(elapsed_ms, 1),
    }
    try:
        _ensure_log_dir()
        with _access_log_lock:
            with open(ACCESS_LOG_PATH, "a") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            # 检查是否需要轮转（超过 MAX_LOG_ENTRIES）
            _rotate_access_log()
    except Exception:
        pass


def _rotate_access_log():
    """轮转访问日志：保留最近 MAX_LOG_ENTRIES 条"""
    try:
        if not os.path.exists(ACCESS_LOG_PATH):
            return
        # 只检查行数，避免每次都读大文件
        with open(ACCESS_LOG_PATH) as f:
            lines = f.readlines()
        if len(lines) > MAX_LOG_ENTRIES:
            kept = lines[-MAX_LOG_ENTRIES:]
            with open(ACCESS_LOG_PATH, "w") as f:
                f.writelines(kept)
    except Exception:
        pass


def get_access_log_entries(count=None):
    """读取最近的访问日志条目"""
    if count is None:
        count = ACCESS_DISPLAY_COUNT
    try:
        with _access_log_lock:
            if not os.path.exists(ACCESS_LOG_PATH):
                return []
            with open(ACCESS_LOG_PATH) as f:
                lines = f.readlines()
        entries = []
        for line in lines[-count * 2:]:  # 多读一些，过滤空行
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        # 返回最近 N 条
        return entries[-count:]
    except Exception:
        return []


# ── Samba 审计日志 ────────────────────────────────────────────────────────────

SAMBA_AUDIT_MAX = 50  # 仪表盘显示的最近审计条目数


def get_samba_access_log():
    """从 systemd journal 读取 Samba 审计日志（PAM session + full_audit）"""
    entries = []
    try:
        # 读取最近 24 小时的 smbd journal 条目（默认格式含时间戳）
        out = run_cmd([
            "journalctl", "-u", "smbd", "--no-pager",
            "--since", "24 hours ago",
        ], sudo=True)
        if not out:
            return []

        for line in out.split("\n"):
            line = line.strip()
            if not line:
                continue

            # PAM session events
            m = re.match(
                r"^(\w+\s+\d+\s+[\d:]+)\s+\S+\s+smbd\[\d+\]:\s+pam_unix\(samba:session\): session (opened|closed) for user (\w+)(?:\(uid=(\d+)\))?",
                line,
            )
            if m:
                ts_raw, event, user, uid = m.groups()
                ts = parse_journal_timestamp(ts_raw)
                detail = f"用户 {user} 已{'连接' if event == 'opened' else '断开'}"
                if uid:
                    detail += f" (uid={uid})"
                entries.append({
                    "t": ts,
                    "type": "samba_session",
                    "ip": None,
                    "user": user,
                    "share": None,
                    "op": "connect" if event == "opened" else "disconnect",
                    "detail": detail,
                })
                continue

            # full_audit events
            # Format: msj|192.168.0.105|192.168.0.103|hostname|share: flag=..., access=...: OP: /path: ...
            m2 = re.match(
                r"^(\w+\s+\d+\s+[\d:]+)\s+\S+\s+smbd\[\d+\]:\s+"
                r"([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^:]+):\s+"
                r"(flag=[^,]+,\s+access=[^:]+):\s+"
                r"(\S+):\s+(/\S*)\s*:\s*(.*)",
                line,
            )
            if m2:
                ts_raw, user, client_ip, server_ip, hostname, share, flag_access, op, path, detail = m2.groups()
                ts = parse_journal_timestamp(ts_raw)
                # Filter noise: skip routine internal operations
                if op in ("SMB2_CLOSE",):
                    # Only log meaningful close events (not just directory handles)
                    if path == "/" or not path:
                        continue
                # Filter open/read/close noise
                if op == "SMB2_OPEN" and path.endswith("/"):
                    continue
                if op in ("SMB2_READ", "SMB2_WRITE") and len(path) < 3:
                    continue
                entries.append({
                    "t": ts,
                    "type": "samba_audit",
                    "ip": client_ip,
                    "user": user,
                    "share": share,
                    "op": op,
                    "path": path,
                    "detail": f"{op}: {path}" if path else f"{op}",
                })
                continue

        # 只保留最近 N 条
        entries = entries[-SAMBA_AUDIT_MAX:]
        # 按时间排序
        entries.sort(key=lambda e: e.get("t", ""))
        return entries
    except Exception:
        return []


def parse_journal_timestamp(ts_raw):
    """解析 journal 时间戳为可读格式"""
    try:
        # e.g. "Jul 13 15:35:23"
        now = datetime.now()
        dt = datetime.strptime(f"{now.year} {ts_raw}", "%Y %b %d %H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return ts_raw


def get_samba_connections():
    """获取当前活跃的 Samba 连接"""
    connections = []
    try:
        out = run_cmd([
            "journalctl", "-u", "smbd", "--no-pager",
            "--since", "2 hours ago",
        ], sudo=True)
        if not out:
            return []

        # Find the most recent session opened/closed for each user
        active_sessions = {}
        for line in out.split("\n"):
            line = line.strip()
            m = re.match(
                r"^(\w+\s+\d+\s+[\d:]+)\s+\S+\s+smbd\[\d+\]:\s+pam_unix\(samba:session\): session (opened|closed) for user (\w+)(?:\(uid=(\d+)\))?",
                line,
            )
            if m:
                ts_raw, event, user, uid = m.groups()
                if event == "opened":
                    active_sessions[user] = True
                else:
                    active_sessions[user] = False

        connections = [user for user, active in active_sessions.items() if active]
        return connections
    except Exception:
        return []


def run_cmd(cmd, sudo=False):
    """执行命令并返回 stdout"""
    full_cmd = ["sudo"] + cmd if sudo else cmd
    try:
        r = subprocess.run(full_cmd, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception:
        return ""


def run_cmd_json(cmd, sudo=False):
    """执行命令并返回 JSON"""
    out = run_cmd(cmd, sudo=sudo)
    try:
        return json.loads(out) if out else {}
    except json.JSONDecodeError:
        return {}


# ── 数据采集函数 ──────────────────────────────────────────────────────────────

def get_system_info():
    """获取系统基本信息"""
    uptime_raw = run_cmd(["cat", "/proc/uptime"])
    uptime_sec = float(uptime_raw.split()[0]) if uptime_raw else 0

    loadavg_raw = run_cmd(["cat", "/proc/loadavg"])
    loads = loadavg_raw.split()[:3] if loadavg_raw else ["0", "0", "0"]

    return {
        "hostname": platform.node(),
        "kernel": platform.release(),
        "os": f"Debian 13 (trixie)",
        "uptime_seconds": int(uptime_sec),
        "uptime_human": format_duration(uptime_sec),
        "load_1": loads[0],
        "load_5": loads[1],
        "load_15": loads[2],
    }


def get_cpu_info():
    """获取 CPU 温度和节流状态"""
    temp_raw = run_cmd(["vcgencmd", "measure_temp"])
    temp_match = re.search(r"temp=([\d.]+)", temp_raw) if temp_raw else None
    temp_c = float(temp_match.group(1)) if temp_match else None

    throttled_raw = run_cmd(["vcgencmd", "get_throttled"])
    throttled_val = "0x0"
    throttled_match = re.search(r"throttled=(0x[0-9a-fA-F]+)", throttled_raw)
    if throttled_match:
        throttled_val = throttled_match.group(1)

    # 解析节流标志
    throttle_flags = parse_throttled(throttled_val)

    return {
        "temperature_c": temp_c,
        "throttled": throttled_val,
        "throttle_flags": throttle_flags,
        "is_throttling": throttled_val != "0x0",
    }


def get_hat_info():
    """获取 X1009 扩展板信息"""
    hat = {
        "model": "Geekworm X1009 V1.1",
        "chip": "JMicron JMB585",
        "interface": "PCIe v2.0 x1",
        "sata_ports": 5,
        "power": "12V DC",
        "hat_standby": True,
    }

    # PCIe 链路状态
    pcie_path = "/sys/bus/pci/devices/0001:01:00.0"
    link_speed = ""
    link_width = ""
    try:
        speed_file = os.path.join(pcie_path, "current_link_speed")
        if os.path.exists(speed_file):
            with open(speed_file) as f:
                link_speed = f.read().strip()
        width_file = os.path.join(pcie_path, "current_link_width")
        if os.path.exists(width_file):
            with open(width_file) as f:
                link_width = f.read().strip()
        hat["pcie_link_speed"] = link_speed
        hat["pcie_link_width"] = link_width
        hat["pcie_link_ok"] = "GT/s" in link_speed and link_width != "0"
    except Exception:
        hat["pcie_link_speed"] = "N/A"
        hat["pcie_link_width"] = "N/A"
        hat["pcie_link_ok"] = False

    # JMB585 控制器驱动状态
    driver_path = os.path.join(pcie_path, "driver")
    hat["driver_loaded"] = os.path.islink(driver_path)
    try:
        driver_name = os.readlink(driver_path).split("/")[-1]
        hat["driver_name"] = driver_name
    except Exception:
        hat["driver_name"] = "unknown"

    # SATA 端口状态（解析 dmesg）
    dmesg_out = run_cmd(["dmesg"])
    sata_ports = []
    for i in range(1, 6):  # ata1-ata5
        port = {
            "port": i,
            "link_up": False,
            "sata_speed": None,
            "device": None,
        }
        # 匹配 dmesg 中的 SATA 链路信息
        for line in dmesg_out.split("\n"):
            m = re.match(
                rf"\[\s*\d+\.\d+\] ata{i}: SATA link (up|down) ([\d.]+ Gbps)",
                line
            )
            if m:
                port["link_up"] = m.group(1) == "up"
                port["sata_speed"] = m.group(2)
            # 匹配挂载设备
            dev_m = re.match(
                rf"\[\s*\d+\.\d+\] ata{i}\.\d+: ATA-\d+: (.+?),",
                line
            )
            if dev_m:
                port["device"] = dev_m.group(1)
        sata_ports.append(port)
    hat["sata_port_details"] = sata_ports
    hat["sata_port_count"] = len(sata_ports)

    # 活跃端口数
    hat["active_ports"] = sum(1 for p in sata_ports if p["link_up"])
    hat["down_ports"] = [p["port"] for p in sata_ports if not p["link_up"]]

    # 内核配置检查 (32-bit DMA)
    config_txt = ""
    for path in ["/boot/firmware/config.txt", "/boot/config.txt"]:
        if os.path.exists(path):
            with open(path) as f:
                config_txt = f.read()
            break
    hat["dma_fix_enabled"] = "pcie-32bit-dma-pi5" in config_txt

    # X1009 V1.1 不支持软件控制 LED（硬件 LED 指示灯）
    hat["led_control"] = False
    hat["led_description"] = "蓝色 LED — 电源/磁盘状态（硬件直连）"

    # 风扇控制（X1009 V1.1 需手动焊接，无内置 PWM）
    fan_overlays = ["i2c-pwm-fan", "gpio-fan"]
    hat["fan_configured"] = any(ov in config_txt for ov in fan_overlays)
    hat["fan_note"] = "V1.1 无内置风扇控制，需手动焊接 PWM 引脚"

    return hat


def get_memory_info():
    """获取内存信息"""
    out = run_cmd(["free", "-b"])
    lines = out.strip().split("\n") if out else []

    info = {"total": 0, "used": 0, "free": 0, "available": 0, "used_pct": 0}
    for line in lines:
        if line.startswith("Mem:"):
            parts = line.split()
            if len(parts) >= 7:
                info["total"] = int(parts[1])
                info["used"] = int(parts[2])
                info["free"] = int(parts[3])
                info["available"] = int(parts[6])
                info["used_pct"] = round(info["used"] / info["total"] * 100, 1) if info["total"] else 0
    return info


def get_swap_info():
    """获取 Swap 信息"""
    out = run_cmd(["free", "-b"])
    lines = out.strip().split("\n") if out else []

    info = {"total": 0, "used": 0, "used_pct": 0}
    for line in lines:
        if line.startswith("Swap:"):
            parts = line.split()
            if len(parts) >= 3:
                info["total"] = int(parts[1])
                info["used"] = int(parts[2])
                info["used_pct"] = round(info["used"] / info["total"] * 100, 1) if info["total"] else 0
    return info


def get_disk_usage():
    """获取磁盘使用情况"""
    out = run_cmd(["df", "-B1"] + MOUNT_POINTS)
    lines = out.strip().split("\n") if out else []

    disks = []
    for line in lines[1:]:  # 跳过 header
        parts = line.split()
        if len(parts) >= 6:
            total = int(parts[1])
            used = int(parts[2])
            avail = int(parts[3])
            pct_str = parts[4].rstrip("%")
            try:
                pct = float(pct_str)
            except ValueError:
                pct = 0
            disks.append({
                "mount": parts[5],
                "device": parts[0],
                "total": total,
                "used": used,
                "available": avail,
                "used_pct": pct,
            })
    return disks


def get_disk_health():
    """获取磁盘 SMART 健康数据"""
    disks = []
    for dev in DISK_DEVS:
        data = get_single_disk_health(dev)
        if data:
            disks.append(data)
    return disks


def get_single_disk_health(dev):
    """获取单块磁盘的 SMART 数据"""
    data = run_cmd_json(["smartctl", "-a", dev, "--json"], sudo=True)
    if not data:
        return None

    device = data.get("device", {})
    smart_status = data.get("smart_status", {})
    temperature = data.get("temperature", {})
    power_on = data.get("power_on_time", {})

    model = data.get("model_name", "未知")
    serial = data.get("serial_number", "")

    # 解析 SMART 属性
    attrs_table = data.get("ata_smart_attributes", {}).get("table", [])
    attrs = {}
    for a in attrs_table:
        attrs[a.get("name", "")] = {
            "id": a.get("id", 0),
            "value": a.get("value", 0),
            "worst": a.get("worst", 0),
            "raw_value": a.get("raw", {}).get("value", 0),
            "raw_string": a.get("raw", {}).get("string", ""),
            "thresh": a.get("thresh", 0),
            "failed": bool(a.get("when_failed", "")),
        }

    # 提取关键 SMART 属性
    key_attrs = {}
    key_names = [
        "Reallocated_Sector_Ct", "Current_Pending_Sector",
        "Offline_Uncorrectable", "Reported_Uncorrect",
        "UDMA_CRC_Error_Count", "Power_On_Hours",
        "Power_Cycle_Count", "Temperature_Celsius",
        "Raw_Read_Error_Rate", "Seek_Error_Rate",
        "Spin_Retry_Count", "Start_Stop_Count",
    ]
    for name in key_names:
        if name in attrs:
            a = attrs[name]
            key_attrs[name] = {
                "value": a["value"],
                "raw": a["raw_string"] or str(a["raw_value"]),
                "thresh": a["thresh"],
                "failed": a["failed"],
            }

    # 通电时间（优先用 power_on_time，其次 SMART Power_On_Hours）
    poh = power_on.get("hours", 0)
    if not poh and "Power_On_Hours" in key_attrs:
        try:
            poh = int(attrs["Power_On_Hours"]["raw_value"])
        except (ValueError, TypeError):
            pass

    # 温度
    temp = temperature.get("current", None)
    if temp is None and "Temperature_Celsius" in key_attrs:
        try:
            temp = int(attrs["Temperature_Celsius"]["raw_value"])
        except (ValueError, TypeError):
            pass

    # 健康评估
    health = evaluate_health(attrs, key_attrs, smart_status)

    return {
        "dev": dev,
        "model": model,
        "serial": serial,
        "health": health,
        "temperature_c": temp,
        "power_on_hours": poh,
        "smart_passed": smart_status.get("passed", True),
        "key_attributes": key_attrs,
    }


def evaluate_health(attrs, key_attrs, smart_status):
    """评估磁盘健康等级"""
    score = 100  # 满分 100

    # Reallocated_Sector_Ct
    rsc = key_attrs.get("Reallocated_Sector_Ct", {})
    rsc_raw = rsc.get("raw", "0")
    try:
        rsc_val = int(rsc_raw) if isinstance(rsc_raw, str) else rsc_raw
    except ValueError:
        rsc_val = 0
    if rsc_val > 0:
        score -= min(rsc_val * 0.1, 60)
    if rsc_val >= 100:
        score -= 20
    if rsc_val >= 400:
        score -= 20

    # Current_Pending_Sector
    cps = key_attrs.get("Current_Pending_Sector", {})
    cps_raw = cps.get("raw", "0")
    try:
        cps_val = int(cps_raw) if isinstance(cps_raw, str) else cps_raw
    except ValueError:
        cps_val = 0
    if cps_val > 0:
        score -= min(cps_val * 0.5, 30)

    # Reported_Uncorrect
    unc = key_attrs.get("Reported_Uncorrect", {})
    unc_raw = unc.get("raw", "0")
    try:
        unc_val = int(unc_raw) if isinstance(unc_raw, str) else unc_raw
    except ValueError:
        unc_val = 0
    if unc_val > 0:
        score -= min(unc_val * 0.01, 20)

    # UDMA_CRC_Error_Count
    crc = key_attrs.get("UDMA_CRC_Error_Count", {})
    crc_raw = crc.get("raw", "0")
    try:
        crc_val = int(crc_raw) if isinstance(crc_raw, str) else crc_raw
    except ValueError:
        crc_val = 0
    if crc_val > 10:
        score -= 15
    if crc_val > 100:
        score -= 15

    # SMART passed?
    if not smart_status.get("passed", True):
        score -= 30

    if score >= 80:
        return "healthy"
    elif score >= 50:
        return "warning"
    else:
        return "critical"


def get_services_status():
    """获取服务状态"""
    services = []
    for svc in SERVICES:
        active = run_cmd(["systemctl", "is-active", svc])
        uptime_out = run_cmd(["systemctl", "show", svc, "--property=ActiveEnterTimestamp"])
        started = ""
        if uptime_out:
            ts = uptime_out.split("=", 1)[-1].strip()
            if ts:
                try:
                    dt = datetime.strptime(ts, "%a %Y-%m-%d %H:%M:%S %Z")
                    started = dt.strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    started = ts
        services.append({
            "name": svc,
            "active": active == "active",
            "status": "running" if active == "active" else active,
            "started": started,
        })
    return services


def get_warnings(disk_health):
    """根据磁盘健康数据生成告警"""
    warnings = []
    for disk in disk_health:
        ka = disk.get("key_attributes", {})

        # sdd — 严重坏道
        rsc = ka.get("Reallocated_Sector_Ct", {}).get("raw", "0")
        try:
            rsc_val = int(rsc) if isinstance(rsc, str) else rsc
        except ValueError:
            rsc_val = 0
        if rsc_val > 0:
            severity = "critical" if rsc_val >= 100 else "warning"
            warnings.append({
                "severity": severity,
                "disk": disk["dev"],
                "title": f"{disk['dev']} 重分配扇区过多 ({rsc_val})",
                "detail": f"Reallocated_Sector_Ct = {rsc_val}，磁盘存在物理坏道。{'请立即备份数据并更换硬盘！' if severity == 'critical' else '建议密切关注并准备更换。'}",
            })

        # CRC 错误
        crc = ka.get("UDMA_CRC_Error_Count", {}).get("raw", "0")
        try:
            crc_val = int(crc) if isinstance(crc, str) else crc
        except ValueError:
            crc_val = 0
        if crc_val > 10:
            severity = "critical" if crc_val >= 100 else "warning"
            warnings.append({
                "severity": severity,
                "disk": disk["dev"],
                "title": f"{disk['dev']} SATA 线缆 CRC 错误 ({crc_val})",
                "detail": f"UDMA_CRC_Error_Count = {crc_val}，SATA 数据线或接口接触不良。建议更换 SATA 数据线。",
            })

        # 不可校正错误
        unc = ka.get("Reported_Uncorrect", {}).get("raw", "0")
        try:
            unc_val = int(unc) if isinstance(unc, str) else unc
        except ValueError:
            unc_val = 0
        if unc_val > 100:
            warnings.append({
                "severity": "critical",
                "disk": disk["dev"],
                "title": f"{disk['dev']} 大量不可校正错误 ({unc_val})",
                "detail": f"Reported_Uncorrect = {unc_val}，存在大量无法读取的数据块，数据可能已损坏。",
            })

        # 温度过高
        if disk.get("temperature_c", 0) > 55:
            warnings.append({
                "severity": "warning",
                "disk": disk["dev"],
                "title": f"{disk['dev']} 温度偏高 ({disk['temperature_c']}°C)",
                "detail": "磁盘温度超过 55°C，建议改善散热条件。",
            })

    # CPU 节流告警
    cpu = get_cpu_info()
    if cpu.get("is_throttling"):
        flags = cpu.get("throttle_flags", [])
        warnings.append({
            "severity": "warning",
            "disk": None,
            "title": f"CPU 节流已触发 ({cpu['throttled']})",
            "detail": f"触发原因: {', '.join(flags)}，CPU 已降频运行。",
        })

    return warnings


def parse_throttled(val):
    """解析 throttled 状态位"""
    try:
        v = int(val, 16)
    except ValueError:
        return []

    flags = [
        (0, "Currently throttled"),
        (1, "Frequency capped"),
        (2, "Currently temperature limited"),
        (16, "Previously throttled"),
        (17, "Frequency capped experience"),
        (18, "Temperature limit experience"),
    ]
    result = []
    for bit, desc in flags:
        if v & (1 << bit):
            result.append(desc)
    return result


def format_duration(seconds):
    """格式化运行时间"""
    seconds = int(seconds)
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    parts = []
    if days > 0:
        parts.append(f"{days} 天")
    if hours > 0:
        parts.append(f"{hours} 小时")
    if minutes > 0 or not parts:
        parts.append(f"{minutes} 分钟")
    return " ".join(parts)


def format_bytes(b):
    """格式化字节数"""
    if b >= 1_000_000_000_000:
        return f"{b / 1_000_000_000_000:.1f} TB"
    elif b >= 1_000_000_000:
        return f"{b / 1_000_000_000:.1f} GB"
    elif b >= 1_000_000:
        return f"{b / 1_000_000:.1f} MB"
    else:
        return f"{b / 1024:.1f} KB"


def usage_color(pct):
    """使用率进度条颜色"""
    if pct >= 90:
        return "var(--accent-red)"
    elif pct >= 70:
        return "var(--accent-orange)"
    return "var(--accent-green)"


def health_label(health):
    """健康等级标签"""
    labels = {
        "healthy": ("健康", "health-ok"),
        "warning": ("⚠️ 异常", "health-warn"),
        "critical": ("⛔ 严重", "health-danger"),
    }
    return labels.get(health, ("未知", "health-warn"))


def severity_class(severity):
    if severity == "critical":
        return "severity-critical"
    elif severity == "warning":
        return "severity-warning"
    return "severity-info"


# ── 缓存聚合 ──────────────────────────────────────────────────────────────────

def collect_status():
    """收集所有状态数据（带缓存）"""
    with _cache_lock:
        if _cache["data"] and time.time() - _cache["timestamp"] < CACHE_TTL:
            return _cache["data"]

    sys_info = get_system_info()
    cpu_info = get_cpu_info()
    mem_info = get_memory_info()
    swap_info = get_swap_info()
    disk_usage = get_disk_usage()
    disk_health = get_disk_health()
    services = get_services_status()
    warnings = get_warnings(disk_health)
    hat_info = get_hat_info()

    data = {
        "collected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "system": sys_info,
        "cpu": cpu_info,
        "memory": mem_info,
        "swap": swap_info,
        "disk_usage": disk_usage,
        "disk_health": disk_health,
        "services": services,
        "warnings": warnings,
        "hat": hat_info,
        "access_log": get_access_log_entries(),
        "samba_access_log": get_samba_access_log(),
        "samba_connections": get_samba_connections(),
    }

    with _cache_lock:
        _cache["data"] = data
        _cache["timestamp"] = time.time()

    return data


# ── HTTP 处理 ─────────────────────────────────────────────────────────────────

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NAS 监控仪表盘</title>
<style>
:root {
  --bg: #0f1117;
  --surface: #1a1d27;
  --border: #2a2d3a;
  --text: #e1e4ed;
  --text-dim: #8b8fa3;
  --accent-blue: #5b8def;
  --accent-green: #4ecb8d;
  --accent-orange: #f0a050;
  --accent-red: #e85d6a;
  --accent-purple: #a78bfa;
  --accent-cyan: #38d9d0;
  --accent-yellow: #f5d76e;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', system-ui, sans-serif;
  background: var(--bg);
  color: var(--text);
  padding: 24px 16px;
  min-height: 100vh;
}
h1 {
  text-align: center;
  font-size: 26px;
  font-weight: 700;
  margin-bottom: 6px;
  background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
.header-sub {
  text-align: center;
  color: var(--text-dim);
  font-size: 13px;
  margin-bottom: 8px;
}
.header-bar {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 16px;
  margin-bottom: 28px;
  flex-wrap: wrap;
}
.header-bar .updated { font-size: 12px; color: var(--text-dim); }
.header-bar .refresh-btn {
  background: var(--surface);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 6px 16px;
  border-radius: 8px;
  cursor: pointer;
  font-size: 13px;
  transition: all 0.2s;
}
.header-bar .refresh-btn:hover { border-color: var(--accent-blue); color: var(--accent-blue); }
.header-bar .refresh-btn:disabled { opacity: 0.4; cursor: wait; }

.grid {
  max-width: 1200px;
  margin: 0 auto;
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
  margin-bottom: 16px;
}
@media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }

.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 20px;
}
.card-title {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 1.5px;
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.card-title .dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  display: inline-block;
}

.stat-row {
  display: flex;
  justify-content: space-between;
  padding: 8px 0;
  border-bottom: 1px solid rgba(255,255,255,0.04);
  font-size: 13px;
}
.stat-row:last-child { border-bottom: none; }
.stat-label { color: var(--text-dim); }
.stat-value { font-weight: 600; font-family: 'SF Mono', 'Cascadia Code', monospace; font-size: 12px; }
.stat-value.highlight { color: var(--accent-cyan); }
.stat-value.warn { color: var(--accent-orange); }
.stat-value.danger { color: var(--accent-red); }

/* Progress bar */
.progress-bar {
  height: 6px;
  border-radius: 3px;
  background: rgba(255,255,255,0.08);
  margin-top: 8px;
  overflow: hidden;
}
.progress-fill {
  height: 100%;
  border-radius: 3px;
  transition: width 0.3s;
}

/* Disk card */
.disk-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--border);
}
.disk-model { font-weight: 600; font-size: 14px; }
.disk-serial { font-size: 11px; color: var(--text-dim); font-family: monospace; }
.disk-meta {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 6px;
  margin-bottom: 12px;
}
.disk-meta-item {
  background: rgba(255,255,255,0.03);
  border-radius: 6px;
  padding: 8px 10px;
  font-size: 12px;
}
.disk-meta-item .label { color: var(--text-dim); font-size: 10px; text-transform: uppercase; }
.disk-meta-item .val { font-weight: 600; margin-top: 2px; font-family: monospace; }

.disk-attrs { font-size: 12px; }
.disk-attr {
  display: flex;
  justify-content: space-between;
  padding: 5px 0;
  border-bottom: 1px solid rgba(255,255,255,0.03);
}
.disk-attr:last-child { border-bottom: none; }
.disk-attr .attr-name { color: var(--text-dim); }
.disk-attr .attr-val { font-family: monospace; font-weight: 600; }
.attr-bad { color: var(--accent-red); }
.attr-ok { color: var(--accent-green); }
.attr-warn { color: var(--accent-orange); }

/* Service item */
.svc-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 14px;
  background: rgba(255,255,255,0.03);
  border-radius: 8px;
  margin-bottom: 8px;
  font-size: 13px;
}
.svc-row:last-child { margin-bottom: 0; }
.svc-status {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
}
.svc-dot {
  width: 6px; height: 6px;
  border-radius: 50%;
}
.svc-dot.on { background: var(--accent-green); }
.svc-dot.off { background: var(--text-dim); }

/* Warning */
.warn-section {
  max-width: 1200px;
  margin: 0 auto;
}
.warn-card {
  border-radius: 12px;
  padding: 16px 20px;
  margin-bottom: 10px;
  display: flex;
  align-items: flex-start;
  gap: 12px;
}
.warn-card.critical {
  background: rgba(232,93,106,0.1);
  border: 1px solid rgba(232,93,106,0.3);
}
.warn-card.warning {
  background: rgba(240,160,80,0.08);
  border: 1px solid rgba(240,160,80,0.25);
}
.warn-icon { font-size: 18px; flex-shrink: 0; margin-top: 1px; }
.warn-title { font-weight: 600; font-size: 13px; margin-bottom: 4px; }
.warn-card.critical .warn-title { color: var(--accent-red); }
.warn-card.warning .warn-title { color: var(--accent-orange); }
.warn-desc { font-size: 12px; color: var(--text-dim); line-height: 1.5; }

.no-warn {
  text-align: center;
  padding: 24px;
  color: var(--accent-green);
  font-size: 14px;
  font-weight: 600;
}

/* Disk usage table */
.usage-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.usage-table th {
  text-align: left;
  padding: 8px 12px;
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-dim);
  border-bottom: 1px solid var(--border);
}
.usage-table td { padding: 8px 12px; border-bottom: 1px solid rgba(255,255,255,0.04); }
.usage-table .mount { font-weight: 600; }
.usage-table .bar-cell { min-width: 100px; }
.usage-bar-sm {
  height: 4px;
  border-radius: 2px;
  background: rgba(255,255,255,0.08);
  width: 100px;
  position: relative;
}
.usage-fill-sm {
  height: 100%;
  border-radius: 2px;
  position: absolute;
  left: 0; top: 0;
}

/* Health badge */
.badge {
  font-size: 10px;
  padding: 2px 8px;
  border-radius: 10px;
  font-weight: 600;
}
.badge-ok { background: rgba(78,203,141,0.2); color: var(--accent-green); }
.badge-warn { background: rgba(240,160,80,0.2); color: var(--accent-orange); }
.badge-danger { background: rgba(232,93,106,0.2); color: var(--accent-red); }

/* Full width card */
.full-width { grid-column: 1 / -1; }

/* Loading */
.loading { text-align: center; padding: 40px; color: var(--text-dim); }
.loading .spinner {
  display: inline-block;
  width: 24px; height: 24px;
  border: 3px solid var(--border);
  border-top-color: var(--accent-blue);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
  margin-bottom: 12px;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* Error */
.error-msg {
  text-align: center;
  padding: 40px;
  color: var(--accent-red);
  font-size: 14px;
}

/* Access log */
.access-log-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.access-log-table th {
  text-align: left;
  padding: 8px 10px;
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-dim);
  border-bottom: 1px solid var(--border);
}
.access-log-table td {
  padding: 6px 10px;
  border-bottom: 1px solid rgba(255,255,255,0.03);
  font-family: 'SF Mono', 'Cascadia Code', monospace;
  font-size: 11px;
}
.access-log-table tr:last-child td { border-bottom: none; }
.access-log-table .ip-cell { color: var(--accent-cyan); }
.access-log-table .path-cell { color: var(--text); }
.access-log-table .method-cell { color: var(--accent-purple); }
.access-log-table .ua-cell { color: var(--text-dim); max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.status-dot {
  display: inline-block;
  width: 6px; height: 6px;
  border-radius: 50%;
  margin-right: 4px;
  vertical-align: middle;
}
.status-dot.s2 { background: var(--accent-green); }
.status-dot.s3 { background: var(--accent-blue); }
.status-dot.s4 { background: var(--accent-orange); }
.status-dot.s5 { background: var(--accent-red); }
.access-log-empty { text-align: center; padding: 20px; color: var(--text-dim); font-size: 13px; }
</style>
</head>
<body>

<h1>NAS 监控仪表盘</h1>
<p class="header-sub">Raspberry Pi 5 Model B · Debian 13 · 4 盘位 SATA · Samba</p>
<div class="header-bar">
  <span class="updated" id="updated">加载中...</span>
  <button class="refresh-btn" id="refreshBtn" onclick="refreshData()">刷新</button>
  <span style="font-size:11px;color:var(--text-dim)">每 30 秒自动刷新</span>
</div>

<div id="content"><div class="loading"><div class="spinner"></div><br>正在加载监控数据...</div></div>

<script>
const CONTENT_EL = document.getElementById('content');
const UPDATED_EL = document.getElementById('updated');
const REFRESH_BTN = document.getElementById('refreshBtn');

function fmtBytes(b) {
  if (b >= 1e12) return (b / 1e12).toFixed(1) + ' TB';
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB';
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB';
  return (b / 1e3).toFixed(1) + ' KB';
}

function usageColor(pct) {
  if (pct >= 90) return 'var(--accent-red)';
  if (pct >= 70) return 'var(--accent-orange)';
  return 'var(--accent-green)';
}

function healthBadge(h) {
  if (h === 'healthy') return '<span class="badge badge-ok">健康</span>';
  if (h === 'warning') return '<span class="badge badge-warn">⚠️ 异常</span>';
  return '<span class="badge badge-danger">⛔ 严重</span>';
}

function attrClass(val, thresh) {
  if (!thresh) return 'attr-ok';
  return val < thresh ? 'attr-bad' : 'attr-ok';
}

function render(data) {
  const s = data.system;
  const c = data.cpu;
  const m = data.memory;
  const sw = data.swap;
  const du = data.disk_usage;
  const dh = data.disk_health;
  const svcs = data.services;
  const warns = data.warnings;
  const hat = data.hat;

  let html = '';

  // ── Row 1: System, Memory, Services ──
  html += '<div class="grid">';

  // System overview
  html += `<div class="card">
    <div class="card-title"><span class="dot" style="background:var(--accent-cyan)"></span> 系统概览</div>
    <div class="stat-row"><span class="stat-label">主机名</span><span class="stat-value highlight">${s.hostname}</span></div>
    <div class="stat-row"><span class="stat-label">操作系统</span><span class="stat-value">${s.os}</span></div>
    <div class="stat-row"><span class="stat-label">内核版本</span><span class="stat-value" style="font-size:11px">${s.kernel}</span></div>
    <div class="stat-row"><span class="stat-label">运行时间</span><span class="stat-value highlight">${s.uptime_human}</span></div>
    <div class="stat-row"><span class="stat-label">负载 (1/5/15)</span><span class="stat-value">${s.load_1} / ${s.load_5} / ${s.load_15}</span></div>
    <div class="stat-row"><span class="stat-label">CPU 温度</span><span class="stat-value ${c.temperature_c > 65 ? 'danger' : c.temperature_c > 55 ? 'warn' : ''}">${c.temperature_c !== null ? c.temperature_c + '°C' : 'N/A'}</span></div>
    <div class="stat-row"><span class="stat-label">节流状态</span><span class="stat-value ${c.is_throttling ? 'danger' : ''}">${c.is_throttling ? '⚠️ ' + c.throttled : '✅ 正常'}</span></div>
  </div>`;

  // Memory
  html += `<div class="card">
    <div class="card-title"><span class="dot" style="background:var(--accent-purple)"></span> 内存</div>
    <div class="stat-row"><span class="stat-label">总计</span><span class="stat-value">${fmtBytes(m.total)}</span></div>
    <div class="stat-row"><span class="stat-label">已用</span><span class="stat-value">${fmtBytes(m.used)}</span></div>
    <div class="stat-row"><span class="stat-label">可用</span><span class="stat-value">${fmtBytes(m.available)}</span></div>
    <div class="stat-row"><span class="stat-label">使用率</span><span class="stat-value ${m.used_pct > 80 ? 'warn' : ''}">${m.used_pct}%</span></div>
    <div class="progress-bar"><div class="progress-fill" style="width:${m.used_pct}%;background:${usageColor(m.used_pct)}"></div></div>
    <div style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
      <div class="stat-row"><span class="stat-label">Swap</span><span class="stat-value">${fmtBytes(sw.used)} / ${fmtBytes(sw.total)} (${sw.used_pct}%)</span></div>
      <div class="progress-bar"><div class="progress-fill" style="width:${sw.used_pct}%;background:var(--accent-blue)"></div></div>
    </div>
  </div>`;

  // Services
  html += `<div class="card">
    <div class="card-title"><span class="dot" style="background:var(--accent-green)"></span> 服务状态</div>`;
  for (svc of svcs) {
    html += `<div class="svc-row">
      <span>${svc.name}</span>
      <span class="svc-status"><span class="svc-dot ${svc.active ? 'on' : 'off'}"></span>${svc.active ? '运行中' : svc.status}</span>
    </div>`;
  }
  html += `</div></div>`;

  // ── Row 2: X1009 HAT ──
  const activePorts = hat.active_ports;
  const sataPorts = hat.sata_port_details;
  const sataPortRows = sataPorts.map(p => {
    const linkCls = p.link_up ? 'attr-ok' : 'attr-warn';
    const linkText = p.link_up ? '已连接' : '空闲';
    const speedText = p.sata_speed ? p.sata_speed : '—';
    const devText = p.device ? p.device : '—';
    return `<tr>
      <td style="font-family:monospace;font-size:12px">SATA ${p.port}</td>
      <td class="${linkCls}" style="font-weight:600">${p.link_up ? '●' : '○'} ${linkText}</td>
      <td style="font-family:monospace">${speedText}</td>
      <td style="font-size:11px;color:var(--text-dim)">${devText}</td>
    </tr>`;
  }).join('');

  const pcieOkClass = hat.pcie_link_ok ? 'attr-ok' : 'attr-warn';
  const dmaOkClass = hat.dma_fix_enabled ? 'attr-ok' : 'attr-warn';
  const driverOkClass = hat.driver_loaded ? 'attr-ok' : 'attr-warn';

  html += `<div class="grid"><div class="card full-width">
    <div class="card-title"><span class="dot" style="background:var(--accent-cyan)"></span> X1009 扩展板</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:16px">
      <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:12px">
        <div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;margin-bottom:4px">型号</div>
        <div style="font-weight:600;font-size:13px">${hat.model}</div>
      </div>
      <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:12px">
        <div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;margin-bottom:4px">主控芯片</div>
        <div style="font-weight:600;font-size:13px">${hat.chip}</div>
      </div>
      <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:12px">
        <div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;margin-bottom:4px">PCIe 链路</div>
        <div class="${pcieOkClass}" style="font-weight:600;font-size:13px">${hat.pcie_link_speed} ×${hat.pcie_link_width}</div>
      </div>
      <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:12px">
        <div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;margin-bottom:4px">SATA 活跃端口</div>
        <div style="font-weight:600;font-size:13px;color:${activePorts === hat.sata_port_count ? 'var(--accent-green)' : 'var(--accent-orange)'}">${activePorts} / ${hat.sata_port_count}</div>
      </div>
      <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:12px">
        <div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;margin-bottom:4px">驱动状态</div>
        <div class="${driverOkClass}" style="font-weight:600;font-size:13px">${hat.driver_name}</div>
      </div>
      <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:12px">
        <div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;margin-bottom:4px">DMA 修复</div>
        <div class="${dmaOkClass}" style="font-weight:600;font-size:13px">${hat.dma_fix_enabled ? '✅ 已启用' : '⚠️ 未启用'}</div>
      </div>
    </div>
    <table class="usage-table"><thead><tr>
      <th>端口</th><th>状态</th><th>SATA 速度</th><th>连接设备</th>
    </tr></thead><tbody>
      ${sataPortRows}
    </tbody></table>
    <div style="margin-top:12px;font-size:11px;color:var(--text-dim);display:flex;gap:20px;flex-wrap:wrap">
      <span>供电: ${hat.power}</span>
      <span>LED: ${hat.led_description}</span>
      <span>${hat.fan_note}</span>
      <span>HAT+ STANDBY: ${hat.hat_standby ? '✅ 支持' : '❌ 不支持'}</span>
    </div>
  </div></div>`;

  // ── Row 3: Disk Usage ──
  html += `<div class="grid"><div class="card full-width">
    <div class="card-title"><span class="dot" style="background:var(--accent-orange)"></span> 存储使用</div>
    <table class="usage-table"><thead><tr>
      <th>挂载点</th><th>设备</th><th>总容量</th><th>已用</th><th>可用</th><th>使用率</th><th class="bar-cell">进度</th>
    </tr></thead><tbody>`;
  for (d of du) {
    const pct = d.used_pct;
    const col = usageColor(pct);
    html += `<tr>
      <td class="mount">${d.mount}</td>
      <td style="font-family:monospace;font-size:11px;color:var(--text-dim)">${d.device}</td>
      <td>${fmtBytes(d.total)}</td>
      <td>${fmtBytes(d.used)}</td>
      <td>${fmtBytes(d.available)}</td>
      <td style="font-weight:600;color:${col}">${pct}%</td>
      <td class="bar-cell"><div class="usage-bar-sm"><div class="usage-fill-sm" style="width:${pct}%;background:${col}"></div></div></td>
    </tr>`;
  }
  html += `</tbody></table></div></div>`;

  // ── Row 4: Disk Health ──
  html += `<div class="grid">`;
  for (disk of dh) {
    html += `<div class="card">
      <div class="disk-header">
        <div>
          <div class="disk-model">${disk.model}</div>
          <div class="disk-serial">${disk.serial || 'N/A'}</div>
        </div>
        ${healthBadge(disk.health)}
      </div>
      <div class="disk-meta">
        <div class="disk-meta-item"><div class="label">温度</div><div class="val" style="color:${disk.temperature_c > 55 ? 'var(--accent-red)' : disk.temperature_c > 45 ? 'var(--accent-orange)' : ''}">${disk.temperature_c !== null ? disk.temperature_c + '°C' : 'N/A'}</div></div>
        <div class="disk-meta-item"><div class="label">通电时间</div><div class="val">${disk.power_on_hours ? disk.power_on_hours.toLocaleString() + 'h' : 'N/A'}</div></div>
        <div class="disk-meta-item"><div class="label">设备</div><div class="val">${disk.dev}</div></div>
        <div class="disk-meta-item"><div class="label">SMART</div><div class="val">${disk.smart_passed ? 'PASSED' : 'FAILED'}</div></div>
      </div>`;

    if (disk.key_attributes && Object.keys(disk.key_attributes).length > 0) {
      html += `<div class="disk-attrs">`;
      const showAttrs = [
        'Reallocated_Sector_Ct', 'Current_Pending_Sector', 'Reported_Uncorrect',
        'UDMA_CRC_Error_Count', 'Power_Cycle_Count', 'Start_Stop_Count',
      ];
      for (let key of showAttrs) {
        if (!(key in disk.key_attributes)) continue;
        const a = disk.key_attributes[key];
        let cls = 'attr-ok';
        const rawNum = parseInt(a.raw);
        if (!isNaN(rawNum)) {
          if (key === 'Reallocated_Sector_Ct' && rawNum > 0) cls = rawNum >= 100 ? 'attr-bad' : 'attr-warn';
          else if (key === 'Current_Pending_Sector' && rawNum > 0) cls = 'attr-warn';
          else if (key === 'Reported_Uncorrect' && rawNum > 0) cls = rawNum >= 100 ? 'attr-bad' : 'attr-warn';
          else if (key === 'UDMA_CRC_Error_Count' && rawNum > 10) cls = rawNum >= 100 ? 'attr-bad' : 'attr-warn';
        }
        html += `<div class="disk-attr">
          <span class="attr-name">${key}</span>
          <span class="attr-val ${cls}">${a.raw}</span>
        </div>`;
      }
      html += `</div>`;
    }

    html += `</div>`;
  }
  html += `</div>`;

  // ── Row 4: Warnings ──
  html += `<div class="warn-section">`;
  if (warns.length === 0) {
    html += `<div class="card"><div class="no-warn">✅ 所有系统运行正常，无告警</div></div>`;
  } else {
    html += `<div class="card-title" style="margin-bottom:12px"><span class="dot" style="background:var(--accent-red)"></span> 告警 (${warns.length})</div>`;
    for (w of warns) {
      const icon = w.severity === 'critical' ? '⛔' : '⚠️';
      html += `<div class="warn-card ${w.severity}">
        <span class="warn-icon">${icon}</span>
        <div>
          <div class="warn-title">${w.title}</div>
          <div class="warn-desc">${w.detail}</div>
        </div>
      </div>`;
    }
  }
  html += `</div>`;

  // ── Access Log ──
  const al = data.access_log || [];
  html += `<div class="warn-section">`;
  html += `<div class="card">
    <div class="card-title"><span class="dot" style="background:var(--accent-purple)"></span> 访问日志 (${al.length} 条)</div>`;
  if (al.length === 0) {
    html += `<div class="access-log-empty">暂无访问记录</div>`;
  } else {
    html += `<div style="overflow-x:auto"><table class="access-log-table"><thead><tr>
      <th>时间</th><th>IP</th><th>方法</th><th>路径</th><th>状态</th><th>耗时</th><th>客户端</th>
    </tr></thead><tbody>`;
    for (let e of al) {
      const statusClass = 's' + String(e.s)[0];
      html += `<tr>
        <td>${e.t}</td>
        <td class="ip-cell">${e.ip}</td>
        <td class="method-cell">${e.m}</td>
        <td class="path-cell">${e.p}</td>
        <td><span class="status-dot ${statusClass}"></span>${e.s}</td>
        <td>${e.ms !== undefined ? e.ms.toFixed(0) + 'ms' : '—'}</td>
        <td class="ua-cell" title="${e.ua || ''}">${e.ua || '—'}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }
  html += `</div></div>`;

  // ── Samba 文件访问审计日志 ──
  const sal = data.samba_access_log || [];
  const conn = data.samba_connections || [];
  html += `<div class="warn-section">`;
  html += `<div class="card">
    <div class="card-title"><span class="dot" style="background:var(--accent-yellow)"></span> Samba 文件访问 (${sal.length} 条) 活跃连接: ${conn.length}</div>`;
  if (conn.length > 0) {
    html += `<div style="margin-bottom:12px;font-size:12px;color:var(--text-dim)">`;
    html += `当前用户: ${conn.map(u => '<span style="color:var(--accent-green);font-weight:600">' + u + '</span>').join(', ')}`;
    html += `</div>`;
  }
  if (sal.length === 0) {
    html += `<div class="access-log-empty">暂无 Samba 访问记录</div>`;
  } else {
    html += `<div style="overflow-x:auto"><table class="access-log-table"><thead><tr>
      <th>时间</th><th>用户</th><th>共享</th><th>操作</th><th>文件路径</th><th>IP</th>
    </tr></thead><tbody>`;
    for (let e of sal) {
      const opColor = e.op === 'connect' || e.op === 'SMB2_OPEN' ? 'var(--accent-green)' :
                      e.op === 'disconnect' ? 'var(--accent-red)' :
                      e.op === 'mkdir' || e.op === 'SMB2_MKDIR' ? 'var(--accent-cyan)' :
                      e.op === 'rmdir' || e.op === 'unlink' ? 'var(--accent-orange)' :
                      e.op === 'rename' ? 'var(--accent-purple)' : 'var(--text-dim)';
      const typeDot = e.type === 'samba_session' ? '<span style="color:var(--accent-yellow)">●</span>' : '<span style="color:var(--text-dim)">•</span>';
      html += `<tr>
        <td>${e.t || ''}</td>
        <td>${e.user || '—'}</td>
        <td>${e.share || '—'}</td>
        <td style="color:${opColor};font-weight:600">${typeDot} ${e.op}</td>
        <td class="path-cell">${e.path || e.detail || '—'}</td>
        <td class="ip-cell">${e.ip || '—'}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }
  html += `</div></div>`;

  CONTENT_EL.innerHTML = html;
}

async function refreshData() {
  REFRESH_BTN.disabled = true;
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    render(data);
    UPDATED_EL.textContent = '更新于 ' + data.collected_at;
  } catch (e) {
    CONTENT_EL.innerHTML = '<div class="error-msg">获取数据失败: ' + e.message + '</div>';
  } finally {
    REFRESH_BTN.disabled = false;
  }
}

// 初始加载
refreshData();

// 定时刷新
setInterval(refreshData, 30000);
</script>

</body>
</html>
"""


class MonitorHandler(BaseHTTPRequestHandler):
    """HTTP 请求处理器"""

    def __init__(self, request, client_address, server):
        self._start_time = None
        super().__init__(request, client_address, server)

    def do_GET(self):
        self._start_time = time.time()
        self._last_status = 200
        if self.path == "/api/status":
            self.handle_api()
        elif self.path == "/":
            self.handle_index()
        else:
            self._last_status = 404
            self.send_error(404)

    def handle_index(self):
        """返回仪表盘页面"""
        self.send_response(200)
        self._last_status = 200
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        body = HTML_TEMPLATE.encode("utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_api(self):
        """返回 JSON 状态数据"""
        try:
            data = collect_status()
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self._last_status = 200
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            self._last_status = 500
            self.send_error(500, str(e))

    def log_message(self, format, *args):
        """自定义日志格式 — 写入控制台 + 访问日志文件"""
        status = self._last_status
        elapsed_ms = 0
        if self._start_time:
            elapsed_ms = (time.time() - self._start_time) * 1000

        # 控制台日志
        print(f"[{self.log_date_time_string()}] {self.client_address[0]} {self.command} {self.path} {status} {elapsed_ms:.0f}ms")

        # 文件日志 — 仅记录用户访问（排除仪表盘自动刷新请求）
        if self.path == "/api/status":
            return
        user_agent = self.headers.get('User-Agent', '')
        log_access(self.client_address[0], self.command, self.path, status, user_agent, elapsed_ms)


# ── 系统服务安装 ──────────────────────────────────────────────────────────────

SERVICE_UNIT = """\
[Unit]
Description=NAS Monitor Dashboard
After=network-online.target smbd.service
Wants=network-online.target

[Service]
Type=simple
User=msj
ExecStart=/usr/bin/python3 /home/msj/zw/nas-monitor.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""


def install_service():
    """安装为 systemd 服务"""
    unit_path = "/etc/systemd/system/nas-monitor.service"

    # 确保 smartctl 可以免密码 sudo
    sudoers_path = "/etc/sudoers.d/nas-monitor"
    sudoers_content = f"msj ALL=(root) NOPASSWD: /usr/sbin/smartctl\n"

    import getpass
    try:
        current_user = getpass.getuser()
    except Exception:
        current_user = os.environ.get("USER", "msj")

    if current_user != "root":
        print("请使用 sudo 运行安装命令:")
        print(f"  sudo python3 {sys.argv[0]} --install")
        sys.exit(1)

    # 写入 sudoers
    if not os.path.exists(sudoers_path):
        with open(sudoers_path, "w") as f:
            f.write(sudoers_content)
        os.chmod(sudoers_path, 0o440)
        print(f"[+] 已创建 {sudoers_path}")

    # 写入 service unit
    with open(unit_path, "w") as f:
        f.write(SERVICE_UNIT)
    print(f"[+] 已创建 {unit_path}")

    # 创建访问日志目录
    log_dir = os.path.dirname(ACCESS_LOG_PATH)
    os.makedirs(log_dir, exist_ok=True)
    print(f"[+] 访问日志目录: {log_dir}")

    # 重新加载 systemd
    subprocess.run(["systemctl", "daemon-reload"])
    subprocess.run(["systemctl", "enable", "--now", "nas-monitor"])
    print("[+] 服务已启用并启动")
    print(f"[+] 仪表盘: http://{current_user}@192.168.0.103:{PORT}")


# ── 主入口 ─────────────────────────────────────────────────────────────────────

def main():
    if "--install" in sys.argv:
        install_service()
        return

    _ensure_log_dir()
    server = HTTPServer((HOST, PORT), MonitorHandler)
    print(f"NAS 监控仪表盘已启动: http://0.0.0.0:{PORT}")
    print(f"访问日志: {ACCESS_LOG_PATH}")
    print("按 Ctrl+C 停止")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] 服务已停止")
        server.shutdown()


if __name__ == "__main__":
    main()
