#!/usr/bin/env python3
"""
Модуль блокирования соединений.
Осуществляет блокирование подозрительных сетевых соединений через pfctl на macOS.
"""

import os
import ipaddress
import socket
import subprocess
import shutil
from urllib.parse import urlparse

import psutil


class ConnectionBlocker:
    def __init__(self):
        self.blocked_entries = []
        self._next_id = 1
        self._ip_ref_counts = {}

        self.table_name = "nm_blocked_hosts"
        self.anchor_name = "com.network_monitor"
        self.pfctl_path = shutil.which("pfctl")
        self.can_block = bool(self.pfctl_path and os.geteuid() == 0)
        self.anchor_loaded = False
        self.anchor_referenced = False

        if self.can_block:
            try:
                self._ensure_pf_enabled()
                self._load_anchor_rules()
                self.anchor_loaded = True
                self.anchor_referenced = self._is_anchor_referenced()
                if not self.anchor_referenced:
                    print(
                        "ВНИМАНИЕ: anchor com.network_monitor не подключен в активных правилах PF. "
                        "Команды блокировки будут только симулироваться."
                    )
                    print(
                        "Добавьте в /etc/pf.conf строку: anchor \"com.network_monitor\" "
                        "и перезагрузите PF: sudo pfctl -f /etc/pf.conf"
                    )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                print("Ошибка pfctl: {}".format(error))
        else:
            if not self.pfctl_path:
                print("pfctl не найден. Блокировка сетевых соединений не будет работать.")
            elif os.geteuid() != 0:
                print("Запустите приложение с правами администратора (sudo) для реального блокирования.")

    def _run_command(self, command, input_text=None, timeout=5):
        # Таймаут не дает GUI зависнуть, если pfctl отвечает слишком долго.
        result = subprocess.run(
            command,
            input=input_text,
            text=True,
            capture_output=True,
            check=True,
            timeout=timeout,
        )
        return result.stdout.strip()

    @property
    def real_blocking_enabled(self):
        return self.can_block and self.anchor_loaded and self.anchor_referenced

    def _ensure_pf_enabled(self):
        status = self._run_command([self.pfctl_path, "-s", "info"])
        if "Status: Disabled" in status or "Disabled" in status:
            self._run_command([self.pfctl_path, "-e"])

    def _load_anchor_rules(self):
        rules = (
            f"table <{self.table_name}> persist\n"
            f"block drop out quick to <{self.table_name}>\n"
            f"block drop in quick from <{self.table_name}>\n"
        )
        self._run_command([self.pfctl_path, "-a", self.anchor_name, "-f", "-"], input_text=rules)

    def _is_anchor_referenced(self):
        try:
            rules = self._run_command([self.pfctl_path, "-s", "rules"])
        except subprocess.CalledProcessError:
            return False

        probes = [
            f'anchor "{self.anchor_name}"',
            f"anchor {self.anchor_name}",
            f'load anchor "{self.anchor_name}"',
            f"load anchor {self.anchor_name}",
        ]
        return any(probe in rules for probe in probes)

    def _parse_addr(self, addr, label):
        if not addr:
            raise ValueError(f"{label} is empty")

        # Формат из GUI/monitor обычно x.x.x.x:port
        if addr.count(":") == 1:
            ip, port_text = addr.rsplit(":", 1)
            return ip, int(port_text)

        # Поддержка IPv6 с портом, если встретится формат [::1]:443
        if addr.startswith("[") and "]:" in addr:
            host, port_text = addr[1:].split("]:", 1)
            return host, int(port_text)

        # Если порт не распознан, возвращаем только IP
        return addr, None

    def _parse_remote_addr(self, remote_addr):
        return self._parse_addr(remote_addr, "remote_addr")

    def _parse_local_addr(self, local_addr):
        if not local_addr:
            return None

        try:
            ip, _ = self._parse_addr(local_addr, "local_addr")
        except ValueError:
            return None
        return ip

    def _normalize_url(self, url):
        raw = (url or "").strip()
        if not raw:
            raise ValueError("URL пуст")

        candidate = raw if "://" in raw else "https://" + raw
        parsed = urlparse(candidate)
        host = parsed.hostname
        if not host:
            raise ValueError("Некорректный URL: {}".format(url))

        return raw, host, parsed.port

    def _resolve_host(self, host):
        infos = socket.getaddrinfo(host, None)
        ips = []
        seen = set()
        for info in infos:
            ip = info[4][0]
            if ip not in seen:
                ips.append(ip)
                seen.add(ip)
        return ips

    def _make_rule_text(self, ip, port):
        if port is None:
            return f"block from any to {ip}"
        return f"block from any to {ip} port {port}"

    def _entry_exists(self, source, source_value, ip, port):
        for entry in self.blocked_entries:
            if (
                entry["source"] == source
                and entry["source_value"] == source_value
                and entry["ip"] == ip
                and entry["port"] == port
            ):
                return True
        return False

    def _get_local_interface_ips(self, version):
        local_ips = []
        seen = set()
        try:
            for addresses in psutil.net_if_addrs().values():
                for address in addresses:
                    if address.family not in (socket.AF_INET, socket.AF_INET6):
                        continue
                    candidate = address.address.split("%", 1)[0]
                    try:
                        parsed = ipaddress.ip_address(candidate)
                    except ValueError:
                        continue
                    if parsed.version == version and candidate not in seen:
                        local_ips.append(candidate)
                        seen.add(candidate)
        except (psutil.Error, OSError):
            return []
        return local_ips

    def _apply_pf_add(self, ip, local_ip=None):
        if not self.real_blocking_enabled:
            print(f"Симуляция блокировки: {ip}")
            return
        self._run_command([self.pfctl_path, "-a", self.anchor_name, "-t", self.table_name, "-T", "add", ip])
        self._expire_pf_states(ip, local_ip)
        print(f"Реально блокировано: {ip}")

    def _expire_pf_states(self, ip, local_ip=None):
        # Уже открытые TCP-соединения живут в state table PF. Поэтому после добавления
        # IP в блок-лист нужно удалить состояния и в направлении local -> remote тоже.
        parsed_ip = ipaddress.ip_address(ip)
        any_host = "::/0" if parsed_ip.version == 6 else "0.0.0.0/0"
        local_ips = []
        if local_ip:
            try:
                parsed_local = ipaddress.ip_address(local_ip)
                if parsed_local.version == parsed_ip.version:
                    local_ips.append(local_ip)
            except ValueError:
                pass

        for candidate in self._get_local_interface_ips(parsed_ip.version):
            if candidate not in local_ips:
                local_ips.append(candidate)

        commands = [[self.pfctl_path, "-k", ip]]
        for candidate in local_ips:
            commands.append([self.pfctl_path, "-k", candidate, "-k", ip])
            commands.append([self.pfctl_path, "-k", ip, "-k", candidate])
        commands.append([self.pfctl_path, "-k", any_host, "-k", ip])

        for command in commands:
            try:
                self._run_command(command)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                print(f"Не удалось сбросить PF-состояния для {ip}: {error}")

    def _apply_pf_delete(self, ip):
        if not self.real_blocking_enabled:
            print(f"Симуляция разблокировки: {ip}")
            return
        self._run_command([self.pfctl_path, "-a", self.anchor_name, "-t", self.table_name, "-T", "delete", ip])
        print(f"Реально разблокировано: {ip}")

    def _register_block(self, source, source_value, ip, port=None, local_ip=None):
        if self._entry_exists(source, source_value, ip, port):
            return None

        # Один IP может быть добавлен из разных источников, удаляем его только после последней записи.
        ip_ref = self._ip_ref_counts.get(ip, 0)
        if ip_ref == 0:
            self._apply_pf_add(ip, local_ip)
        elif self.real_blocking_enabled:
            self._expire_pf_states(ip, local_ip)
        self._ip_ref_counts[ip] = ip_ref + 1

        entry = {
            "id": self._next_id,
            "source": source,
            "source_value": source_value,
            "ip": ip,
            "port": port,
            "rule": self._make_rule_text(ip, port),
        }
        self._next_id += 1
        self.blocked_entries.append(entry)
        return entry

    def block_connection(self, conn):
        remote_addr = conn.get("remote_addr", "")
        if not remote_addr:
            return None

        try:
            ip, port = self._parse_remote_addr(remote_addr)
            local_ip = self._parse_local_addr(conn.get("local_addr", ""))
            return self._register_block("connection", remote_addr, ip, port, local_ip)
        except ValueError as error:
            print(str(error))
            return None
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            stderr = error.stderr.strip() if getattr(error, "stderr", None) else str(error)
            print(f"Не удалось заблокировать {remote_addr}: {stderr}")
            return None

    def block_url(self, url):
        try:
            source_value, host, parsed_port = self._normalize_url(url)
            ips = self._resolve_host(host)
        except (ValueError, socket.gaierror) as error:
            return [], str(error)

        added_entries = []
        errors = []
        for ip in ips:
            try:
                entry = self._register_block("url", source_value, ip, parsed_port)
                if entry:
                    added_entries.append(entry)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                stderr = error.stderr.strip() if getattr(error, "stderr", None) else str(error)
                errors.append(f"{ip}: {stderr}")

        if errors:
            return added_entries, "; ".join(errors)
        return added_entries, ""

    def _find_entry(self, block_id):
        for entry in self.blocked_entries:
            if entry["id"] == block_id:
                return entry
        return None

    def unblock_by_id(self, block_id):
        entry = self._find_entry(block_id)
        if not entry:
            return False, "Блокировка с ID={} не найдена".format(block_id)

        ip = entry["ip"]
        current_ref = self._ip_ref_counts.get(ip, 0)

        if current_ref <= 1:
            try:
                self._apply_pf_delete(ip)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                stderr = error.stderr.strip() if getattr(error, "stderr", None) else str(error)
                return False, f"Не удалось разблокировать {ip}: {stderr}"
            self._ip_ref_counts.pop(ip, None)
        else:
            self._ip_ref_counts[ip] = current_ref - 1

        self.blocked_entries = [item for item in self.blocked_entries if item["id"] != block_id]
        return True, ""

    def unblock_connection(self, conn):
        remote_addr = conn.get("remote_addr", "")
        if not remote_addr:
            return

        # Снимаем блокировки именно по этому remote_addr,
        # если они были добавлены из suspicious-таблицы.
        target_ids = [
            entry["id"]
            for entry in self.blocked_entries
            if entry["source"] == "connection" and entry["source_value"] == remote_addr
        ]

        for block_id in target_ids:
            self.unblock_by_id(block_id)

    def get_blocked_entries(self):
        return [dict(entry) for entry in self.blocked_entries]

    def get_blocked_rules(self):
        return [entry["rule"] for entry in self.blocked_entries]
