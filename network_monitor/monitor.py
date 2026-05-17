#!/usr/bin/env python3 для внешнего использования
"""
Модуль мониторинга сетевых соединений.
Обнаруживает активные соединения, процессы и подозрительную активность.
"""

import socket
import time
import psutil

class NetworkMonitor:
    def __init__(self):
        self.suspicious_ports = [22, 23, 25, 53, 80, 443, 3389]  # Порты подозрительной активности по умолчанию
        self.suspicious_ips = []  # Может быть обновлено из параметров
        self._dns_cache = {}
        self._dns_ttl_success = 900
        self._dns_ttl_fail = 120

    def update_rules(self, ports, ips):
        self.suspicious_ports = [int(p.strip()) for p in ports if p.strip()]
        self.suspicious_ips = [ip.strip() for ip in ips if ip.strip()]

    def get_active_connections(self):
        connections = []
        now = time.time()
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    try:
                        # Получаем информацию о процессе
                        process = psutil.Process(conn.pid) if conn.pid else None
                        process_name = process.name() if process else "Unknown"
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_name = "Unknown"

                    local_addr = "{}:{}".format(conn.laddr.ip, conn.laddr.port) if conn.laddr else ""
                    remote_addr = "{}:{}".format(conn.raddr.ip, conn.raddr.port) if conn.raddr else ""
                    remote_domain = self._resolve_remote_domain(conn.raddr.ip, now) if conn.raddr else ""

                    connections.append({
                        'local_addr': local_addr,
                        'remote_addr': remote_addr,
                        'remote_domain': remote_domain,
                        'status': conn.status,
                        'pid': conn.pid,
                        'process_name': process_name,
                        'type': str(conn.type)
                    })
        except (psutil.AccessDenied, PermissionError) as e:
            print("Доступ запрещен при обращении к информации о сетевых соединениях. Запустите с sudo.")
            print("Ошибка: {}".format(str(e)))
        return connections

    def get_processes_with_network(self):
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    # Проверяем, имеет ли процесс сетевые соединения
                    connections = proc.net_connections()
                    if connections:
                        processes.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'cpu_percent': proc.info['cpu_percent'],
                            'memory_percent': proc.info['memory_percent']
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except (psutil.AccessDenied, PermissionError) as e:
            print("Доступ запрещен при обращении к информации о процессах. Запустите с sudo.")
            print("Ошибка: {}".format(str(e)))
        return processes

    def get_suspicious_connections(self):
        suspicious = []
        connections = self.get_active_connections()
        for conn in connections:
            reason = self._check_suspicious(conn)
            if reason:
                conn['reason'] = reason
                suspicious.append(conn)
        return suspicious

    def _check_suspicious(self, conn):
        if not conn.get('remote_addr'):
            return ""

        try:
            remote_ip, remote_port = conn['remote_addr'].rsplit(':', 1)
            remote_port = int(remote_port)
        except ValueError:
            return ""

        # Проверяем подозрительные порты
        if remote_port in self.suspicious_ports:
            return "Подозрительный порт: {}".format(remote_port)

        # Проверяем подозрительные IP-адреса
        if remote_ip in self.suspicious_ips:
            return "Подозрительный IP: {}".format(remote_ip)

        # Здесь можно добавить дополнительные проверки
        # например, проверка против известных вредоносных IP, необычные паттерны трафика и т.д.

        return ""

    def _resolve_remote_domain(self, ip, now=None):
        if not ip:
            return ""

        if now is None:
            now = time.time()

        cached = self._dns_cache.get(ip)
        if cached and cached["expires_at"] > now:
            return cached["domain"]

        try:
            domain, _, _ = socket.gethostbyaddr(ip)
            resolved = domain if domain and domain != ip else ""
            expires_at = now + self._dns_ttl_success
        except (socket.herror, socket.gaierror, OSError):
            resolved = ""
            expires_at = now + self._dns_ttl_fail

        self._dns_cache[ip] = {"domain": resolved, "expires_at": expires_at}
        return resolved
