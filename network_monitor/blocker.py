#!/usr/bin/env python3
"""
Модуль блокирования соединений.
Осуществляет блокирование подозрительных сетевых соединений.
"""

import subprocess
import os

class ConnectionBlocker:
    def __init__(self):
        self.blocked_rules = []

    def block_connection(self, conn):
        """
        Блокирует определенное соединение.
        На macOS обычно используются правила пакетного фильтра (pf firewall).
        В этой реализации блокирование имитируется через логирование.
        В реальной системе используйте pfctl или аналогичные инструменты.
        """
        remote_addr = conn.get('remote_addr', '')
        if not remote_addr:
            return

        try:
            ip, port = remote_addr.rsplit(':', 1)
            # Имитируем блокирование - в реальной реализации используйте pfctl
            # Пример: sudo pfctl -t blocked_hosts -T add ip
            # Но требует прав администратора

            # Для демонстрации просто выводим в консоль и логируем
            print("Блокирование соединения с {}".format(remote_addr))
            self.blocked_rules.append("block from any to {} port {}".format(ip, port))

            # Если бы у нас были права, мы могли бы сделать:
            # subprocess.run(['sudo', 'pfctl', '-t', 'blocked_hosts', '-T', 'add', ip], check=True)

        except ValueError:
            print("Invalid address format: {}".format(remote_addr))

    def unblock_connection(self, conn):
        """
        Разблокирует ранее заблокированное соединение.
        """
        remote_addr = conn.get('remote_addr', '')
        if not remote_addr:
            return

        try:
            ip, port = remote_addr.rsplit(':', 1)
            print("Разблокирование соединения с {}".format(remote_addr))
            rule = "block from any to {} port {}".format(ip, port)
            if rule in self.blocked_rules:
                self.blocked_rules.remove(rule)
            # subprocess.run(['sudo', 'pfctl', '-t', 'blocked_hosts', '-T', 'delete', ip], check=True)

        except ValueError:
            print("Invalid address format: {}".format(remote_addr))

    def get_blocked_rules(self):
        return self.blocked_rules[:]