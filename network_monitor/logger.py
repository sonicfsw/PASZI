#!/usr/bin/env python3
"""
Модуль логирования событий.
Осуществляет логирование событий мониторинга и блокирования.
"""

import datetime
import os

class EventLogger:
    def __init__(self, log_file="network_monitor.log"):
        self.log_file = log_file
        # Файл создается один раз, дальше события только дописываются в конец.
        if not os.path.exists(log_file):
            with open(log_file, 'w') as f:
                f.write("Network Monitor Event Log\n")
                f.write("=" * 50 + "\n")

    def log_event(self, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = "[{}] {}\n".format(timestamp, message)
        
        with open(self.log_file, 'a') as f:
            f.write(log_entry)
        
        print(log_entry.strip())  # Также выводим в консоль для отладкиging

    def get_recent_logs(self, lines=50):
        if not os.path.exists(self.log_file):
            return []
        
        with open(self.log_file, 'r') as f:
            all_lines = f.readlines()
        
        return all_lines[-lines:] if len(all_lines) > lines else all_lines

    def clear_logs(self):
        with open(self.log_file, 'w') as f:
            f.write("Network Monitor Event Log (cleared)\n")
            f.write("=" * 50 + "\n")
