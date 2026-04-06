#!/usr/bin/env python3
"""
Модуль графического интерфейса.
Предоставляет основной интерфейс с вкладками для активных соединений,
подозрительных соединений, процессов и параметров.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QTabWidget, QTextEdit, QLineEdit, QCheckBox,
    QGroupBox, QMainWindow
)
from PyQt5.QtCore import QTimer
import psutil
from monitor import NetworkMonitor
from blocker import ConnectionBlocker
from logger import EventLogger

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.monitor = NetworkMonitor()
        self.blocker = ConnectionBlocker()
        self.logger = EventLogger()
        self.init_ui()
        self.setup_timers()

    def init_ui(self):
        self.setWindowTitle("Система мониторинга и блокирования сетевых соединений")
        self.setGeometry(100, 100, 1200, 800)

        # Центральный виджет
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Вкладки
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Вкладка активных соединений
        self.active_tab = QWidget()
        self.setup_active_connections_tab()
        self.tabs.addTab(self.active_tab, "Активные соединения")

        # Вкладка подозрительных соединений
        self.suspicious_tab = QWidget()
        self.setup_suspicious_connections_tab()
        self.tabs.addTab(self.suspicious_tab, "Подозрительные соединения")

        # Вкладка процессов
        self.processes_tab = QWidget()
        self.setup_processes_tab()
        self.tabs.addTab(self.processes_tab, "Процессы")

        # Вкладка параметров
        self.settings_tab = QWidget()
        self.setup_settings_tab()
        self.tabs.addTab(self.settings_tab, "Параметры")

        # Отображение журнала
        self.log_display = QTextEdit()
        self.log_display.setMaximumHeight(150)
        self.log_display.setReadOnly(True)
        layout.addWidget(QLabel("Журнал событий:"))
        layout.addWidget(self.log_display)

    def setup_active_connections_tab(self):
        layout = QVBoxLayout(self.active_tab)

        # Элементы управления
        controls_layout = QHBoxLayout()
        refresh_btn = QPushButton("Обновить")
        refresh_btn.clicked.connect(self.refresh_active_connections)
        controls_layout.addWidget(refresh_btn)

        self.auto_refresh_cb = QCheckBox("Автообновление (5 сек)")
        self.auto_refresh_cb.setChecked(True)
        controls_layout.addWidget(self.auto_refresh_cb)

        controls_layout.addStretch()
        layout.addLayout(controls_layout)

        # Таблица
        self.active_table = QTableWidget()
        self.active_table.setColumnCount(6)
        self.active_table.setHorizontalHeaderLabels([
            "Локальный адрес", "Удалённый адрес", "Статус", "PID", "Имя процесса", "Протокол"
        ])
        layout.addWidget(self.active_table)

    def setup_suspicious_connections_tab(self):
        layout = QVBoxLayout(self.suspicious_tab)

        # Элементы управления
        controls_layout = QHBoxLayout()
        block_btn = QPushButton("Заблокировать выбранное")
        block_btn.clicked.connect(self.block_selected_suspicious)
        controls_layout.addWidget(block_btn)

        allow_btn = QPushButton("Разрешить выбранное")
        allow_btn.clicked.connect(self.allow_selected_suspicious)
        controls_layout.addWidget(allow_btn)

        controls_layout.addStretch()
        layout.addLayout(controls_layout)

        # Таблица
        self.suspicious_table = QTableWidget()
        self.suspicious_table.setColumnCount(7)
        self.suspicious_table.setHorizontalHeaderLabels([
            "Локальный адрес", "Удалённый адрес", "Статус", "PID", "Имя процесса", "Протокол", "Причина"
        ])
        layout.addWidget(self.suspicious_table)

    def setup_processes_tab(self):
        layout = QVBoxLayout(self.processes_tab)

        # Элементы управления
        controls_layout = QHBoxLayout()
        refresh_btn = QPushButton("Обновить")
        refresh_btn.clicked.connect(self.refresh_processes)
        controls_layout.addWidget(refresh_btn)

        self.auto_refresh_proc_cb = QCheckBox("Автообновление (10 сек)")
        self.auto_refresh_proc_cb.setChecked(True)
        controls_layout.addWidget(self.auto_refresh_proc_cb)

        controls_layout.addStretch()
        layout.addLayout(controls_layout)

        # Таблица
        self.processes_table = QTableWidget()
        self.processes_table.setColumnCount(4)
        self.processes_table.setHorizontalHeaderLabels([
            "PID", "Имя", "CPU %", "Память %"
        ])
        layout.addWidget(self.processes_table)

    def setup_settings_tab(self):
        layout = QVBoxLayout(self.settings_tab)

        # Группа правил
        rules_group = QGroupBox("Правила обнаружения")
        rules_layout = QVBoxLayout(rules_group)

        # Подозрительные порты
        ports_layout = QHBoxLayout()
        ports_layout.addWidget(QLabel("Подозрительные порты (через запятую):"))
        self.suspicious_ports_edit = QLineEdit("22,23,25,53,80,443,3389")
        ports_layout.addWidget(self.suspicious_ports_edit)
        rules_layout.addLayout(ports_layout)

        # Подозрительные IP
        ips_layout = QHBoxLayout()
        ips_layout.addWidget(QLabel("Подозрительные IP-адреса (через запятую):"))
        self.suspicious_ips_edit = QLineEdit("")
        ips_layout.addWidget(self.suspicious_ips_edit)
        rules_layout.addLayout(ips_layout)

        # Автоблокирование
        self.auto_block_cb = QCheckBox("Автоматически блокировать подозрительные соединения")
        self.auto_block_cb.setChecked(False)
        rules_layout.addWidget(self.auto_block_cb)

        layout.addWidget(rules_group)

        # Кнопка сохранения
        save_btn = QPushButton("Сохранить параметры")
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
        layout.addStretch()

    def setup_timers(self):
        # Таймер для обновления активных соединений
        self.active_timer = QTimer()
        self.active_timer.timeout.connect(self.refresh_active_connections)
        self.active_timer.start(5000)  # 5 секунд

        # Таймер для обновления информации о процессах
        self.process_timer = QTimer()
        self.process_timer.timeout.connect(self.refresh_processes)
        self.process_timer.start(10000)  # 10 секунд

        # Таймер для проверки подозрительных соединений
        self.monitor_timer = QTimer()
        self.monitor_timer.timeout.connect(self.check_suspicious)
        self.monitor_timer.start(1000)  # 1 секунда

    def refresh_active_connections(self):
        if not self.auto_refresh_cb.isChecked():
            return
        try:
            connections = self.monitor.get_active_connections()
            self.active_table.setRowCount(len(connections))
            for row, conn in enumerate(connections):
                self.active_table.setItem(row, 0, QTableWidgetItem(conn.get('local_addr', '')))
                self.active_table.setItem(row, 1, QTableWidgetItem(conn.get('remote_addr', '')))
                self.active_table.setItem(row, 2, QTableWidgetItem(conn.get('status', '')))
                self.active_table.setItem(row, 3, QTableWidgetItem(str(conn.get('pid', ''))))
                self.active_table.setItem(row, 4, QTableWidgetItem(conn.get('process_name', '')))
                self.active_table.setItem(row, 5, QTableWidgetItem(conn.get('type', '')))
        except Exception as e:
            self.log_display.append("ОШИБКА: Нет доступа к информации о соединениях. Запустите приложение с правами администратора (sudo).")

    def refresh_processes(self):
        if not self.auto_refresh_proc_cb.isChecked():
            return
        try:
            processes = self.monitor.get_processes_with_network()
            self.processes_table.setRowCount(len(processes))
            for row, proc in enumerate(processes):
                self.processes_table.setItem(row, 0, QTableWidgetItem(str(proc['pid'])))
                self.processes_table.setItem(row, 1, QTableWidgetItem(proc['name']))
                self.processes_table.setItem(row, 2, QTableWidgetItem("{:.1f}".format(proc['cpu_percent'])))
                self.processes_table.setItem(row, 3, QTableWidgetItem("{:.1f}".format(proc['memory_percent'])))
        except Exception as e:
            self.log_display.append("ОШИБКА: Нет доступа к информации о процессах. Запустите приложение с правами администратора (sudo).")

    def check_suspicious(self):
        try:
            suspicious = self.monitor.get_suspicious_connections()
            self.suspicious_table.setRowCount(len(suspicious))
            for row, conn in enumerate(suspicious):
                self.suspicious_table.setItem(row, 0, QTableWidgetItem(conn.get('local_addr', '')))
                self.suspicious_table.setItem(row, 1, QTableWidgetItem(conn.get('remote_addr', '')))
                self.suspicious_table.setItem(row, 2, QTableWidgetItem(conn.get('status', '')))
                self.suspicious_table.setItem(row, 3, QTableWidgetItem(str(conn.get('pid', ''))))
                self.suspicious_table.setItem(row, 4, QTableWidgetItem(conn.get('process_name', '')))
                self.suspicious_table.setItem(row, 5, QTableWidgetItem(conn.get('type', '')))
                self.suspicious_table.setItem(row, 6, QTableWidgetItem(conn.get('reason', '')))

            if self.auto_block_cb.isChecked() and suspicious:
                for conn in suspicious:
                    self.blocker.block_connection(conn)
                    self.logger.log_event("Автоматически блокировано подозрительное соединение: {}".format(conn))
        except Exception as e:
            pass  # Молчаливый отказ, чтобы избежать избыточных сообщений об ошибках

    def block_selected_suspicious(self):
        # Получаем выбранные строки
        selected_rows = set()
        for item in self.suspicious_table.selectedItems():
            selected_rows.add(item.row())
        for row in selected_rows:
            # Получаем информацию о соединении из таблицы
            local = self.suspicious_table.item(row, 0).text()
            remote = self.suspicious_table.item(row, 1).text()
            pid = int(self.suspicious_table.item(row, 3).text())
            conn = {'local_addr': local, 'remote_addr': remote, 'pid': pid}
            self.blocker.block_connection(conn)
            self.logger.log_event("Вручную заблокировано соединение: {}".format(conn))

    def allow_selected_suspicious(self):
        # Просто удаляем выбранные строки из таблицы подозрительных соединений
        selected_rows = sorted(set(item.row() for item in self.suspicious_table.selectedItems()), reverse=True)
        for row in selected_rows:
            self.suspicious_table.removeRow(row)

    def save_settings(self):
        # Сохраняем параметры конфигурации (пока просто выводим)
        ports = self.suspicious_ports_edit.text()
        ips = self.suspicious_ips_edit.text()
        auto_block = self.auto_block_cb.isChecked()
        self.monitor.update_rules(ports.split(','), ips.split(','))
        self.logger.log_event("Параметры обновлены: порты={}, IP={}, автоблокировка={}".format(ports, ips, auto_block))

    def closeEvent(self, event):
        self.active_timer.stop()
        self.process_timer.stop()
        self.monitor_timer.stop()
        event.accept()