#!/usr/bin/env python3
"""
Система мониторинга и блокирования сетевых соединений.
Точка входа приложения.
"""

import sys
import os
from PyQt5.QtWidgets import QApplication
from gui import MainWindow

def main():
    if os.geteuid() != 0:
        print("WARNING: Для реального блокирования сетевых соединений приложение нужно запускать с sudo.")
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()