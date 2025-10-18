import sys
import os
import socket
import logging
import shutil
import subprocess
from datetime import datetime
from urllib.parse import urlparse

from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                               QHBoxLayout, QPushButton, QTextEdit, QLineEdit,
                               QLabel, QGroupBox, QCheckBox, QProgressBar,
                               QTableWidget, QTableWidgetItem,
                               QHeaderView, QMessageBox, QFileDialog, QSplitter)
from PySide6.QtCore import QThread, Signal, QTimer, Qt, QUrl, QEventLoop
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply, QSslSocket, QHostInfo
from PySide6.QtGui import QFont, QTextCursor, QColor


class NetworkTestWorker(QThread):
    """网络检测工作线程"""

    # 信号定义
    log_signal = Signal(str, str)  # 日志内容，日志级别
    progress_signal = Signal(int)  # 进度
    test_result_signal = Signal(str, bool, str)  # 测试项，结果，详细信息
    finished_signal = Signal(bool)  # 整体完成状态

    def __init__(self, target_url, tests_to_run):
        super().__init__()
        self.target_url = target_url
        self.tests_to_run = tests_to_run
        self.is_running = True
        self.network_manager = QNetworkAccessManager()

    def stop_test(self):
        """停止测试"""
        self.is_running = False

    def log(self, message, level="INFO"):
        """记录日志"""
        if self.is_running:
            self.log_signal.emit(message, level)

    def run(self):
        """执行网络检测"""
        try:
            parsed_url = urlparse(self.target_url)
            hostname = parsed_url.hostname

            total_tests = len(self.tests_to_run)
            completed_tests = 0

            # DNS解析测试
            if "dns" in self.tests_to_run and self.is_running:
                self.test_dns_resolution(hostname)
                completed_tests += 1
                self.progress_signal.emit(int(completed_tests / total_tests * 100))

            # TCP连接测试
            if "tcp" in self.tests_to_run and self.is_running:
                self.test_tcp_connection(hostname, parsed_url.port or (443 if parsed_url.scheme == "https" else 80))
                completed_tests += 1
                self.progress_signal.emit(int(completed_tests / total_tests * 100))

            # HTTP/HTTPS请求测试
            if "http" in self.tests_to_run and self.is_running:
                self.test_http_request(self.target_url)
                completed_tests += 1
                self.progress_signal.emit(int(completed_tests / total_tests * 100))

            # SSL证书测试（如果是HTTPS）
            if "ssl" in self.tests_to_run and parsed_url.scheme == "https" and self.is_running:
                self.test_ssl_certificate(self.target_url)
                completed_tests += 1
                self.progress_signal.emit(int(completed_tests / total_tests * 100))

            # 网络可达性测试
            if "reachability" in self.tests_to_run and self.is_running:
                self.test_network_reachability(hostname)
                completed_tests += 1
                self.progress_signal.emit(int(completed_tests / total_tests * 100))

            self.finished_signal.emit(True)

        except Exception as e:
            self.log(f"测试过程中发生错误: {str(e)}", "ERROR")
            self.finished_signal.emit(False)

    def test_dns_resolution(self, hostname):
        """测试DNS解析"""
        self.log(f"开始DNS解析测试: {hostname}")

        try:
            # 方法1: 使用Qt的DNS解析
            host_info = QHostInfo.fromName(hostname)
            if host_info.error() == QHostInfo.NoError:
                addresses = host_info.addresses()
                if addresses:
                    ip_list = [addr.toString() for addr in addresses]
                    self.log(f"DNS解析成功 - Qt方法: {', '.join(ip_list)}")
                    self.test_result_signal.emit("DNS解析", True, f"解析到的IP: {', '.join(ip_list)}")
                else:
                    self.log("DNS解析失败 - 未找到IP地址", "ERROR")
                    self.test_result_signal.emit("DNS解析", False, "未找到IP地址")
            else:
                self.log(f"DNS解析失败 - Qt方法: {host_info.errorString()}", "ERROR")
                self.test_result_signal.emit("DNS解析", False, f"Qt错误: {host_info.errorString()}")

        except Exception as e:
            self.log(f"DNS解析异常: {str(e)}", "ERROR")
            self.test_result_signal.emit("DNS解析", False, f"异常: {str(e)}")

    def test_tcp_connection(self, hostname, port):
        """测试TCP连接"""
        self.log(f"开始TCP连接测试: {hostname}:{port}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            result = sock.connect_ex((hostname, port))
            sock.close()

            if result == 0:
                self.log(f"TCP连接成功: {hostname}:{port}")
                self.test_result_signal.emit("TCP连接", True, f"成功连接到 {hostname}:{port}")
            else:
                self.log(f"TCP连接失败: 错误代码 {result}", "ERROR")
                self.test_result_signal.emit("TCP连接", False, f"连接失败，错误代码: {result}")

        except Exception as e:
            self.log(f"TCP连接异常: {str(e)}", "ERROR")
            self.test_result_signal.emit("TCP连接", False, f"异常: {str(e)}")

    def test_http_request(self, url):
        """测试HTTP请求"""
        self.log(f"开始HTTP请求测试: {url}")

        try:
            request = QNetworkRequest(QUrl(url))
            request.setRawHeader(b"User-Agent", b"NetworkDiagnosticTool/1.0")

            reply = self.network_manager.get(request)

            # 等待请求完成
            loop = QEventLoop()
            reply.finished.connect(loop.quit)
            timer = QTimer()
            timer.timeout.connect(loop.quit)
            timer.start(15000)  # 15秒超时
            loop.exec()

            if reply.error() == QNetworkReply.NetworkError.NoError:
                status_code = reply.attribute(QNetworkRequest.HttpStatusCodeAttribute)
                content_type = reply.header(QNetworkRequest.ContentTypeHeader)

                info = f"状态码: {status_code}"
                if content_type:
                    info += f", 内容类型: {content_type}"

                self.log(f"HTTP请求成功 - {info}")
                self.test_result_signal.emit("HTTP请求", True, info)
            else:
                error_msg = f"错误: {reply.errorString()} (代码: {reply.error()})"
                self.log(f"HTTP请求失败 - {error_msg}", "ERROR")
                self.test_result_signal.emit("HTTP请求", False, error_msg)

            reply.deleteLater()

        except Exception as e:
            self.log(f"HTTP请求异常: {str(e)}", "ERROR")
            self.test_result_signal.emit("HTTP请求", False, f"异常: {str(e)}")

    def test_ssl_certificate(self, url):
        """测试SSL证书"""
        self.log(f"开始SSL证书测试: {url}")

        try:
            request = QNetworkRequest(QUrl(url))

            # SSL配置
            ssl_config = request.sslConfiguration()
            ssl_config.setPeerVerifyMode(QSslSocket.PeerVerifyMode.VerifyPeer)  # 验证对等证书

            reply = self.network_manager.get(request)

            def handle_ssl_errors(ssl_errors):
                error_messages = [error.errorString() for error in ssl_errors]
                error_str = "; ".join(error_messages)
                self.log(f"SSL证书错误: {error_str}", "WARNING")

            reply.sslErrors.connect(handle_ssl_errors)

            loop = QEventLoop()
            reply.finished.connect(loop.quit)
            timer = QTimer()
            timer.timeout.connect(loop.quit)
            timer.start(15000)
            loop.exec()

            if reply.error() in [QNetworkReply.NetworkError.NoError, QNetworkReply.SslHandshakeFailedError]:
                ssl_config = reply.sslConfiguration()
                cert = ssl_config.peerCertificate()

                if cert.isNull():
                    self.log("SSL证书测试: 未获取到证书", "WARNING")
                    self.test_result_signal.emit("SSL证书", False, "未获取到服务器证书")
                else:
                    issuer = cert.issuerInfo(cert.SubjectInfo.CommonName)
                    expiry_date = cert.expiryDate().toString("yyyy-MM-dd")
                    info = f"颁发者: {issuer}, 过期时间: {expiry_date}"
                    self.log(f"SSL证书信息: {info}")
                    self.test_result_signal.emit("SSL证书", True, info)
            else:
                self.log(f"SSL测试失败: {reply.errorString()}", "ERROR")
                self.test_result_signal.emit("SSL证书", False, reply.errorString())

            reply.deleteLater()

        except Exception as e:
            self.log(f"SSL证书测试异常: {str(e)}", "ERROR")
            self.test_result_signal.emit("SSL证书", False, f"异常: {str(e)}")

    def test_network_reachability(self, hostname):
        """测试网络可达性"""
        self.log(f"开始网络可达性测试: {hostname}")

        try:
            # 使用ping命令测试基本可达性，隐藏命令行窗口
            if os.name == 'nt':  # Windows系统
                result = subprocess.run(
                    ["ping", "-n", "4", hostname],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW  # 隐藏命令行窗口
                )
            else:  # Linux/Mac系统
                result = subprocess.run(
                    ["ping", "-c", "4", hostname],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

            if result.returncode == 0:
                # 解析ping结果获取统计信息
                output_lines = result.stdout.split('\n')
                stats_line = None
                for line in output_lines:
                    if "平均" in line or "Average" in line or "avg" in line:
                        stats_line = line
                        break

                if stats_line:
                    self.log(f"网络可达性测试成功: 可以ping通 {hostname} - {stats_line.strip()}")
                    self.test_result_signal.emit("网络可达性", True, f"ping测试成功 - {stats_line.strip()}")
                else:
                    self.log(f"网络可达性测试成功: 可以ping通 {hostname}")
                    self.test_result_signal.emit("网络可达性", True, "ping测试成功")
            else:
                self.log(f"网络可达性测试失败: 无法ping通 {hostname}", "WARNING")
                self.test_result_signal.emit("网络可达性", False, "ping测试失败")

        except subprocess.TimeoutExpired:
            self.log("网络可达性测试超时", "WARNING")
            self.test_result_signal.emit("网络可达性", False, "ping测试超时")
        except Exception as e:
            self.log(f"网络可达性测试异常: {str(e)}", "ERROR")
            self.test_result_signal.emit("网络可达性", False, f"异常: {str(e)}")


class NetworkDiagnosticTool(QMainWindow):
    """网络诊断工具主窗口"""

    def __init__(self):
        super().__init__()
        self.worker_thread = None
        self.log_file = None
        self.setup_logging()
        self.init_ui()

    def setup_logging(self):
        """设置日志系统"""
        # 创建日志目录
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # 生成日志文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(log_dir, f"network_diagnostic_{timestamp}.log")

        # 配置logging
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )

    def init_ui(self):
        """初始化用户界面"""
        self.setWindowTitle("网络诊断工具 - v1.0.0 - PySide6")
        self.setGeometry(100, 100, 1200, 800)

        # 中心部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 主布局
        main_layout = QVBoxLayout(central_widget)

        # 顶部控制区域
        control_group = QGroupBox("测试配置")
        control_layout = QHBoxLayout(control_group)

        # URL输入
        url_layout = QVBoxLayout()
        url_layout.addWidget(QLabel("测试URL:"))
        self.url_input = QLineEdit("http://www.agiletiles.com:6666/api/version/public/current?type=Windows")
        url_layout.addWidget(self.url_input)
        control_layout.addLayout(url_layout)

        # 测试选项
        tests_layout = QVBoxLayout()
        tests_layout.addWidget(QLabel("检测项目:"))

        tests_widget = QWidget()
        tests_inner_layout = QHBoxLayout(tests_widget)

        self.dns_check = QCheckBox("DNS解析")
        self.tcp_check = QCheckBox("TCP连接")
        self.http_check = QCheckBox("HTTP请求")
        self.ssl_check = QCheckBox("SSL证书")
        self.reachability_check = QCheckBox("网络可达性")

        # 默认选中所有检测项
        self.dns_check.setChecked(True)
        self.tcp_check.setChecked(True)
        self.http_check.setChecked(True)
        self.ssl_check.setChecked(True)
        self.reachability_check.setChecked(True)

        tests_inner_layout.addWidget(self.dns_check)
        tests_inner_layout.addWidget(self.tcp_check)
        tests_inner_layout.addWidget(self.http_check)
        tests_inner_layout.addWidget(self.ssl_check)
        tests_inner_layout.addWidget(self.reachability_check)

        tests_layout.addWidget(tests_widget)
        control_layout.addLayout(tests_layout)

        # 按钮区域
        button_layout = QVBoxLayout()
        self.start_btn = QPushButton("开始检测")
        self.stop_btn = QPushButton("停止检测")
        self.export_btn = QPushButton("导出日志")

        self.start_btn.clicked.connect(self.start_test)
        self.stop_btn.clicked.connect(self.stop_test)
        self.export_btn.clicked.connect(self.export_logs)

        self.stop_btn.setEnabled(False)

        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        button_layout.addWidget(self.export_btn)
        control_layout.addLayout(button_layout)

        main_layout.addWidget(control_group)

        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

        # 分割区域
        splitter = QSplitter(Qt.Vertical)

        # 结果表格
        results_group = QGroupBox("检测结果")
        results_layout = QVBoxLayout(results_group)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["检测项目", "状态", "详细信息"])
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        results_layout.addWidget(self.results_table)

        splitter.addWidget(results_group)

        # 日志显示
        log_group = QGroupBox("实时日志")
        log_layout = QVBoxLayout(log_group)

        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFont(QFont("Consolas", 9))
        log_layout.addWidget(self.log_display)

        splitter.addWidget(log_group)
        splitter.setSizes([300, 500])

        main_layout.addWidget(splitter)

        # 状态栏
        self.statusBar().showMessage("就绪")

    def start_test(self):
        """开始网络检测"""
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "输入错误", "请输入要测试的URL")
            return

        # 验证URL格式
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                QMessageBox.warning(self, "URL错误", "请输入有效的URL（包含协议和域名）")
                return
        except Exception:
            QMessageBox.warning(self, "URL错误", "请输入有效的URL")
            return

        # 收集选中的测试项目
        tests_to_run = []
        if self.dns_check.isChecked():
            tests_to_run.append("dns")
        if self.tcp_check.isChecked():
            tests_to_run.append("tcp")
        if self.http_check.isChecked():
            tests_to_run.append("http")
        if self.ssl_check.isChecked():
            tests_to_run.append("ssl")
        if self.reachability_check.isChecked():
            tests_to_run.append("reachability")

        if not tests_to_run:
            QMessageBox.warning(self, "配置错误", "请至少选择一个检测项目")
            return

        # 清空之前的结果和日志
        self.results_table.setRowCount(0)
        self.log_display.clear()

        # 更新UI状态
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        # 创建并启动工作线程
        self.worker_thread = NetworkTestWorker(url, tests_to_run)
        self.worker_thread.log_signal.connect(self.handle_log)
        self.worker_thread.progress_signal.connect(self.progress_bar.setValue)
        self.worker_thread.test_result_signal.connect(self.handle_test_result)
        self.worker_thread.finished_signal.connect(self.handle_test_finished)

        self.worker_thread.start()

        self.log("开始网络诊断测试...", "INFO")
        self.log(f"目标URL: {url}", "INFO")
        self.log(f"检测项目: {', '.join(tests_to_run)}", "INFO")
        self.statusBar().showMessage("测试进行中...")

    def stop_test(self):
        """停止检测"""
        if self.worker_thread and self.worker_thread.isRunning():
            self.worker_thread.stop_test()
            self.worker_thread.quit()
            self.worker_thread.wait(2000)  # 等待2秒

        self.handle_test_finished(False)
        self.log("测试被用户中断", "WARNING")

    def handle_log(self, message, level):
        """处理日志信息"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"

        # 在界面显示
        self.log_display.append(log_entry)
        self.log_display.moveCursor(QTextCursor.End)

        # 记录到文件
        if level == "ERROR":
            logging.error(message)
        elif level == "WARNING":
            logging.warning(message)
        else:
            logging.info(message)

    def handle_test_result(self, test_name, success, details):
        """处理测试结果"""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)

        # 测试项目
        self.results_table.setItem(row, 0, QTableWidgetItem(test_name))

        # 状态
        status_item = QTableWidgetItem("成功" if success else "失败")
        status_item.setForeground(QColor(0, 128, 0) if success else QColor(255, 0, 0))
        self.results_table.setItem(row, 1, status_item)

        # 详细信息
        self.results_table.setItem(row, 2, QTableWidgetItem(details))

    def handle_test_finished(self, success):
        """处理测试完成"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)

        status = "完成" if success else "中断"
        self.log(f"测试{status}", "INFO")
        self.statusBar().showMessage(f"测试{status}")

    def export_logs(self):
        """导出日志"""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "导出日志",
            f"network_diagnostic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
            "日志文件 (*.log);;所有文件 (*.*)"
        )

        if file_path:
            try:
                # 复制日志文件到指定位置
                shutil.copy2(self.log_file, file_path)
                self.log(f"日志已导出到: {file_path}", "INFO")
                QMessageBox.information(self, "导出成功", f"日志已成功导出到:\n{file_path}")
            except Exception as e:
                self.log(f"导出日志失败: {str(e)}", "ERROR")
                QMessageBox.critical(self, "导出失败", f"导出日志时发生错误:\n{str(e)}")

    def log(self, message, level="INFO"):
        """记录日志的便捷方法"""
        self.handle_log(message, level)


def main():
    """主函数"""
    app = QApplication(sys.argv)

    # 设置应用属性
    app.setApplicationName("网络诊断工具")
    app.setApplicationVersion("1.0")
    app.setOrganizationName("NetworkDiagnostic")

    window = NetworkDiagnosticTool()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()