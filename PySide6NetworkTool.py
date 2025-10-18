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
from PySide6.QtNetwork import (QNetworkAccessManager, QNetworkRequest,
                               QNetworkReply, QSslSocket, QHostInfo,
                               QSslConfiguration, QSsl)
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
            if host_info.error() == QHostInfo.HostInfoError.NoError:
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
            # 设置更详细的socket选项
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)  # 增加超时时间到15秒
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            result = sock.connect_ex((hostname, port))

            if result == 0:
                self.log(f"TCP连接成功: {hostname}:{port}")
                self.test_result_signal.emit("TCP连接", True, f"成功连接到 {hostname}:{port}")

                # 获取连接详细信息
                local_ip, local_port = sock.getsockname()
                self.log(f"连接详情 - 本地: {local_ip}:{local_port} -> 远程: {hostname}:{port}")
            else:
                # 更详细的错误信息
                error_messages = {
                    10035: "非阻塞socket操作无法立即完成",
                    10060: "连接超时",
                    10061: "连接被拒绝",
                    10054: "连接被对等方重置",
                    11001: "主机名解析失败"
                }
                error_msg = error_messages.get(result, f"系统错误代码: {result}")
                self.log(f"TCP连接失败: {error_msg} (错误代码: {result})", "ERROR")
                self.test_result_signal.emit("TCP连接", False, f"{error_msg} (代码: {result})")

            sock.close()

        except socket.timeout:
            self.log("TCP连接超时 (15秒)", "ERROR")
            self.test_result_signal.emit("TCP连接", False, "连接超时 (15秒)")
        except Exception as e:
            self.log(f"TCP连接异常: {str(e)}", "ERROR")
            self.test_result_signal.emit("TCP连接", False, f"异常: {str(e)}")

    def test_http_request(self, url):
        """测试HTTP请求 - 优化版本"""
        self.log(f"开始HTTP请求测试: {url}")

        try:
            # 创建优化的网络请求
            request = QNetworkRequest(QUrl(url))

            # 设置网络请求属性 - 修复Qt6中的重定向设置
            # Qt6中移除了FollowRedirectsAttribute，使用重定向策略
            request.setAttribute(QNetworkRequest.Attribute.RedirectPolicyAttribute,
                                 QNetworkRequest.RedirectPolicy.NoLessSafeRedirectPolicy)
            request.setAttribute(QNetworkRequest.Attribute.HttpPipeliningAllowedAttribute, True)

            # 如果是HTTPS，配置SSL
            if QUrl(url).scheme() == "https":
                ssl_config = QSslConfiguration.defaultConfiguration()
                ssl_config.setPeerVerifyMode(QSslSocket.PeerVerifyMode.VerifyPeer)
                ssl_config.setProtocol(QSsl.SslProtocol.AnyProtocol)
                request.setSslConfiguration(ssl_config)

            reply = self.network_manager.get(request)

            # 连接信号以获得更详细的错误信息
            reply.errorOccurred.connect(lambda error: self._handle_http_error(reply, error))
            if hasattr(reply, 'sslErrors'):
                reply.sslErrors.connect(lambda errors: self._handle_ssl_errors(errors))

            # 等待请求完成
            loop = QEventLoop()
            reply.finished.connect(loop.quit)

            # 设置更长的超时时间
            timer = QTimer()
            timer.timeout.connect(lambda: self._handle_http_timeout(reply, loop))
            timer.start(30000)  # 30秒超时

            loop.exec()

            # 处理响应
            if reply.error() == QNetworkReply.NetworkError.NoError:
                status_code = reply.attribute(QNetworkRequest.Attribute.HttpStatusCodeAttribute)
                content_type = reply.header(QNetworkRequest.KnownHeaders.ContentTypeHeader)
                content_length = reply.header(QNetworkRequest.KnownHeaders.ContentLengthHeader)

                # 读取响应内容（前500字符）
                response_data = reply.read(500)
                response_preview = response_data.data().decode('utf-8', errors='ignore') if response_data else ""

                info = f"状态码: {status_code}"
                if content_type:
                    info += f", 内容类型: {content_type}"
                if content_length:
                    info += f", 内容长度: {content_length} bytes"
                if response_preview:
                    info += f", 响应预览: {response_preview[:100]}{'...' if len(response_preview) > 100 else ''}"

                self.log(f"HTTP请求成功 - {info}")
                self.test_result_signal.emit("HTTP请求", True, info)
            else:
                # 错误信息已经在errorOccurred信号中处理
                pass

            reply.deleteLater()

        except Exception as e:
            self.log(f"HTTP请求异常: {str(e)}", "ERROR")
            self.test_result_signal.emit("HTTP请求", False, f"异常: {str(e)}")

    def _handle_http_error(self, reply, error):
        """处理HTTP错误"""
        error_messages = {
            QNetworkReply.NetworkError.ConnectionRefusedError: "连接被服务器拒绝",
            QNetworkReply.NetworkError.RemoteHostClosedError: "远程主机关闭连接",
            QNetworkReply.NetworkError.HostNotFoundError: "主机未找到",
            QNetworkReply.NetworkError.TimeoutError: "请求超时",
            QNetworkReply.NetworkError.OperationCanceledError: "操作被取消",
            QNetworkReply.NetworkError.SslHandshakeFailedError: "SSL握手失败",
            QNetworkReply.NetworkError.TemporaryNetworkFailureError: "临时网络故障",
            QNetworkReply.NetworkError.ProxyConnectionRefusedError: "代理连接被拒绝",
            QNetworkReply.NetworkError.ProxyConnectionClosedError: "代理连接关闭",
            QNetworkReply.NetworkError.ProxyNotFoundError: "代理未找到",
            QNetworkReply.NetworkError.ProxyTimeoutError: "代理超时",
            QNetworkReply.NetworkError.ProxyAuthenticationRequiredError: "需要代理认证",
            QNetworkReply.NetworkError.ContentAccessDenied: "内容访问被拒绝",
            QNetworkReply.NetworkError.ContentOperationNotPermittedError: "内容操作不允许",
            QNetworkReply.NetworkError.ContentNotFoundError: "内容未找到",
            QNetworkReply.NetworkError.AuthenticationRequiredError: "需要认证",
            QNetworkReply.NetworkError.ContentReSendError: "内容重新发送错误",
            QNetworkReply.NetworkError.ProtocolUnknownError: "协议未知错误",
            QNetworkReply.NetworkError.ProtocolInvalidOperationError: "协议无效操作",
            QNetworkReply.NetworkError.UnknownNetworkError: "未知网络错误",
            QNetworkReply.NetworkError.UnknownProxyError: "未知代理错误",
            QNetworkReply.NetworkError.UnknownContentError: "未知内容错误",
            QNetworkReply.NetworkError.ProtocolFailure: "协议失败"
        }

        error_msg = error_messages.get(error, f"未知错误: {error}")
        detailed_info = f"错误: {error_msg} (代码: {error}), 错误字符串: {reply.errorString()}"

        self.log(f"HTTP请求失败 - {detailed_info}", "ERROR")
        self.test_result_signal.emit("HTTP请求", False, detailed_info)

    def _handle_ssl_errors(self, ssl_errors):
        """处理SSL错误"""
        error_strings = [error.errorString() for error in ssl_errors]
        error_msg = "; ".join(error_strings)
        self.log(f"SSL错误: {error_msg}", "WARNING")

    def _handle_http_timeout(self, reply, loop):
        """处理HTTP超时"""
        self.log("HTTP请求超时 (30秒)", "ERROR")
        self.test_result_signal.emit("HTTP请求", False, "请求超时 (30秒未响应)")
        reply.abort()
        loop.quit()

    def test_ssl_certificate(self, url):
        """测试SSL证书"""
        self.log(f"开始SSL证书测试: {url}")

        try:
            request = QNetworkRequest(QUrl(url))

            # SSL配置
            ssl_config = QSslConfiguration.defaultConfiguration()
            ssl_config.setPeerVerifyMode(QSslSocket.PeerVerifyMode.VerifyPeer)
            request.setSslConfiguration(ssl_config)

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

            if reply.error() in [QNetworkReply.NetworkError.NoError, QNetworkReply.NetworkError.SslHandshakeFailedError]:
                ssl_config = reply.sslConfiguration()
                cert = ssl_config.peerCertificate()

                if cert.isNull():
                    self.log("SSL证书测试: 未获取到证书", "WARNING")
                    self.test_result_signal.emit("SSL证书", False, "未获取到服务器证书")
                else:
                    issuer = cert.issuerInfo(cert.SubjectInfo.CommonName)
                    subject = cert.subjectInfo(cert.SubjectInfo.CommonName)
                    expiry_date = cert.expiryDate().toString("yyyy-MM-dd")
                    effective_date = cert.effectiveDate().toString("yyyy-MM-dd")

                    info = f"颁发者: {issuer}, 主题: {subject}, 有效期: {effective_date} 至 {expiry_date}"
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
        self.setWindowTitle("网络诊断工具 - v1.1.0 - PySide6 (优化版)")
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
        splitter = QSplitter(Qt.Orientation.Vertical)

        # 结果表格
        results_group = QGroupBox("检测结果")
        results_layout = QVBoxLayout(results_group)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["检测项目", "状态", "详细信息"])
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
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
        self.statusBar().showMessage("就绪 - 优化版本已启用更详细的错误报告")

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
        self.log("注意: 此版本已优化网络请求配置，提供更详细的错误信息", "INFO")
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
        self.log_display.moveCursor(QTextCursor.MoveOperation.End)

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
    app.setApplicationVersion("1.1")
    app.setOrganizationName("NetworkDiagnostic")

    window = NetworkDiagnosticTool()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()