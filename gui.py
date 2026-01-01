import sys
import json
import frida
from datetime import datetime
from PyQt6.QtWidgets import (
  QApplication, QMainWindow, QWidget, QVBoxLayout,
  QTableWidget, QTableWidgetItem, QTextEdit, QLineEdit, QPushButton,
  QLabel, QSplitter, QHeaderView, QTabWidget, QMessageBox,
  QMenu, QComboBox, QCheckBox, QToolBar, QStatusBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QColor

HACKER_STYLE = """
QMainWindow {
  background-color: #0a0a0a;
}
QWidget {
  background-color: #0a0a0a;
  color: #00ff00;
  font-family: 'Consolas', 'Microsoft YaHei UI', monospace;
  font-size: 12px;
}
QToolBar {
  background-color: #0d0d0d;
  border: none;
  border-bottom: 1px solid #00ff00;
  padding: 6px 10px;
  spacing: 8px;
}
QToolBar QLabel#stats {
  color: #00ff00;
  font-weight: bold;
}
QLineEdit {
  background-color: #000000;
  border: 1px solid #00ff00;
  border-radius: 0px;
  padding: 6px 12px;
  color: #00ff00;
  min-width: 280px;
  max-width: 320px;
  selection-background-color: #00ff00;
  selection-color: #000000;
}
QLineEdit:focus {
  border: 1px solid #00ff88;
  background-color: #0a0a0a;
}
QLineEdit::placeholder {
  color: #006600;
}
QPushButton {
  background-color: #000000;
  border: 1px solid #00ff00;
  border-radius: 0px;
  padding: 6px 16px;
  color: #00ff00;
  font-weight: bold;
}
QPushButton:hover {
  background-color: #00ff00;
  color: #000000;
}
QPushButton:pressed {
  background-color: #00aa00;
  color: #000000;
}
QPushButton#stop {
  border-color: #ff0000;
  color: #ff0000;
}
QPushButton#stop:hover {
  background-color: #ff0000;
  color: #000000;
}
QPushButton#secondary {
  border-color: #00aa00;
  color: #00aa00;
}
QPushButton#secondary:hover {
  background-color: #00aa00;
  color: #000000;
}
QComboBox {
  background-color: #000000;
  border: 1px solid #00ff00;
  border-radius: 0px;
  padding: 6px 12px;
  color: #00ff00;
  min-width: 100px;
}
QComboBox:hover {
  border: 1px solid #00ff88;
}
QComboBox::drop-down {
  border: none;
  border-left: 1px solid #00ff00;
  width: 25px;
}
QComboBox::down-arrow {
  image: none;
  border-left: 5px solid transparent;
  border-right: 5px solid transparent;
  border-top: 6px solid #00ff00;
  margin-right: 5px;
}
QComboBox QAbstractItemView {
  background-color: #000000;
  border: 1px solid #00ff00;
  selection-background-color: #00ff00;
  selection-color: #000000;
  outline: none;
}
QCheckBox {
  color: #00ff00;
  spacing: 6px;
}
QCheckBox::indicator {
  width: 16px;
  height: 16px;
  border: 1px solid #00ff00;
  background-color: #000000;
}
QCheckBox::indicator:checked {
  background-color: #00ff00;
  border: 1px solid #00ff00;
}
QCheckBox::indicator:hover {
  border: 1px solid #00ff88;
}
QTableWidget {
  background-color: #000000;
  border: 1px solid #00ff00;
  gridline-color: #003300;
  selection-background-color: #003300;
  outline: none;
  color: #00ff00;
}
QTableWidget::item {
  padding: 8px;
  border-bottom: 1px solid #002200;
}
QTableWidget::item:selected {
  background-color: #003300;
  color: #00ff00;
}
QTableWidget::item:hover {
  background-color: #001a00;
}
QHeaderView::section {
  background-color: #0a0a0a;
  color: #00ff00;
  padding: 10px 8px;
  border: none;
  border-bottom: 2px solid #00ff00;
  border-right: 1px solid #003300;
  font-weight: bold;
  font-size: 11px;
}
QTextEdit {
  background-color: #000000;
  border: none;
  padding: 12px;
  color: #00ff00;
  font-family: 'Consolas', 'Microsoft YaHei UI', monospace;
  font-size: 12px;
  selection-background-color: #00ff00;
  selection-color: #000000;
}
QTabWidget::pane {
  border: 1px solid #00ff00;
  background-color: #000000;
}
QTabBar::tab {
  background-color: #0a0a0a;
  color: #008800;
  padding: 10px 20px;
  border: 1px solid #003300;
  border-bottom: none;
  margin-right: 2px;
}
QTabBar::tab:selected {
  background-color: #000000;
  color: #00ff00;
  border: 1px solid #00ff00;
  border-bottom: 2px solid #000000;
}
QTabBar::tab:hover:!selected {
  background-color: #001a00;
  color: #00ff00;
}
QSplitter::handle {
  background-color: #00ff00;
}
QSplitter::handle:horizontal {
  width: 1px;
}
QSplitter::handle:vertical {
  height: 1px;
}
QSplitter::handle:hover {
  background-color: #00ff88;
}
QStatusBar {
  background-color: #0a0a0a;
  color: #00ff00;
  border-top: 1px solid #00ff00;
  padding: 4px 12px;
  font-size: 11px;
  font-family: 'Consolas', monospace;
}
QScrollBar:vertical {
  background-color: #000000;
  width: 12px;
  margin: 0;
  border-left: 1px solid #003300;
}
QScrollBar::handle:vertical {
  background-color: #00ff00;
  min-height: 30px;
}
QScrollBar::handle:vertical:hover {
  background-color: #00ff88;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
  height: 0;
}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
  background-color: #001100;
}
QScrollBar:horizontal {
  background-color: #000000;
  height: 12px;
  margin: 0;
  border-top: 1px solid #003300;
}
QScrollBar::handle:horizontal {
  background-color: #00ff00;
  min-width: 30px;
}
QScrollBar::handle:horizontal:hover {
  background-color: #00ff88;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
  width: 0;
}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
  background-color: #001100;
}
QMenu {
  background-color: #000000;
  border: 1px solid #00ff00;
  padding: 5px;
}
QMenu::item {
  padding: 8px 25px;
  color: #00ff00;
}
QMenu::item:selected {
  background-color: #00ff00;
  color: #000000;
}
QMenu::separator {
  height: 1px;
  background-color: #003300;
  margin: 5px 10px;
}
QMessageBox {
  background-color: #000000;
}
QMessageBox QLabel {
  color: #00ff00;
}
QMessageBox QPushButton {
  min-width: 80px;
}
"""

class FridaWorker(QThread):
  message_received = pyqtSignal(dict)
  status_changed = pyqtSignal(str)
  error_occurred = pyqtSignal(str)

  def __init__(self, js_file='http.js'):
    super().__init__()
    self.js_file = js_file
    self.running = False
    self.script = None
    self.session = None

  def read_js_file(self):
    try:
      with open(self.js_file, 'r', encoding='utf8') as f:
        return f.read()
    except FileNotFoundError:
      self.error_occurred.emit(f"错误: 找不到脚本文件 {self.js_file}")
      return None

  def handle_message(self, message, data):
    if message['type'] == 'send':
      self.message_received.emit(message['payload'])
    elif message['type'] == 'error':
      self.error_occurred.emit(str(message))

  def run(self):
    self.running = True
    try:
      self.status_changed.emit("[*] 正在连接USB设备...")
      device = frida.get_usb_device(timeout=10)
      self.status_changed.emit("[*] 正在附加目标进程...")
      self.session = device.attach('MOMO陌陌')
      js_code = self.read_js_file()
      if not js_code:
        return
      self.script = self.session.create_script(js_code)
      self.script.on('message', self.handle_message)
      self.script.load()
      self.script.exports_sync.setup()
      self.status_changed.emit("[+] 连接成功 - 正在监听数据包...")
      while self.running:
        self.msleep(100)
    except frida.ServerNotRunningError:
      self.error_occurred.emit("[-] Frida服务未运行，请检查设备")
    except frida.ProcessNotFoundError:
      self.error_occurred.emit("[-] 找不到目标进程，请确认应用已启动")
    except frida.TransportError:
      self.error_occurred.emit("[-] 连接中断，请检查USB连接")
    except Exception as e:
      self.error_occurred.emit(f"[-] 错误: {str(e)}")
    finally:
      self.status_changed.emit("[x] 已断开连接")

  def stop(self):
    self.running = False
    if self.script:
      try:
        self.script.unload()
      except:
        pass
    if self.session:
      try:
        self.session.detach()
      except:
        pass

class RequestItem:
  def __init__(self, data):
    self.timestamp = datetime.now()
    self.url = data.get('url', '')
    self.header = data.get('header', {})
    self.body = data.get('body', {})
    self.response = data.get('response', {})
    self.api_name = self.url.split('?')[0].split('/')[-1] if self.url else ''
    self.status = '成功' if self.response.get('ec') == 0 else '失败'
    self.error_msg = self.response.get('em', '')

  def to_dict(self):
    return {
      '时间戳': self.timestamp.isoformat(),
      '地址': self.url,
      '请求头': self.header,
      '请求体': self.body,
      '响应': self.response
    }

class MainWindow(QMainWindow):
  def __init__(self):
    super().__init__()
    self.requests = []
    self.frida_worker = None
    self.auto_scroll = True
    self.init_ui()

  def init_ui(self):
    self.setWindowTitle('陌陌')
    self.setStyleSheet(HACKER_STYLE)
    screen = QApplication.primaryScreen().geometry()
    width = int(screen.width() * 0.7)
    height = int(screen.height() * 0.7)
    self.setGeometry(
      (screen.width() - width) // 2,
      (screen.height() - height) // 2,
      width, height
    )
    central_widget = QWidget()
    self.setCentralWidget(central_widget)
    main_layout = QVBoxLayout(central_widget)
    main_layout.setSpacing(0)
    main_layout.setContentsMargins(0, 0, 0, 0)
    toolbar = QToolBar()
    toolbar.setMovable(False)
    toolbar.setIconSize(QSize(16, 16))
    self.connect_btn = QPushButton('[ 开始监听 ]')
    self.connect_btn.setFixedWidth(100)
    self.connect_btn.clicked.connect(self.toggle_connection)
    toolbar.addWidget(self.connect_btn)
    toolbar.addSeparator()
    self.search_input = QLineEdit()
    self.search_input.setPlaceholderText('输入关键字搜索...')
    self.search_input.textChanged.connect(self.filter_requests)
    toolbar.addWidget(self.search_input)
    self.filter_combo = QComboBox()
    self.filter_combo.addItems(['全部请求', '仅成功', '仅失败'])
    self.filter_combo.currentIndexChanged.connect(self.filter_requests)
    toolbar.addWidget(self.filter_combo)
    self.auto_scroll_cb = QCheckBox('自动滚动')
    self.auto_scroll_cb.setChecked(True)
    self.auto_scroll_cb.stateChanged.connect(
      lambda s: setattr(self, 'auto_scroll', s == Qt.CheckState.Checked.value)
    )
    toolbar.addWidget(self.auto_scroll_cb)
    toolbar.addSeparator()
    copy_btn = QPushButton('复制')
    copy_btn.setObjectName('secondary')
    copy_btn.clicked.connect(self.copy_all)
    toolbar.addWidget(copy_btn)
    export_btn = QPushButton('导出')
    export_btn.setObjectName('secondary')
    export_btn.clicked.connect(self.export_json)
    toolbar.addWidget(export_btn)
    clear_btn = QPushButton('清空')
    clear_btn.setObjectName('secondary')
    clear_btn.clicked.connect(self.clear_requests)
    toolbar.addWidget(clear_btn)
    spacer = QWidget()
    spacer.setSizePolicy(spacer.sizePolicy().horizontalPolicy().Expanding,
              spacer.sizePolicy().verticalPolicy().Preferred)
    toolbar.addWidget(spacer)
    self.stats_label = QLabel('[ 请求: 0 | 成功: 0 | 失败: 0 ]')
    self.stats_label.setObjectName('stats')
    toolbar.addWidget(self.stats_label)
    main_layout.addWidget(toolbar)
    main_splitter = QSplitter(Qt.Orientation.Vertical)
    self.request_table = QTableWidget()
    self.request_table.setColumnCount(5)
    self.request_table.setHorizontalHeaderLabels(['时间', '接口', '请求地址', '状态', '消息'])
    self.request_table.setAlternatingRowColors(False)
    self.request_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    self.request_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
    self.request_table.setShowGrid(False)
    self.request_table.verticalHeader().setVisible(False)
    self.request_table.verticalHeader().setDefaultSectionSize(32)
    header = self.request_table.horizontalHeader()
    header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
    header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
    header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
    header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
    header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
    self.request_table.setColumnWidth(0, 80)
    self.request_table.setColumnWidth(1, 160)
    self.request_table.setColumnWidth(3, 60)
    self.request_table.setColumnWidth(4, 100)
    self.request_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
    self.request_table.customContextMenuRequested.connect(self.show_context_menu)
    self.request_table.selectionModel().selectionChanged.connect(self.on_selection_changed)
    main_splitter.addWidget(self.request_table)
    self.detail_tabs = QTabWidget()
    self.url_text = QTextEdit()
    self.url_text.setReadOnly(True)
    self.detail_tabs.addTab(self.url_text, '请求地址')
    self.headers_text = QTextEdit()
    self.headers_text.setReadOnly(True)
    self.detail_tabs.addTab(self.headers_text, '请求头')
    self.body_text = QTextEdit()
    self.body_text.setReadOnly(True)
    self.detail_tabs.addTab(self.body_text, '请求体')
    self.response_text = QTextEdit()
    self.response_text.setReadOnly(True)
    self.detail_tabs.addTab(self.response_text, '响应数据')
    main_splitter.addWidget(self.detail_tabs)
    main_splitter.setSizes([int(height * 0.55), int(height * 0.35)])
    main_layout.addWidget(main_splitter)
    self.status_bar = QStatusBar()
    self.setStatusBar(self.status_bar)
    self.status_bar.showMessage('[*] 就绪 - 点击"开始监听"连接设备')

  def toggle_connection(self):
    if self.frida_worker and self.frida_worker.isRunning():
      self.stop_monitoring()
    else:
      self.start_monitoring()

  def start_monitoring(self):
    self.frida_worker = FridaWorker()
    self.frida_worker.message_received.connect(self.on_message_received)
    self.frida_worker.status_changed.connect(self.on_status_changed)
    self.frida_worker.error_occurred.connect(self.on_error)
    self.frida_worker.start()
    self.connect_btn.setText('[ 停止监听 ]')
    self.connect_btn.setObjectName('stop')
    self.connect_btn.setStyle(self.connect_btn.style())

  def stop_monitoring(self):
    if self.frida_worker:
      self.frida_worker.stop()
      self.frida_worker.wait()
      self.frida_worker = None
    self.connect_btn.setText('[ 开始监听 ]')
    self.connect_btn.setObjectName('')
    self.connect_btn.setStyle(self.connect_btn.style())
    self.status_bar.showMessage('[x] 已断开连接')

  def on_message_received(self, data):
    request = RequestItem(data)
    self.requests.append(request)
    if self.matches_filter(request):
      self.add_request_to_table(request)
    self.update_stats()
    if self.auto_scroll:
      self.request_table.scrollToBottom()

  def on_status_changed(self, status):
    self.status_bar.showMessage(status)

  def on_error(self, error):
    self.status_bar.showMessage(error)
    QMessageBox.warning(self, '错误', error)
    self.stop_monitoring()

  def add_request_to_table(self, request):
    row = self.request_table.rowCount()
    self.request_table.insertRow(row)
    time_item = QTableWidgetItem(request.timestamp.strftime('%H:%M:%S'))
    time_item.setData(Qt.ItemDataRole.UserRole, len(self.requests) - 1)
    time_item.setForeground(QColor('#00aa00'))
    self.request_table.setItem(row, 0, time_item)
    api_item = QTableWidgetItem(request.api_name)
    api_item.setForeground(QColor('#00ffff'))
    self.request_table.setItem(row, 1, api_item)
    url_display = request.url.split('?')[0] if request.url else ''
    if len(url_display) > 60:
      url_display = '...' + url_display[-57:]
    url_item = QTableWidgetItem(url_display)
    url_item.setToolTip(request.url)
    url_item.setForeground(QColor('#00ff00'))
    self.request_table.setItem(row, 2, url_item)
    status_item = QTableWidgetItem(request.status)
    if request.status == '成功':
      status_item.setForeground(QColor('#00ff00'))
    else:
      status_item.setForeground(QColor('#ff0000'))
    self.request_table.setItem(row, 3, status_item)
    em_item = QTableWidgetItem(request.error_msg[:15] if request.error_msg else '-')
    em_item.setForeground(QColor('#00aa00'))
    self.request_table.setItem(row, 4, em_item)

  def matches_filter(self, request):
    filter_idx = self.filter_combo.currentIndex()
    if filter_idx == 1 and request.status != '成功':
      return False
    if filter_idx == 2 and request.status != '失败':
      return False
    search_text = self.search_input.text().lower()
    if search_text:
      search_content = json.dumps(request.to_dict(), ensure_ascii=False).lower()
      if search_text not in search_content:
        return False
    return True

  def filter_requests(self):
    self.request_table.setRowCount(0)
    for request in self.requests:
      if self.matches_filter(request):
        self.add_request_to_table(request)

  def on_selection_changed(self, selected, deselected):
    indexes = selected.indexes()
    if not indexes:
      return
    row = indexes[0].row()
    item = self.request_table.item(row, 0)
    if not item:
      return
    request_idx = item.data(Qt.ItemDataRole.UserRole)
    if request_idx is None or request_idx >= len(self.requests):
      return
    request = self.requests[request_idx]
    self.show_request_details(request)

  def show_request_details(self, request):
    self.url_text.setPlainText(request.url)
    self.headers_text.setPlainText(json.dumps(request.header, indent=2, ensure_ascii=False))
    self.body_text.setPlainText(json.dumps(request.body, indent=2, ensure_ascii=False))
    self.response_text.setPlainText(json.dumps(request.response, indent=2, ensure_ascii=False))

  def update_stats(self):
    total = len(self.requests)
    success = sum(1 for r in self.requests if r.status == '成功')
    failed = total - success
    self.stats_label.setText(f'[ 请求: {total} | 成功: {success} | 失败: {failed} ]')

  def show_context_menu(self, pos):
    menu = QMenu(self)
    menu.addAction('复制请求地址', self.copy_url)
    menu.addAction('复制请求头', self.copy_headers)
    menu.addAction('复制请求体', self.copy_body)
    menu.addAction('复制响应数据', self.copy_response)
    menu.addSeparator()
    menu.addAction('复制全部', self.copy_all)
    menu.exec(self.request_table.viewport().mapToGlobal(pos))

  def get_selected_request(self):
    indexes = self.request_table.selectedIndexes()
    if not indexes:
      return None
    row = indexes[0].row()
    item = self.request_table.item(row, 0)
    if not item:
      return None
    request_idx = item.data(Qt.ItemDataRole.UserRole)
    if request_idx is None or request_idx >= len(self.requests):
      return None
    return self.requests[request_idx]

  def copy_url(self):
    request = self.get_selected_request()
    if request:
      QApplication.clipboard().setText(request.url)
      self.status_bar.showMessage('[+] 已复制请求地址', 2000)

  def copy_headers(self):
    request = self.get_selected_request()
    if request:
      QApplication.clipboard().setText(json.dumps(request.header, indent=2, ensure_ascii=False))
      self.status_bar.showMessage('[+] 已复制请求头', 2000)

  def copy_body(self):
    request = self.get_selected_request()
    if request:
      QApplication.clipboard().setText(json.dumps(request.body, indent=2, ensure_ascii=False))
      self.status_bar.showMessage('[+] 已复制请求体', 2000)

  def copy_response(self):
    request = self.get_selected_request()
    if request:
      QApplication.clipboard().setText(json.dumps(request.response, indent=2, ensure_ascii=False))
      self.status_bar.showMessage('[+] 已复制响应数据', 2000)

  def copy_all(self):
    request = self.get_selected_request()
    if request:
      QApplication.clipboard().setText(json.dumps(request.to_dict(), indent=2, ensure_ascii=False))
      self.status_bar.showMessage('[+] 已复制全部数据', 2000)

  def export_json(self):
    if not self.requests:
      QMessageBox.information(self, '提示', '没有数据可导出')
      return
    filename = f'momo_数据包_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    data = [r.to_dict() for r in self.requests]
    try:
      with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
      self.status_bar.showMessage(f'[+] 已导出: {filename}', 3000)
    except Exception as e:
      QMessageBox.warning(self, '导出失败', str(e))

  def clear_requests(self):
    if not self.requests:
      return
    reply = QMessageBox.question(
      self, '确认', '确定要清空所有记录吗？',
      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
    )
    if reply == QMessageBox.StandardButton.Yes:
      self.requests.clear()
      self.request_table.setRowCount(0)
      self.url_text.clear()
      self.headers_text.clear()
      self.body_text.clear()
      self.response_text.clear()
      self.update_stats()
      self.status_bar.showMessage('[+] 已清空所有记录', 2000)

  def closeEvent(self, event):
    if self.frida_worker and self.frida_worker.isRunning():
      self.frida_worker.stop()
      self.frida_worker.wait()
    event.accept()

def main():
  app = QApplication(sys.argv)
  app.setFont(QFont('Consolas', 9))
  window = MainWindow()
  window.show()
  sys.exit(app.exec())

if __name__ == '__main__':
  main()
