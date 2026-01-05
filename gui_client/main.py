import logging
from coloredlogs import install

install(level=logging.DEBUG)
logger = logging.getLogger(__name__)

import typing
import sys
import asyncio
import signal

if sys.platform != "win32":
    USE_WINLOOP = False
    try:
        import uvloop
        logger.info("Using uvloop as event loop")
        USE_UVLOOP = True
    except ImportError:
        USE_UVLOOP = False
        logger.warning("uvloop not found, using default asyncio loop")
else:
    USE_UVLOOP = False
    try:
        import winloop
        logger.info("Using winloop as event loop")
        USE_WINLOOP = True
    except ImportError:
        USE_WINLOOP = False
        logger.warning("winloop not found, using default asyncio loop")

import config

from compiled_ui import Ui_MainWindow
from PySide6.QtCore import QThread, Signal, Slot
from PySide6.QtWidgets import QApplication, QMainWindow, QMessageBox, QTableWidgetItem, QPushButton
from PySide6.QtGui import Qt, QGuiApplication

import protocol
import logic

class BackendWorker(QThread):
    gui_query = Signal(dict)
    
    def __init__(self, parent):
        super().__init__(parent)
        self.runner = logic.AppLogic(send_event_to_gui=self.gui_query.emit)
        self.loop = None
    
    def run(self):
        if sys.platform != 'win32' and USE_UVLOOP:
            uvloop.install()  # type: ignore
        elif sys.platform == 'win32' and USE_WINLOOP:
            winloop.install() # type: ignore
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        try:
            self.loop.run_until_complete(self.runner.run())
        except Exception as e:
            logger.critical("BW: Runner finished with exception", exc_info=True)
        finally:
            self.loop.close()
    
    def stop(self):
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.runner.shutdown)
    def submit_event(self, action: str, data: dict):
        if self.loop and self.loop.is_running():
            coro = self.runner.handle_event_from_gui(action, data)
            asyncio.run_coroutine_threadsafe(coro, self.loop)
    

class MainWindow(QMainWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        
        self.backend = BackendWorker(self)
        self.backend.gui_query.connect(self.gui_update)
        self.backend.start()
    
    @Slot(dict)
    def gui_update(self, data: dict):
        logger.debug("GUI: data from backend: %s", data)
        match data["type"]:
            case "warn":
                self.warn("Ошибка", data["message"])
            case "left_room":
                self.unlock_data()
            case "update_data":
                match data["upd"]:
                    case "state":
                        self.ui.statusLabel.setText(f"Статус: {data['new']}")
                    case "roomuuid":
                        self.ui.roomUuidInfoEdit.setText(data['new'])
                    case "roomname":
                        self.ui.roomNameInfoEdit.setText(data["new"])
            case "add_port":
                user, user_port, mapped = data["user"], data["user_port"], data["mapped"]
                self.add_ports_row(user, user_port, mapped)
            case "rm_port":
                user, user_port = data["user"], data["user_port"]
                self.remove_ports_row(user, user_port)
            case _:
                logger.error("GUI: invalid data from backend: %s", data["type"])
    
    def add_ports_row(self, username: str, userport: str, map_port: str):
        row = self.ui.portsTableWidget.rowCount()
        self.ui.portsTableWidget.insertRow(row)
        self.ui.portsTableWidget.setItem(row, 0, QTableWidgetItem(username))
        self.ui.portsTableWidget.setItem(row, 1, QTableWidgetItem(userport))
        self.ui.portsTableWidget.setItem(row, 2, QTableWidgetItem(map_port))
        copy_button = QPushButton("Копировать")
        copy_button.clicked.connect(lambda: QGuiApplication.clipboard().setText(map_port))
        self.ui.portsTableWidget.setCellWidget(row, 3, copy_button)
    
    def remove_ports_row(self, username: str, userport: str):
        table = self.ui.portsTableWidget
        for row in range(table.rowCount() - 1, -1, -1):
            item_user = table.item(row, 0)
            item_port = table.item(row, 1)

            if item_user is not None and item_port is not None:
                if item_user.text() == username and item_port.text() == userport:
                    self.ui.portsTableWidget.removeRow(row)
                    break
    
    def closeEvent(self, event):
        logger.debug("GUI: closing, stopping backend")
        self.backend.stop()
        self.backend.wait()
        logger.debug("GUI: backend stopped")
        super().closeEvent(event)
        
    
    def warn(self, title, text: str):
        msgbox = QMessageBox(parent=self)
        msgbox.setWindowTitle(title)
        if text.startswith("[e]"):
            msgbox.setIcon(QMessageBox.Icon.Critical)
            text = text[3:]
        else:
            msgbox.setIcon(QMessageBox.Icon.Warning)
        msgbox.setText(text)
        msgbox.setStandardButtons(QMessageBox.StandardButton.Ok)
        msgbox.exec()
    
    def on_compression_selected(self, new_selected_type: str):
        should_allow_extcompress = new_selected_type.startswith("Zstd")
        unrel_enabled = self.ui.unrelChannelsCheckbox.checkState() == Qt.CheckState.Checked
        if should_allow_extcompress and (not unrel_enabled):
            self.ui.extendedCompressionCheckbox.setEnabled(True)
        else:
            self.ui.extendedCompressionCheckbox.setCheckState(Qt.CheckState.Unchecked)
            self.ui.extendedCompressionCheckbox.setEnabled(False)
            
    def on_mode_change(self, new_state):
        if new_state == Qt.CheckState.Checked:
            self.ui.extendedCompressionCheckbox.setCheckState(Qt.CheckState.Unchecked)
            self.ui.extendedCompressionCheckbox.setEnabled(False)
        elif new_state == Qt.CheckState.Unchecked:
            if self.ui.compressionComboBox.currentText().startswith("Zstd"):
                self.ui.extendedCompressionCheckbox.setEnabled(True)
        else:
            logger.error("Invalid check state: %s", new_state)
    
    def on_extcompress_change(self, new_state):
        if new_state == Qt.CheckState.Checked:
            self.ui.unrelChannelsCheckbox.setEnabled(False)
        elif new_state == Qt.CheckState.Unchecked:
            self.ui.unrelChannelsCheckbox.setEnabled(True)
        else:
            logger.error("Invalid check state: %s", new_state)
    
    def on_copy_room_uuid_click(self):
        QGuiApplication.clipboard().setText(self.ui.roomUuidInfoEdit.text())
    def on_copy_room_name_click(self):
        QGuiApplication.clipboard().setText(self.ui.roomNameInfoEdit.text())
    
    def on_add_port_share(self):
        n = self.ui.portNSpin.value()
        proto = self.ui.protoSelect.currentText()
        port_s = f"{str(n).zfill(5)}:{proto}"
        if len(self.ui.currentsharesList.findItems(port_s, Qt.MatchFlag.MatchExactly)) > 0:
            self.warn("Ошибка", "Вы уже делитесь доступом к порту")
        else:
            self.ui.currentsharesList.addItem(port_s)
    def on_remove_port(self):
        r = self.ui.currentsharesList.currentRow()
        if r == -1:
            self.warn("Ошибка", "Выберите порт в списке для удаления")
            return
        it = self.ui.currentsharesList.takeItem(r)
        del it
    def get_port_shares(self) -> list[tuple[int, typing.Literal["UDP", "TCP"]]]:
        its = [self.ui.currentsharesList.item(i).text() for i in range(self.ui.currentsharesList.count())]
        res = []
        for it in its:
            s = it.split(":")
            if len(s) != 2:
                logger.error("Error: invalid string in QListWidget: %s", it)
                return []
            if s[1] != "TCP" and s[1] != "UDP":
                logger.error("Error: invalid proto in QListWidget: %s", it)
                return []
            res.append((int(s[0]), s[1]))
        return res
    
    def on_connect_click(self):
        roomname = protocol.check_roomname(self.ui.roomnameEdit.text())
        username = protocol.check_username(self.ui.usernameEdit.text())
        connect_existent = self.ui.newroomButton.isChecked()
        if not connect_existent and not protocol.check_uuid4(self.ui.roomuuidEdit.text()):
            self.warn("Ошибка", "Неверный формат UUID")
            return
        roomuuid = self.ui.roomuuidEdit.text()
        if username is None:
            self.warn("Ошибка", "Неверный формат имени пользователя: от 4 до 48 символов, разрешены латинские буквы, цифры и некоторые спецсимволы")
            return
        if roomname is None:
            self.warn("Ошибка", "Неверный формат имени комнаты: от 4 до 48 символов, разрешены латинские буквы, цифры и некоторые спецсимволы")
            return
        comptxt = self.ui.compressionComboBox.currentText()
        COMPR_TABLE = {
            "Выкл.": "none",
            "LZ4": "lz4",
            "Zstd": "zstd",
            "Zstd slow": "zstd-hc"
        }
        settings = {
            "unrel": (self.ui.unrelChannelsCheckbox.checkState() == Qt.CheckState.Checked),
            "compression": COMPR_TABLE[comptxt],
            "ext_compression": (self.ui.extendedCompressionCheckbox.checkState() == Qt.CheckState.Checked),
            "ports": (self.get_port_shares())
        }
        self.lock_data()
        
        self.backend.submit_event("connect", {
            "username": username,
            "roomname": roomname,
            "create_new": connect_existent,
            "settings": settings,
            "roomuuid": roomuuid
        })
    def on_disconnect_click(self):
        self.backend.submit_event("leave_room", {})
    
    def lock_data(self):
        """Выключить все изменения в конфигурацию после начала подключения к серверу"""
        
        self.ui.usernameEdit.setEnabled(False)
        self.ui.settingsBox.setEnabled(False)
        self.ui.portShareBox.setEnabled(False)
        self.ui.connectionBox.setEnabled(False)
        
        self.ui.infoBox.setEnabled(True)
        self.ui.membersBox.setEnabled(True)
    
    def unlock_data(self):
        """Включить режим изменения конфигурации (клиент отключён от сервера)"""
        
        self.ui.infoBox.setEnabled(False)
        self.ui.membersBox.setEnabled(False)
        
        self.ui.usernameEdit.setEnabled(True)
        self.ui.settingsBox.setEnabled(True)
        self.ui.portShareBox.setEnabled(True)
        self.ui.connectionBox.setEnabled(True)
        
        self.ui.roomNameInfoEdit.setText("CoolRoom")
        self.ui.roomUuidInfoEdit.setText("00000000-0000-4000-8000-000000000000")
        self.ui.portsTableWidget.clearContents()
        
    
    def setup_logic(self):
        self.ui.compressionComboBox.currentTextChanged.connect(self.on_compression_selected)
        self.ui.unrelChannelsCheckbox.checkStateChanged.connect(self.on_mode_change)
        self.ui.extendedCompressionCheckbox.checkStateChanged.connect(self.on_extcompress_change)
        self.ui.copyRoomUuidButton.clicked.connect(self.on_copy_room_uuid_click)
        self.ui.copyRoomNameButton.clicked.connect(self.on_copy_room_name_click)
        self.ui.addPortButton.clicked.connect(self.on_add_port_share)
        self.ui.removePortButton.clicked.connect(self.on_remove_port)
        self.ui.connectButton.clicked.connect(self.on_connect_click)
        self.ui.disconnectButton.clicked.connect(self.on_disconnect_click)


def exit_app(*a, **kw):
    appl.quit()

if __name__ == "__main__":
    
    logging.getLogger("websockets.client").setLevel(logging.WARNING)
    
    logging.getLogger("aioice.ice").setLevel(logging.INFO)
    logging.getLogger("aiortc.rtcsctptransport").setLevel(logging.INFO)
    logging.getLogger("aiortc.rtcpeerconnection").setLevel(logging.INFO)
    
    appl = QApplication()
    
    if config.FORCE_STYLE is not None:
        appl.setStyle(config.FORCE_STYLE)
    
    if config.FORCE_THEME is not None:
        if config.FORCE_THEME == "dark":
            appl.styleHints().setColorScheme(Qt.ColorScheme.Dark)
        else:
            appl.styleHints().setColorScheme(Qt.ColorScheme.Light)
    
    window = MainWindow()
    window.setup_logic()
    
    signal.signal(signal.SIGINT, exit_app)
    
    logger.debug("set UI up")
    
    window.show()
    appl.exec()
