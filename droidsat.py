import sys
import re
import os
import subprocess
import tempfile
import shutil
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QAction,
    QFileDialog, QTableWidget, QTableWidgetItem, QLineEdit, QTextEdit,
    QHeaderView, QMessageBox, QTreeWidget, QTreeWidgetItem, QSplitter, QLabel
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from androguard.misc import AnalyzeAPK
from lxml import etree
from androguard.decompiler.decompiler import DecompilerDAD

# Expanded set of suspicious (malicious) permissions.
SUSPICIOUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.CALL_PHONE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BIND_DEVICE_ADMIN"
}

SUSPICIOUS_API_CALLS = {
    "getDeviceId", "getSubscriberId", "sendTextMessage",
    "exec", "loadLibrary", "getSimSerialNumber"
}

# Set environment variable to help with duplicate Qt warnings on macOS.
os.environ["QT_MAC_WANTS_LAYER"] = "1"

class APKAnalyzerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced APK Analysis Toolkit")
        self.resize(1400, 900)
        
        # Analysis and decompilation attributes
        self.apk = None
        self.apk_file = None         # APK file path
        self.dex_list = []
        self.dx = None
        self.decompiled_dir = None         # Directory for JADX output
        self.fallback_decompiled_dir = None  # Directory for dex2jar/jd-cli output
        self.api_calls_list = []           # For API calls table
        self.method_analysis_dict = {}     # Mapping (class, method, descriptor) -> method_analysis
        self.advanced_analysis_output = {} # External advanced analysis outputs
        
        # Main Tab Widget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # Initialize tabs
        self.init_overview_tab()
        self.init_manifest_tab()
        self.init_api_tab()
        self.init_dex_tab()
        self.init_security_tab()
        self.init_certificates_tab()
        self.init_source_tab()
        self.init_recon_tab()
        self.init_components_tab()
        self.init_advanced_tab()
        
        # Setup Menu/Toolbar
        openAction = QAction("Open APK", self)
        openAction.triggered.connect(self.open_file)
        menubar = self.menuBar()
        fileMenu = menubar.addMenu("File")
        fileMenu.addAction(openAction)
        
        # Apply modern white theme styles
        self.setup_styles()
    
    def setup_styles(self):
        style = """
        QMainWindow {
            background-color: #ffffff;
        }
        QTabWidget::pane {
            border: 1px solid #ddd;
            background: #ffffff;
        }
        QTabBar::tab {
            background: #f7f7f7;
            color: #333;
            padding: 8px;
            margin: 2px;
        }
        QTabBar::tab:selected {
            background: #ffffff;
            border-bottom: 2px solid #4285f4;
            font-weight: bold;
        }
        QTextEdit, QTreeWidget, QTableWidget, QLineEdit {
            background-color: #ffffff;
            color: #333;
            border: 1px solid #ccc;
        }
        QHeaderView::section {
            background-color: #f0f0f0;
            color: #333;
            padding: 4px;
            border: 1px solid #ccc;
        }
        QPushButton {
            background-color: #4285f4;
            color: #fff;
            border: none;
            padding: 5px;
        }
        """
        self.setStyleSheet(style)
    
    def init_overview_tab(self):
        self.overview_tab = QWidget()
        layout = QVBoxLayout()
        self.overview_text = QTextEdit()
        self.overview_text.setReadOnly(True)
        layout.addWidget(self.overview_text)
        self.overview_tab.setLayout(layout)
        self.tabs.addTab(self.overview_tab, "Overview")
    
    def init_manifest_tab(self):
        self.manifest_tab = QWidget()
        layout = QVBoxLayout()
        self.manifest_tree = QTreeWidget()
        self.manifest_tree.setHeaderLabels(["Tag", "Attributes", "Text"])
        layout.addWidget(self.manifest_tree)
        self.manifest_tab.setLayout(layout)
        self.tabs.addTab(self.manifest_tab, "Manifest")
    
    def init_api_tab(self):
        self.api_tab = QWidget()
        layout = QVBoxLayout()
        self.api_search = QLineEdit()
        self.api_search.setPlaceholderText("Search API Calls (regex supported)")
        self.api_search.textChanged.connect(self.filter_api_calls)
        layout.addWidget(self.api_search)
        
        self.api_table = QTableWidget()
        self.api_table.setColumnCount(4)
        self.api_table.setHorizontalHeaderLabels(["Method Name", "Class", "Descriptor", "Access Flags"])
        self.api_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.api_table.setAlternatingRowColors(True)
        self.api_table.itemClicked.connect(self.show_api_details)
        layout.addWidget(self.api_table)
        
        self.api_details = QTextEdit()
        self.api_details.setReadOnly(True)
        self.api_details.setFixedHeight(150)
        layout.addWidget(QLabel("API Call Details:"))
        layout.addWidget(self.api_details)
        
        self.api_tab.setLayout(layout)
        self.tabs.addTab(self.api_tab, "API Calls")
    
    def init_dex_tab(self):
        self.dex_tab = QWidget()
        layout = QVBoxLayout()
        self.dex_table = QTableWidget()
        self.dex_table.setColumnCount(2)
        self.dex_table.setHorizontalHeaderLabels(["Type", "File"])
        self.dex_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.dex_table.setAlternatingRowColors(True)
        layout.addWidget(self.dex_table)
        self.dex_tab.setLayout(layout)
        self.tabs.addTab(self.dex_tab, "DEX & Native")
    
    def init_security_tab(self):
        self.security_tab = QWidget()
        layout = QVBoxLayout()
        self.security_text = QTextEdit()
        self.security_text.setReadOnly(True)
        layout.addWidget(self.security_text)
        self.security_tab.setLayout(layout)
        self.tabs.addTab(self.security_tab, "Security")
    
    def init_certificates_tab(self):
        self.cert_tab = QWidget()
        layout = QVBoxLayout()
        self.cert_table = QTableWidget()
        self.cert_table.setColumnCount(4)
        self.cert_table.setHorizontalHeaderLabels(["Subject", "Issuer", "Serial Number", "Validity"])
        self.cert_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.cert_table.setAlternatingRowColors(True)
        layout.addWidget(self.cert_table)
        self.cert_tab.setLayout(layout)
        self.tabs.addTab(self.cert_tab, "Certificates")
    
    def init_source_tab(self):
        self.source_tab = QWidget()
        layout = QVBoxLayout()
        splitter = QSplitter(Qt.Horizontal)
        self.source_tree = QTreeWidget()
        self.source_tree.setHeaderLabels(["Class / Method"])
        self.source_tree.itemClicked.connect(self.on_source_item_clicked)
        splitter.addWidget(self.source_tree)
        self.source_code_text = QTextEdit()
        self.source_code_text.setReadOnly(True)
        splitter.addWidget(self.source_code_text)
        splitter.setStretchFactor(0, 30)
        splitter.setStretchFactor(1, 70)
        layout.addWidget(splitter)
        self.source_tab.setLayout(layout)
        self.tabs.addTab(self.source_tab, "Source Code")
    
    def init_recon_tab(self):
        self.recon_tab = QWidget()
        layout = QVBoxLayout()
        self.recon_tree = QTreeWidget()
        self.recon_tree.setHeaderLabels(["Category", "Detail"])
        layout.addWidget(self.recon_tree)
        self.recon_tab.setLayout(layout)
        self.tabs.addTab(self.recon_tab, "Recon")
    
    def init_components_tab(self):
        self.components_tab = QWidget()
        layout = QVBoxLayout()
        splitter = QSplitter(Qt.Horizontal)
        self.components_tree = QTreeWidget()
        self.components_tree.setHeaderLabels(["Component", "Count"])
        self.components_tree.itemClicked.connect(self.on_component_item_clicked)
        splitter.addWidget(self.components_tree)
        self.components_details = QTextEdit()
        self.components_details.setReadOnly(True)
        splitter.addWidget(self.components_details)
        splitter.setStretchFactor(0, 40)
        splitter.setStretchFactor(1, 60)
        layout.addWidget(splitter)
        self.components_tab.setLayout(layout)
        self.tabs.addTab(self.components_tab, "Components")
    
    def init_advanced_tab(self):
        self.advanced_tab = QWidget()
        layout = QVBoxLayout()
        self.advanced_text = QTextEdit()
        self.advanced_text.setReadOnly(True)
        layout.addWidget(self.advanced_text)
        self.advanced_tab.setLayout(layout)
        self.tabs.addTab(self.advanced_tab, "Advanced")
    
    def open_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open APK File", "", "APK Files (*.apk);;All Files (*)", options=options
        )
        if file_path:
            self.analyze_apk(file_path)
    
    def analyze_apk(self, file_path):
        try:
            self.apk, self.dex_list, self.dx = AnalyzeAPK(file_path)
            self.apk_file = file_path
            for d in self.dex_list:
                try:
                    d.set_decompiler(DecompilerDAD(d))
                except Exception as e:
                    print("Internal decompiler setup failed:", e)
            self.method_analysis_dict = {}
            for method_analysis in self.dx.get_methods():
                m = method_analysis.get_method()
                key = (m.get_class_name(), m.get_name(), m.get_descriptor())
                self.method_analysis_dict[key] = method_analysis

            self.decompile_apk_externally()
            self.run_fallback_decompilation()
            self.run_advanced_analysis()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to analyze APK:\n{e}")
            return
        
        self.update_overview_tab()
        self.update_manifest_tab()
        self.update_api_calls_tab()
        self.update_dex_native_tab()
        self.update_security_tab()
        self.update_certificates_tab()
        self.update_source_code_tab()
        self.update_recon_tab()
        self.update_components_tab()
        self.update_advanced_tab()
        self.tabs.setCurrentIndex(0)
    
    def decompile_apk_externally(self):
        self.decompiled_dir = tempfile.mkdtemp(prefix="jadx_output_")
        try:
            subprocess.run(["jadx", "-d", self.decompiled_dir, self.apk_file], check=True)
            print(f"JADX decompilation completed. Output: {self.decompiled_dir}")
        except Exception as e:
            print("JADX decompilation failed:", e)
            self.decompiled_dir = None
    
    def run_fallback_decompilation(self):
        self.fallback_decompiled_dir = tempfile.mkdtemp(prefix="jd_output_")
        try:
            jar_output = os.path.join(self.fallback_decompiled_dir, "output.jar")
            subprocess.run(["d2j-dex2jar", self.apk_file, "-o", jar_output],
                           check=True, capture_output=True, text=True)
            subprocess.run(["jd-cli", jar_output, "-od", self.fallback_decompiled_dir],
                           check=True, capture_output=True, text=True)
            print("Fallback decompilation completed. Output:", self.fallback_decompiled_dir)
        except Exception as e:
            print("Fallback decompilation failed:", e)
            self.fallback_decompiled_dir = None

    def run_advanced_static_analysis(self):
        analysis_results = {}
        manifest_xml = self.apk.get_android_manifest_xml()
        if manifest_xml is not None:
            manifest_str = etree.tostring(manifest_xml, pretty_print=True, encoding="utf-8").decode("utf-8")
            patterns = ["Class.forName", "getDeclaredMethod", "invoke", "Runtime.getRuntime", "exec(", "System.loadLibrary"]
            manifest_counts = {pattern: manifest_str.count(pattern) for pattern in patterns}
            analysis_results["Manifest Patterns"] = manifest_counts
        source_counts = {}
        if self.decompiled_dir:
            for root, dirs, files in os.walk(self.decompiled_dir):
                for file in files:
                    if file.endswith(".java"):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, "r", encoding="utf-8") as f:
                                content = f.read()
                                for pattern in ["Class.forName", "getDeclaredMethod", "invoke", "Runtime.getRuntime", "exec(", "System.loadLibrary"]:
                                    count = content.count(pattern)
                                    if count > 0:
                                        source_counts[pattern] = source_counts.get(pattern, 0) + count
                        except Exception:
                            continue
            analysis_results["Decompiled Source Patterns"] = source_counts
        return analysis_results

    def analyze_malicious_permissions(self):
        permissions = self.apk.get_permissions() or []
        malicious = set(permissions).intersection(SUSPICIOUS_PERMISSIONS)
        summary = f"Found {len(malicious)} suspicious permissions: " + ", ".join(malicious) if malicious else "No suspicious permissions detected."
        return summary

    def analyze_apktool_output(self, apktool_dir):
        """Enhance analysis by reading the APKTool output directory."""
        resource_summary = {}
        if os.path.isdir(apktool_dir):
            res_dir = os.path.join(apktool_dir, "res")
            if os.path.isdir(res_dir):
                count = sum([len(files) for r, d, files in os.walk(res_dir)])
                resource_summary["Total Resource Files"] = count
            manifest_path = os.path.join(apktool_dir, "AndroidManifest.xml")
            if os.path.exists(manifest_path):
                try:
                    with open(manifest_path, "r", encoding="utf-8") as f:
                        manifest_content = f.read()
                    resource_summary["Manifest Length"] = len(manifest_content)
                except Exception:
                    resource_summary["Manifest Length"] = "Error reading manifest."
        return resource_summary

    def run_advanced_analysis(self):
        self.advanced_analysis_output = {}
        # Run apkid
        try:
            result = subprocess.run(["apkid", self.apk_file],
                                    capture_output=True, text=True)
            if result.returncode != 0:
                self.advanced_analysis_output["APKID"] = f"Error running apkid: {result.stderr.strip()}"
            else:
                self.advanced_analysis_output["APKID"] = result.stdout
        except Exception as e:
            self.advanced_analysis_output["APKID"] = f"Error running apkid: {e}"
        # Run apktool and analyze its output
        try:
            apktool_output_dir = tempfile.mkdtemp(prefix="apktool_")
            subprocess.run(["apktool", "d", self.apk_file, "-o", apktool_output_dir, "-f"],
                           capture_output=True, text=True, check=True)
            self.advanced_analysis_output["APKTOOL"] = f"APKTool output directory: {apktool_output_dir}"
            res_analysis = self.analyze_apktool_output(apktool_output_dir)
            self.advanced_analysis_output["APKTOOL Resources"] = res_analysis
        except Exception as e:
            self.advanced_analysis_output["APKTOOL"] = f"Error running apktool: {e}"
        # Additional static analysis
        static_analysis = self.run_advanced_static_analysis()
        self.advanced_analysis_output["STATIC_ANALYSIS"] = static_analysis
        # Analyze malicious permissions
        perm_analysis = self.analyze_malicious_permissions()
        self.advanced_analysis_output["PERMISSIONS_ANALYSIS"] = perm_analysis

    def update_overview_tab(self):
        if not self.apk:
            return
        html = "<h2>App Overview</h2><hr>"
        html += "<h3>Basic Information</h3>"
        html += f"<b>App Name:</b> {self.apk.get_app_name()}<br>"
        html += f"<b>Package:</b> {self.apk.get_package()}<br>"
        html += f"<b>Version Code:</b> {self.apk.get_androidversion_code()}<br>"
        html += f"<b>Version Name:</b> {self.apk.get_androidversion_name()}<br><br>"
        
        perms = self.apk.get_permissions() or []
        html += f"<h3>Permissions ({len(perms)})</h3><ul>"
        for p in perms:
            if p in SUSPICIOUS_PERMISSIONS:
                html += f"<li><font color='red'>{p} (SUSPICIOUS)</font></li>"
            else:
                html += f"<li>{p}</li>"
        html += "</ul>"
        
        activities = self.apk.get_activities() or []
        html += f"<h3>Activities ({len(activities)})</h3><ul>"
        for a in activities:
            if "malware" in a.lower() or "spy" in a.lower():
                html += f"<li><font color='red'>{a} (SUSPICIOUS)</font></li>"
            else:
                html += f"<li>{a}</li>"
        html += "</ul>"
        
        purpose = self.analyze_purpose()
        html += f"<h3>Purpose Analysis</h3><p>{purpose}</p>"
        
        self.overview_text.setHtml(html)
    
    def update_manifest_tab(self):
        self.manifest_tree.clear()
        if not self.apk:
            return
        manifest_xml = self.apk.get_android_manifest_xml()
        if manifest_xml is None:
            return
        self.populate_manifest_tree(self.manifest_tree, manifest_xml)
        self.manifest_tree.expandAll()
    
    def populate_manifest_tree(self, tree_widget, xml_element, parent_item=None):
        attributes = " ".join([f'{k}="{v}"' for k, v in xml_element.attrib.items()])
        text = xml_element.text.strip() if xml_element.text and xml_element.text.strip() else ""
        item_text = [xml_element.tag, attributes, text]
        if parent_item is None:
            item = QTreeWidgetItem(tree_widget, item_text)
        else:
            item = QTreeWidgetItem(parent_item, item_text)
        for child in xml_element:
            self.populate_manifest_tree(tree_widget, child, item)
    
    def update_api_calls_tab(self):
        self.api_calls_list = []
        self.api_table.setRowCount(0)
        if not self.dx:
            return
        for method_analysis in self.dx.get_methods():
            m = method_analysis.get_method()
            entry = {
                "name": m.get_name(),
                "class": m.get_class_name(),
                "descriptor": m.get_descriptor(),
                "access": m.get_access_flags_string()
            }
            self.api_calls_list.append(entry)
        self.populate_api_table(self.api_calls_list)
    
    def populate_api_table(self, methods):
        self.api_table.setRowCount(0)
        for method in methods:
            row = self.api_table.rowCount()
            self.api_table.insertRow(row)
            item_name = QTableWidgetItem(method["name"])
            item_class = QTableWidgetItem(method["class"])
            item_desc = QTableWidgetItem(method["descriptor"])
            item_access = QTableWidgetItem(method["access"])
            
            if any(susp in method["name"] for susp in SUSPICIOUS_API_CALLS):
                for item in [item_name, item_class, item_desc, item_access]:
                    item.setBackground(QColor("lightcoral"))
            
            self.api_table.setItem(row, 0, item_name)
            self.api_table.setItem(row, 1, item_class)
            self.api_table.setItem(row, 2, item_desc)
            self.api_table.setItem(row, 3, item_access)
    
    def filter_api_calls(self, text):
        if not text:
            filtered = self.api_calls_list
        else:
            try:
                regex = re.compile(text)
                filtered = [m for m in self.api_calls_list if regex.search(m["name"]) or regex.search(m["class"]) or regex.search(m["descriptor"])]
            except re.error:
                filtered = [m for m in self.api_calls_list if text.lower() in m["name"].lower() or text.lower() in m["class"].lower() or text.lower() in m["descriptor"].lower()]
        self.populate_api_table(filtered)
    
    def show_api_details(self, item):
        row = item.row()
        name_item = self.api_table.item(row, 0)
        class_item = self.api_table.item(row, 1)
        desc_item = self.api_table.item(row, 2)
        access_item = self.api_table.item(row, 3)
        details = f"<b>Method Name:</b> {name_item.text()}<br>"
        details += f"<b>Class:</b> {class_item.text()}<br>"
        details += f"<b>Descriptor:</b> {desc_item.text()}<br>"
        details += f"<b>Access Flags:</b> {access_item.text()}<br>"
        self.api_details.setHtml(details)
    
    def update_dex_native_tab(self):
        self.dex_table.setRowCount(0)
        if not self.apk:
            return
        files = self.apk.get_files()
        for f in files:
            if f.endswith(".dex"):
                row = self.dex_table.rowCount()
                self.dex_table.insertRow(row)
                self.dex_table.setItem(row, 0, QTableWidgetItem("DEX"))
                self.dex_table.setItem(row, 1, QTableWidgetItem(f))
            elif f.startswith("lib/") and f.endswith(".so"):
                row = self.dex_table.rowCount()
                self.dex_table.insertRow(row)
                self.dex_table.setItem(row, 0, QTableWidgetItem("Native Library"))
                self.dex_table.setItem(row, 1, QTableWidgetItem(f))
    
    def update_security_tab(self):
        if not self.apk:
            return
        results = []
        try:
            debuggable = self.apk.is_debuggable()
        except Exception:
            debuggable = "Unknown"
        results.append(f"Debuggable: {debuggable}")
        
        manifest_xml = self.apk.get_android_manifest_xml()
        ns = manifest_xml.nsmap.copy() if manifest_xml is not None else {}
        if 'android' not in ns:
            ns['android'] = 'http://schemas.android.com/apk/res/android'
        net_sec_list = manifest_xml.xpath("//application/@android:networkSecurityConfig", namespaces=ns) if manifest_xml is not None else []
        net_sec = net_sec_list[0] if net_sec_list else "Not defined"
        results.append(f"Network Security Config: {net_sec}")
        
        class_names = self.get_all_class_names()
        short_count = sum(1 for cname in class_names if len(cname.strip("L;").split("/")[-1]) <= 2)
        obfuscation_ratio = short_count / len(class_names) if class_names else 0
        results.append(f"Obfuscation suspected: {'Yes' if obfuscation_ratio > 0.5 else 'No'} (Short names ratio: {obfuscation_ratio:.2f})")
        
        self.security_text.setPlainText("\n".join(results))
    
    def update_certificates_tab(self):
        self.cert_table.setRowCount(0)
        if not self.apk:
            return
        certs = self.apk.get_certificates()
        if not certs:
            return
        for cert in certs:
            row = self.cert_table.rowCount()
            self.cert_table.insertRow(row)
            try:
                subj_text = str(cert.get_subject())
            except Exception:
                subj_text = "N/A"
            try:
                issuer_text = str(cert.get_issuer())
            except Exception:
                issuer_text = "N/A"
            try:
                serial = hex(cert.get_serial_number())
            except Exception:
                serial = "N/A"
            try:
                notBefore = cert.get_notBefore().decode('utf-8') if hasattr(cert, "get_notBefore") else "N/A"
                notAfter = cert.get_notAfter().decode('utf-8') if hasattr(cert, "get_notAfter") else "N/A"
                validity = f"{notBefore} - {notAfter}"
            except Exception:
                validity = "N/A"
            self.cert_table.setItem(row, 0, QTableWidgetItem(subj_text))
            self.cert_table.setItem(row, 1, QTableWidgetItem(issuer_text))
            self.cert_table.setItem(row, 2, QTableWidgetItem(serial))
            self.cert_table.setItem(row, 3, QTableWidgetItem(validity))
    
    def update_source_code_tab(self):
        self.source_tree.clear()
        if not self.dex_list:
            return
        classes_dict = {}
        for d in self.dex_list:
            try:
                for cls in d.get_classes():
                    cname = cls.get_name()
                    if cname not in classes_dict:
                        classes_dict[cname] = cls.get_methods()
                    else:
                        classes_dict[cname].extend(cls.get_methods())
            except Exception:
                continue
        for cname, methods in classes_dict.items():
            class_item = QTreeWidgetItem(self.source_tree, [cname])
            class_item.setData(0, Qt.UserRole, None)
            for m in methods:
                key = (cname, m.get_name(), m.get_descriptor())
                method_item = QTreeWidgetItem(class_item, [m.get_name()])
                method_item.setData(0, Qt.UserRole, self.method_analysis_dict.get(key, None))
        self.source_tree.expandAll()
    
    def on_source_item_clicked(self, item, column):
        method_analysis = item.data(0, Qt.UserRole)
        if method_analysis:
            source = self.decompile_method(method_analysis)
            self.source_code_text.setPlainText(source)
        else:
            self.source_code_text.clear()
    
    def find_java_source(self, base_dir, simple_filename):
        """Recursively search for a file with the given simple filename."""
        for root, dirs, files in os.walk(base_dir):
            if simple_filename in files:
                return os.path.join(root, simple_filename)
        return None
    
    def decompile_method(self, method_analysis):
        method = method_analysis.get_method()
        class_name = method.get_class_name().strip("L;").replace("/", ".")
        simple_filename = class_name.split(".")[-1] + ".java"
        # Try expected path in JADX output
        if self.decompiled_dir:
            expected_path = os.path.join(self.decompiled_dir, *class_name.split(".")) + ".java"
            if os.path.exists(expected_path):
                try:
                    with open(expected_path, "r", encoding="utf-8") as f:
                        return f.read()
                except Exception as e:
                    return f"Error reading JADX file: {e}"
            # Fallback: search recursively
            found = self.find_java_source(self.decompiled_dir, simple_filename)
            if found:
                try:
                    with open(found, "r", encoding="utf-8") as f:
                        return f.read()
                except Exception as e:
                    return f"Error reading recursively found JADX file: {e}"
        # Then try fallback directory
        if self.fallback_decompiled_dir:
            expected_path = os.path.join(self.fallback_decompiled_dir, *class_name.split(".")) + ".java"
            if os.path.exists(expected_path):
                try:
                    with open(expected_path, "r", encoding="utf-8") as f:
                        return f.read()
                except Exception as e:
                    return f"Error reading fallback file: {e}"
            found = self.find_java_source(self.fallback_decompiled_dir, simple_filename)
            if found:
                try:
                    with open(found, "r", encoding="utf-8") as f:
                        return f.read()
                except Exception as e:
                    return f"Error reading recursively found fallback file: {e}"
        return f"Decompiled source file not found for {class_name}."
    
    def get_all_class_names(self):
        names = []
        for d in self.dex_list:
            try:
                for cls in d.get_classes():
                    names.append(cls.get_name())
            except Exception:
                continue
        return names
    
    def analyze_purpose(self):
        if not self.apk:
            return "No APK loaded."
        perms = self.apk.get_permissions() or []
        activities = self.apk.get_activities() or []
        purpose = ""
        sensitive_count = sum(1 for p in perms if p in SUSPICIOUS_PERMISSIONS)
        if sensitive_count >= 3:
            purpose += "This app requests several sensitive permissions, indicating potential for spying or malicious data collection. "
        else:
            purpose += "Permissions do not appear overly sensitive. "
        if any("login" in act.lower() for act in activities):
            purpose += "Contains authentication or login functionality. "
        if any("ad" in act.lower() for act in activities):
            purpose += "May include advertisement components. "
        if not purpose:
            purpose = "No clear purpose determined."
        return purpose
    
    def update_recon_tab(self):
        self.recon_tree.clear()
        if not self.apk:
            return
        manifest_xml = self.apk.get_android_manifest_xml()
        manifest_str = (etree.tostring(manifest_xml, pretty_print=True, encoding="utf-8")
                        .decode("utf-8") if manifest_xml is not None else "")
        emails = set(re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', manifest_str))
        urls = set(re.findall(r'https?://[^\s"\'<>]+', manifest_str))
        secrets = set(re.findall(r'(?i)(?:key|secret|token|password)\s*[:=]\s*["\']?([\w-]+)["\']?', manifest_str))
        all_strings = set(re.findall(r'["\']([^"\']{4,})["\']', manifest_str))
        def add_category(category, items):
            cat_item = QTreeWidgetItem(self.recon_tree, [category, f"{len(items)} found"])
            for i in items:
                QTreeWidgetItem(cat_item, ["", i])
            return cat_item
        add_category("Emails", emails if emails else ["None"])
        add_category("URLs", urls if urls else ["None"])
        add_category("Potential Secrets", secrets if secrets else ["None"])
        add_category("Hardcoded Strings", all_strings if all_strings else ["None"])
        self.recon_tree.expandAll()
    
    def update_components_tab(self):
        self.components_tree.clear()
        if not self.apk:
            return
        activities = self.apk.get_activities() or []
        act_item = QTreeWidgetItem(self.components_tree, ["Activities", f"{len(activities)}"])
        act_item.setData(0, Qt.UserRole, "List of all activities declared in the APK.")
        for act in activities:
            child = QTreeWidgetItem(act_item, [act, ""])
            child.setData(0, Qt.UserRole, f"Activity Name: {act}")
        services = self.apk.get_services() if hasattr(self.apk, "get_services") else []
        serv_item = QTreeWidgetItem(self.components_tree, ["Services", f"{len(services)}"])
        serv_item.setData(0, Qt.UserRole, "List of services declared in the APK.")
        for serv in services:
            child = QTreeWidgetItem(serv_item, [serv, ""])
            child.setData(0, Qt.UserRole, f"Service Name: {serv}")
        providers = self.apk.get_providers() if hasattr(self.apk, "get_providers") else []
        prov_item = QTreeWidgetItem(self.components_tree, ["Providers", f"{len(providers)}"])
        prov_item.setData(0, Qt.UserRole, "List of content providers declared in the APK.")
        for prov in providers:
            child = QTreeWidgetItem(prov_item, [prov, ""])
            child.setData(0, Qt.UserRole, f"Provider Name: {prov}")
        libraries = self.apk.get_libraries() if hasattr(self.apk, "get_libraries") else []
        lib_item = QTreeWidgetItem(self.components_tree, ["Libraries", f"{len(libraries)}"])
        lib_item.setData(0, Qt.UserRole, "List of native libraries included in the APK.")
        for lib in libraries:
            child = QTreeWidgetItem(lib_item, [lib, ""])
            child.setData(0, Qt.UserRole, f"Library: {lib}")
        files = self.apk.get_files() or []
        files_item = QTreeWidgetItem(self.components_tree, ["Files", f"{len(files)}"])
        files_item.setData(0, Qt.UserRole, "All files contained in the APK.")
        for f in files:
            child = QTreeWidgetItem(files_item, [f, ""])
            child.setData(0, Qt.UserRole, f"File path: {f}")
        sbom_item = QTreeWidgetItem(self.components_tree, ["SBOM", "Not Available"])
        sbom_item.setData(0, Qt.UserRole, "Software Bill of Materials information not available.")
        self.components_tree.expandAll()
    
    def on_component_item_clicked(self, item, column):
        detail = item.data(0, Qt.UserRole)
        if detail:
            self.components_details.setPlainText(detail)
        else:
            self.components_details.clear()
    
    def update_advanced_tab(self):
        if not self.advanced_analysis_output:
            self.advanced_text.setPlainText("No advanced analysis data available.")
            return
        output = "<h2>Advanced Analysis Report</h2>"
        # Basic info section
        output += "<h3>APK Information</h3>"
        output += f"<b>App Name:</b> {self.apk.get_app_name()}<br>"
        output += f"<b>Package:</b> {self.apk.get_package()}<br>"
        output += f"<b>Version:</b> {self.apk.get_androidversion_name()} ({self.apk.get_androidversion_code()})<br><br>"
        # Permissions analysis
        output += "<h3>Permissions Analysis</h3>"
        output += f"<p>{self.advanced_analysis_output.get('PERMISSIONS_ANALYSIS', '')}</p>"
        # APKID results
        output += "<h3>APKID Results</h3>"
        output += f"<pre>{self.advanced_analysis_output.get('APKID', '')}</pre>"
        # APKTool results and resource analysis
        output += "<h3>APKTool Analysis</h3>"
        output += f"<p>{self.advanced_analysis_output.get('APKTOOL', '')}</p>"
        res_analysis = self.advanced_analysis_output.get("APKTOOL Resources", {})
        output += "<ul>"
        for k, v in res_analysis.items():
            output += f"<li>{k}: {v}</li>"
        output += "</ul>"
        # Static analysis patterns
        output += "<h3>Static Analysis</h3>"
        static = self.advanced_analysis_output.get("STATIC_ANALYSIS", {})
        for section, data in static.items():
            output += f"<h4>{section}</h4><ul>"
            for pattern, count in data.items():
                output += f"<li>{pattern}: {count}</li>"
            output += "</ul>"
        self.advanced_text.setHtml(output)
    
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = APKAnalyzerWindow()
    window.show()
    sys.exit(app.exec_())
