#!/usr/bin/env python3
"""
Antivirus Scanner GUI

A comprehensive graphical interface for the antivirus scanner and security monitoring.
Uses tkinter for cross-platform compatibility.

Features:
- Full/Quick scans for malware and keyloggers
- Process, filesystem, and input device scanning
- Screen sharing and remote viewing detection
- Network connection monitoring (SSH, FTP, etc.)
- Startup program monitoring with encrypted persistence
- Real-time threat monitoring

Usage:
    python -m daemon.security.antivirus_gui
    # or
    ./daemon/security/antivirus_gui.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
from datetime import datetime

# Import scanner components
from .antivirus import (
    AntivirusScanner, StartupMonitor, RealTimeMonitor,
    ThreatLevel, ThreatCategory
)


class AntivirusGUI:
    """Main GUI application for the antivirus scanner."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Boundary Daemon - Security Scanner")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)

        # Initialize scanner components
        self.scanner = AntivirusScanner()
        self.startup_monitor = StartupMonitor(
            notification_callback=self._on_startup_notification
        )
        self.realtime_monitor = RealTimeMonitor(
            self.scanner,
            callback=self._on_realtime_threat
        )

        # Message queue for thread-safe GUI updates
        self.msg_queue = queue.Queue()

        # Track running operations
        self.scan_running = False
        self.startup_monitor_running = False
        self.realtime_monitor_running = False

        # Build the GUI
        self._setup_styles()
        self._create_widgets()

        # Start queue processor
        self._process_queue()

        # Show initial status
        self._update_scanner_status()

    def _setup_styles(self):
        """Configure ttk styles."""
        style = ttk.Style()
        style.configure('Title.TLabel', font=('Helvetica', 14, 'bold'))
        style.configure('Subtitle.TLabel', font=('Helvetica', 11, 'bold'))
        style.configure('Status.TLabel', font=('Helvetica', 10))
        style.configure('Scan.TButton', padding=8)
        style.configure('Action.TButton', padding=5)
        style.configure('Monitor.TButton', padding=8)

    def _create_widgets(self):
        """Create all GUI widgets."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="5")
        main_frame.grid(row=0, column=0, sticky="nsew")

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)

        # === Header Section ===
        self._create_header(main_frame)

        # === Notebook (Tabbed Interface) ===
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=1, column=0, sticky="nsew", pady=(5, 0))

        # Create tabs
        self._create_scan_tab()
        self._create_startup_tab()
        self._create_network_tab()
        self._create_screen_tab()
        self._create_monitor_tab()

        # === Status Bar ===
        self._create_status_bar(main_frame)

    def _create_header(self, parent):
        """Create header section."""
        header_frame = ttk.Frame(parent)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        header_frame.columnconfigure(1, weight=1)

        ttk.Label(
            header_frame,
            text="Security Scanner",
            style='Title.TLabel'
        ).grid(row=0, column=0, sticky="w")

        self.status_label = ttk.Label(
            header_frame,
            text="Ready",
            style='Status.TLabel'
        )
        self.status_label.grid(row=0, column=2, sticky="e")

        # Clear button
        ttk.Button(
            header_frame,
            text="Clear Log",
            command=self._clear_log
        ).grid(row=0, column=1, sticky="e", padx=10)

    def _create_scan_tab(self):
        """Create the main scanning tab."""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Scanning")

        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        # Button frame
        btn_frame = ttk.LabelFrame(tab, text="Scan Options", padding="10")
        btn_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        # Row 1: Main scans
        row1 = ttk.Frame(btn_frame)
        row1.pack(fill="x", pady=(0, 5))

        self.full_scan_btn = ttk.Button(
            row1, text="Full Scan", command=self._run_full_scan, style='Scan.TButton'
        )
        self.full_scan_btn.pack(side="left", padx=(0, 5))

        self.quick_scan_btn = ttk.Button(
            row1, text="Quick Scan", command=self._run_quick_scan, style='Scan.TButton'
        )
        self.quick_scan_btn.pack(side="left", padx=5)

        ttk.Separator(row1, orient="vertical").pack(side="left", padx=10, fill="y")

        self.process_scan_btn = ttk.Button(
            row1, text="Scan Processes", command=self._run_process_scan, style='Action.TButton'
        )
        self.process_scan_btn.pack(side="left", padx=5)

        self.filesystem_scan_btn = ttk.Button(
            row1, text="Scan Filesystem", command=self._run_filesystem_scan, style='Action.TButton'
        )
        self.filesystem_scan_btn.pack(side="left", padx=5)

        self.input_scan_btn = ttk.Button(
            row1, text="Scan Input Devices", command=self._run_input_scan, style='Action.TButton'
        )
        self.input_scan_btn.pack(side="left", padx=5)

        self.persistence_scan_btn = ttk.Button(
            row1, text="Scan Persistence", command=self._run_persistence_scan, style='Action.TButton'
        )
        self.persistence_scan_btn.pack(side="left", padx=5)

        # Results area
        results_frame = ttk.LabelFrame(tab, text="Results", padding="5")
        results_frame.grid(row=1, column=0, sticky="nsew")
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            wrap=tk.WORD,
            font=('Courier', 10),
            state='disabled'
        )
        self.results_text.grid(row=0, column=0, sticky="nsew")

        # Configure text tags for coloring
        self._configure_text_tags(self.results_text)

    def _create_startup_tab(self):
        """Create the startup programs tab."""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Startup Programs")

        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        # Button frame
        btn_frame = ttk.LabelFrame(tab, text="Startup Monitor", padding="10")
        btn_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        row1 = ttk.Frame(btn_frame)
        row1.pack(fill="x")

        self.startup_init_btn = ttk.Button(
            row1, text="Initialize Baseline", command=self._run_startup_init, style='Scan.TButton'
        )
        self.startup_init_btn.pack(side="left", padx=(0, 5))

        self.startup_check_btn = ttk.Button(
            row1, text="Check for New Programs", command=self._run_startup_check, style='Scan.TButton'
        )
        self.startup_check_btn.pack(side="left", padx=5)

        self.startup_list_btn = ttk.Button(
            row1, text="List All Programs", command=self._run_startup_list, style='Action.TButton'
        )
        self.startup_list_btn.pack(side="left", padx=5)

        ttk.Separator(row1, orient="vertical").pack(side="left", padx=10, fill="y")

        self.startup_monitor_btn = ttk.Button(
            row1, text="Start Hourly Monitor", command=self._toggle_startup_monitor, style='Monitor.TButton'
        )
        self.startup_monitor_btn.pack(side="left", padx=5)

        # Info label
        info_frame = ttk.Frame(btn_frame)
        info_frame.pack(fill="x", pady=(10, 0))

        self.startup_info_label = ttk.Label(
            info_frame,
            text=f"Known programs: {len(self.startup_monitor.get_known_programs())} | "
                 f"Data file: {self.startup_monitor.data_file}"
        )
        self.startup_info_label.pack(side="left")

        # Results
        results_frame = ttk.LabelFrame(tab, text="Startup Programs", padding="5")
        results_frame.grid(row=1, column=0, sticky="nsew")
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        self.startup_text = scrolledtext.ScrolledText(
            results_frame,
            wrap=tk.WORD,
            font=('Courier', 10),
            state='disabled'
        )
        self.startup_text.grid(row=0, column=0, sticky="nsew")
        self._configure_text_tags(self.startup_text)

    def _create_network_tab(self):
        """Create the network monitoring tab."""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Network")

        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        # Button frame
        btn_frame = ttk.LabelFrame(tab, text="Network Monitoring", padding="10")
        btn_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        row1 = ttk.Frame(btn_frame)
        row1.pack(fill="x")

        self.network_scan_btn = ttk.Button(
            row1, text="Full Network Scan", command=self._run_network_scan, style='Scan.TButton'
        )
        self.network_scan_btn.pack(side="left", padx=(0, 5))

        ttk.Separator(row1, orient="vertical").pack(side="left", padx=10, fill="y")

        self.ssh_btn = ttk.Button(
            row1, text="SSH Sessions", command=self._show_ssh_sessions, style='Action.TButton'
        )
        self.ssh_btn.pack(side="left", padx=5)

        self.ftp_btn = ttk.Button(
            row1, text="FTP Connections", command=self._show_ftp_connections, style='Action.TButton'
        )
        self.ftp_btn.pack(side="left", padx=5)

        self.connections_btn = ttk.Button(
            row1, text="All Connections", command=self._show_all_connections, style='Action.TButton'
        )
        self.connections_btn.pack(side="left", padx=5)

        # Results
        results_frame = ttk.LabelFrame(tab, text="Network Activity", padding="5")
        results_frame.grid(row=1, column=0, sticky="nsew")
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        self.network_text = scrolledtext.ScrolledText(
            results_frame,
            wrap=tk.WORD,
            font=('Courier', 10),
            state='disabled'
        )
        self.network_text.grid(row=0, column=0, sticky="nsew")
        self._configure_text_tags(self.network_text)

    def _create_screen_tab(self):
        """Create the screen sharing detection tab."""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Screen Sharing")

        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        # Button frame
        btn_frame = ttk.LabelFrame(tab, text="Screen Sharing Detection", padding="10")
        btn_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        row1 = ttk.Frame(btn_frame)
        row1.pack(fill="x")

        self.screen_scan_btn = ttk.Button(
            row1, text="Scan for Screen Sharing", command=self._run_screen_scan, style='Scan.TButton'
        )
        self.screen_scan_btn.pack(side="left", padx=(0, 5))

        self.screen_quick_btn = ttk.Button(
            row1, text="Quick Check", command=self._run_screen_quick_check, style='Action.TButton'
        )
        self.screen_quick_btn.pack(side="left", padx=5)

        # Info
        info_label = ttk.Label(
            btn_frame,
            text="Detects: VNC, RDP, TeamViewer, AnyDesk, RustDesk, X11 capture, D-Bus screen sharing, SSH X11 forwarding"
        )
        info_label.pack(anchor="w", pady=(10, 0))

        # Results
        results_frame = ttk.LabelFrame(tab, text="Screen Sharing Status", padding="5")
        results_frame.grid(row=1, column=0, sticky="nsew")
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        self.screen_text = scrolledtext.ScrolledText(
            results_frame,
            wrap=tk.WORD,
            font=('Courier', 10),
            state='disabled'
        )
        self.screen_text.grid(row=0, column=0, sticky="nsew")
        self._configure_text_tags(self.screen_text)

    def _create_monitor_tab(self):
        """Create the real-time monitoring tab."""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Real-Time Monitor")

        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        # Control frame
        ctrl_frame = ttk.LabelFrame(tab, text="Real-Time Monitoring", padding="10")
        ctrl_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        row1 = ttk.Frame(ctrl_frame)
        row1.pack(fill="x")

        self.realtime_btn = ttk.Button(
            row1, text="Start Real-Time Monitor", command=self._toggle_realtime_monitor, style='Monitor.TButton'
        )
        self.realtime_btn.pack(side="left", padx=(0, 10))

        self.realtime_status = ttk.Label(row1, text="Status: Stopped", style='Status.TLabel')
        self.realtime_status.pack(side="left")

        # Info
        info_frame = ttk.Frame(ctrl_frame)
        info_frame.pack(fill="x", pady=(10, 0))

        ttk.Label(
            info_frame,
            text="Monitors for: New suspicious processes, keylogger indicators, input device access"
        ).pack(anchor="w")

        # Scanner status
        status_frame = ttk.LabelFrame(tab, text="Scanner Status", padding="10")
        status_frame.grid(row=1, column=0, sticky="nsew")
        status_frame.columnconfigure(1, weight=1)

        # Status info
        self.scanner_status_labels = {}
        status_items = [
            ("Signatures loaded", "signatures"),
            ("File patterns", "patterns"),
            ("Monitored directories", "directories"),
            ("Screen sharing signatures", "screen_sigs"),
            ("Network ports monitored", "network_ports"),
            ("Network process signatures", "network_procs"),
        ]

        for i, (label, key) in enumerate(status_items):
            ttk.Label(status_frame, text=f"{label}:").grid(row=i, column=0, sticky="w", pady=2)
            self.scanner_status_labels[key] = ttk.Label(status_frame, text="0")
            self.scanner_status_labels[key].grid(row=i, column=1, sticky="w", padx=10, pady=2)

        # Refresh button
        ttk.Button(
            status_frame, text="Refresh Status", command=self._update_scanner_status
        ).grid(row=len(status_items), column=0, columnspan=2, pady=(10, 0))

        # Monitor log
        log_frame = ttk.LabelFrame(tab, text="Monitor Log", padding="5")
        log_frame.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        tab.rowconfigure(2, weight=1)

        self.monitor_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            font=('Courier', 10),
            state='disabled',
            height=10
        )
        self.monitor_text.grid(row=0, column=0, sticky="nsew")
        self._configure_text_tags(self.monitor_text)

    def _create_status_bar(self, parent):
        """Create status bar."""
        status_frame = ttk.Frame(parent)
        status_frame.grid(row=2, column=0, sticky="ew", pady=(5, 0))

        self.progress = ttk.Progressbar(
            status_frame,
            mode='indeterminate',
            length=200
        )
        self.progress.pack(side="left", padx=(0, 10))

        self.detail_label = ttk.Label(status_frame, text="")
        self.detail_label.pack(side="left", fill="x", expand=True)

        self.known_count_label = ttk.Label(
            status_frame,
            text=f"Known startup programs: {len(self.startup_monitor.get_known_programs())}"
        )
        self.known_count_label.pack(side="right")

    def _configure_text_tags(self, text_widget):
        """Configure text tags for a text widget."""
        text_widget.tag_configure('info', foreground='#2196F3')
        text_widget.tag_configure('success', foreground='#4CAF50')
        text_widget.tag_configure('warning', foreground='#FF9800')
        text_widget.tag_configure('error', foreground='#F44336')
        text_widget.tag_configure('critical', foreground='#D32F2F', font=('Courier', 10, 'bold'))
        text_widget.tag_configure('header', font=('Courier', 11, 'bold'))

    def _log(self, message: str, tag: str = None, target: str = 'results'):
        """Add message to a text area."""
        self.msg_queue.put(('log', message, tag, target))

    def _update_status(self, status: str):
        """Update status label."""
        self.msg_queue.put(('status', status, None, None))

    def _update_detail(self, detail: str):
        """Update detail label."""
        self.msg_queue.put(('detail', detail, None, None))

    def _clear_log(self):
        """Clear all log areas."""
        for widget in [self.results_text, self.startup_text, self.network_text,
                       self.screen_text, self.monitor_text]:
            widget.configure(state='normal')
            widget.delete('1.0', tk.END)
            widget.configure(state='disabled')

    def _process_queue(self):
        """Process messages from the queue (thread-safe GUI updates)."""
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                msg_type = msg[0]
                content = msg[1]
                tag = msg[2] if len(msg) > 2 else None
                target = msg[3] if len(msg) > 3 else 'results'

                if msg_type == 'log':
                    widget_map = {
                        'results': self.results_text,
                        'startup': self.startup_text,
                        'network': self.network_text,
                        'screen': self.screen_text,
                        'monitor': self.monitor_text,
                    }
                    widget = widget_map.get(target, self.results_text)
                    widget.configure(state='normal')
                    if tag:
                        widget.insert(tk.END, content + '\n', tag)
                    else:
                        widget.insert(tk.END, content + '\n')
                    widget.see(tk.END)
                    widget.configure(state='disabled')

                elif msg_type == 'status':
                    self.status_label.configure(text=content)

                elif msg_type == 'detail':
                    self.detail_label.configure(text=content)

                elif msg_type == 'progress_start':
                    self.progress.start(10)

                elif msg_type == 'progress_stop':
                    self.progress.stop()

                elif msg_type == 'update_known_count':
                    count = len(self.startup_monitor.get_known_programs())
                    self.known_count_label.configure(text=f"Known startup programs: {count}")
                    self.startup_info_label.configure(
                        text=f"Known programs: {count} | Data file: {self.startup_monitor.data_file}"
                    )

                elif msg_type == 'enable_buttons':
                    self._set_buttons_state('normal')

        except queue.Empty:
            pass

        self.root.after(100, self._process_queue)

    def _set_buttons_state(self, state: str):
        """Enable or disable scan buttons."""
        buttons = [
            self.full_scan_btn, self.quick_scan_btn, self.process_scan_btn,
            self.filesystem_scan_btn, self.input_scan_btn, self.persistence_scan_btn,
            self.startup_init_btn, self.startup_check_btn, self.startup_list_btn,
            self.network_scan_btn, self.ssh_btn, self.ftp_btn, self.connections_btn,
            self.screen_scan_btn, self.screen_quick_btn,
        ]
        for btn in buttons:
            btn.configure(state=state)

    def _run_in_thread(self, func, *args):
        """Run a function in a background thread."""
        if self.scan_running:
            return False
        self.scan_running = True
        self._set_buttons_state('disabled')
        self.msg_queue.put(('progress_start', None, None, None))
        threading.Thread(target=func, args=args, daemon=True).start()
        return True

    def _finish_scan(self):
        """Common cleanup after a scan."""
        self.scan_running = False
        self.msg_queue.put(('progress_stop', None, None, None))
        self.msg_queue.put(('enable_buttons', None, None, None))

    # ==================== Scan Tab Methods ====================

    def _run_full_scan(self):
        """Run full antivirus scan."""
        if not self._run_in_thread(self._do_full_scan):
            return

    def _do_full_scan(self):
        try:
            self._log("=" * 60, 'header')
            self._log("FULL SCAN", 'header')
            self._log("=" * 60, 'header')
            self._log("")
            self._log("Scanning all areas... This may take a few minutes.", 'info')
            self._log("")

            self._update_status("Full scanning...")
            self._update_detail("Scanning processes, files, input devices, persistence, screen, network...")

            result = self.scanner.full_scan()

            self._log(f"Items scanned: {result.items_scanned}", 'info')
            self._log(f"Threats found: {result.threat_count}",
                     'error' if result.threat_count > 0 else 'success')
            self._log("")

            if result.threats_found:
                self._display_threats(result.threats_found)
            else:
                self._log("No threats detected.", 'success')

            if result.errors:
                self._log(f"\nErrors during scan: {len(result.errors)}", 'warning')

            self._update_status("Ready")
            self._update_detail(f"Scanned {result.items_scanned} items")

        except Exception as e:
            self._log(f"\nError: {str(e)}", 'error')
            self._update_status("Error")
        finally:
            self._finish_scan()

    def _run_quick_scan(self):
        if not self._run_in_thread(self._do_quick_scan):
            return

    def _do_quick_scan(self):
        try:
            self._log("=" * 60, 'header')
            self._log("QUICK SCAN", 'header')
            self._log("=" * 60, 'header')
            self._log("")

            self._update_status("Quick scanning...")
            self._update_detail("Scanning processes and input devices...")

            result = self.scanner.quick_scan()

            self._log(f"Items scanned: {result.items_scanned}", 'info')
            self._log(f"Threats found: {result.threat_count}",
                     'error' if result.threat_count > 0 else 'success')
            self._log("")

            if result.threats_found:
                self._display_threats(result.threats_found)
            else:
                self._log("No threats detected.", 'success')

            self._update_status("Ready")
            self._update_detail("")

        except Exception as e:
            self._log(f"\nError: {str(e)}", 'error')
        finally:
            self._finish_scan()

    def _run_process_scan(self):
        if not self._run_in_thread(self._do_process_scan):
            return

    def _do_process_scan(self):
        try:
            self._log("=" * 60, 'header')
            self._log("PROCESS SCAN", 'header')
            self._log("=" * 60, 'header')
            self._log("")

            self._update_status("Scanning processes...")
            self._update_detail("Checking running processes for keylogger signatures...")

            result = self.scanner.scan_processes()

            self._log(f"Processes scanned: {result.items_scanned}", 'info')
            self._log(f"Threats found: {result.threat_count}",
                     'error' if result.threat_count > 0 else 'success')
            self._log("")

            if result.threats_found:
                self._display_threats(result.threats_found)
            else:
                self._log("No suspicious processes detected.", 'success')

            self._update_status("Ready")

        except Exception as e:
            self._log(f"\nError: {str(e)}", 'error')
        finally:
            self._finish_scan()

    def _run_filesystem_scan(self):
        if not self._run_in_thread(self._do_filesystem_scan):
            return

    def _do_filesystem_scan(self):
        try:
            self._log("=" * 60, 'header')
            self._log("FILESYSTEM SCAN", 'header')
            self._log("=" * 60, 'header')
            self._log("")

            self._update_status("Scanning filesystem...")
            self._update_detail("Checking suspicious directories for malware...")

            result = self.scanner.scan_filesystem()

            self._log(f"Files scanned: {result.items_scanned}", 'info')
            self._log(f"Threats found: {result.threat_count}",
                     'error' if result.threat_count > 0 else 'success')
            self._log("")

            if result.threats_found:
                self._display_threats(result.threats_found)
            else:
                self._log("No suspicious files detected.", 'success')

            if result.errors:
                self._log(f"\nPermission errors: {len(result.errors)}", 'warning')

            self._update_status("Ready")

        except Exception as e:
            self._log(f"\nError: {str(e)}", 'error')
        finally:
            self._finish_scan()

    def _run_input_scan(self):
        if not self._run_in_thread(self._do_input_scan):
            return

    def _do_input_scan(self):
        try:
            self._log("=" * 60, 'header')
            self._log("INPUT DEVICE SCAN", 'header')
            self._log("=" * 60, 'header')
            self._log("")

            self._update_status("Scanning input devices...")
            self._update_detail("Checking for unauthorized input device access...")

            result = self.scanner.scan_input_devices()

            self._log(f"Items checked: {result.items_scanned}", 'info')
            self._log(f"Issues found: {result.threat_count}",
                     'error' if result.threat_count > 0 else 'success')
            self._log("")

            if result.threats_found:
                self._display_threats(result.threats_found)
            else:
                self._log("No unauthorized input device access detected.", 'success')

            self._update_status("Ready")

        except Exception as e:
            self._log(f"\nError: {str(e)}", 'error')
        finally:
            self._finish_scan()

    def _run_persistence_scan(self):
        if not self._run_in_thread(self._do_persistence_scan):
            return

    def _do_persistence_scan(self):
        try:
            self._log("=" * 60, 'header')
            self._log("PERSISTENCE MECHANISM SCAN", 'header')
            self._log("=" * 60, 'header')
            self._log("")

            self._update_status("Scanning persistence mechanisms...")
            self._update_detail("Checking startup scripts, services, cron jobs...")

            result = self.scanner.scan_persistence_mechanisms()

            self._log(f"Locations checked: {result.items_scanned}", 'info')
            self._log(f"Issues found: {result.threat_count}",
                     'error' if result.threat_count > 0 else 'success')
            self._log("")

            if result.threats_found:
                self._display_threats(result.threats_found)
            else:
                self._log("No suspicious persistence mechanisms detected.", 'success')

            self._update_status("Ready")

        except Exception as e:
            self._log(f"\nError: {str(e)}", 'error')
        finally:
            self._finish_scan()

    def _display_threats(self, threats, target='results'):
        """Display detected threats."""
        self._log("THREATS DETECTED:", 'error', target)
        self._log("", target=target)

        for threat in threats:
            level = threat.level.value.upper()
            tag = 'critical' if threat.level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH] else 'warning'

            self._log(f"[{level}] {threat.name}", tag, target)
            self._log(f"  Category: {threat.category.value}", target=target)
            self._log(f"  Location: {threat.location}", target=target)
            self._log(f"  Description: {threat.description}", target=target)
            if threat.evidence:
                self._log(f"  Evidence: {threat.evidence[:100]}", target=target)
            if threat.remediation:
                self._log(f"  Remediation: {threat.remediation}", 'info', target)
            self._log("", target=target)

    # ==================== Startup Tab Methods ====================

    def _run_startup_init(self):
        if not self._run_in_thread(self._do_startup_init):
            return

    def _do_startup_init(self):
        try:
            self._log("=" * 60, 'header', 'startup')
            self._log("INITIALIZING STARTUP BASELINE", 'header', 'startup')
            self._log("=" * 60, 'header', 'startup')
            self._log("", target='startup')

            self._update_status("Scanning startup programs...")
            self._update_detail("Scanning all startup locations...")

            programs = self.startup_monitor.scan_startup_programs()

            self._log(f"Found {len(programs)} startup programs:\n", 'info', 'startup')

            by_location = {}
            for prog_id, prog in programs.items():
                loc = prog.get('location', 'unknown')
                if loc not in by_location:
                    by_location[loc] = []
                by_location[loc].append(prog)

            for location, progs in sorted(by_location.items()):
                self._log(f"\n[{location.upper()}] ({len(progs)} programs)", 'header', 'startup')
                for p in progs:
                    self._log(f"  - {p.get('name', 'unknown')}", 'info', 'startup')
                    if p.get('exec'):
                        self._log(f"    {p['exec'][:60]}...", target='startup')

            self._update_detail("Saving encrypted baseline...")
            count = self.startup_monitor.initialize_baseline()

            self._log("", target='startup')
            self._log("=" * 60, 'success', 'startup')
            self._log(f"Baseline initialized with {count} programs", 'success', 'startup')
            self._log("=" * 60, 'success', 'startup')

            self._update_status("Ready")
            self._update_detail(f"Baseline saved: {count} programs")
            self.msg_queue.put(('update_known_count', None, None, None))

        except Exception as e:
            self._log(f"\nError: {str(e)}", 'error', 'startup')
        finally:
            self._finish_scan()

    def _run_startup_check(self):
        if not self.startup_monitor.get_known_programs():
            messagebox.showinfo("No Baseline", "Please initialize baseline first.")
            return
        if not self._run_in_thread(self._do_startup_check):
            return

    def _do_startup_check(self):
        try:
            self._log("=" * 60, 'header', 'startup')
            self._log("CHECKING FOR NEW PROGRAMS", 'header', 'startup')
            self._log("=" * 60, 'header', 'startup')
            self._log("", target='startup')

            self._update_status("Checking...")
            self._update_detail("Comparing to baseline...")

            new_programs = self.startup_monitor.check_for_new_programs()

            if new_programs:
                self._log(f"Found {len(new_programs)} NEW startup programs:\n", 'warning', 'startup')

                for prog in new_programs:
                    self._log(f"\n  NEW: {prog.get('name', 'unknown')}", 'warning', 'startup')
                    self._log(f"  Type: {prog.get('type', 'unknown')}", target='startup')
                    self._log(f"  Location: {prog.get('path', 'unknown')}", target='startup')
                    if prog.get('exec'):
                        self._log(f"  Command: {prog['exec'][:80]}", target='startup')
                    self._log("", target='startup')
                    self._log("  If you installed this recently, no action needed.", 'info', 'startup')

                self._update_status(f"{len(new_programs)} new programs")
            else:
                self._log("No new startup programs detected.", 'success', 'startup')
                self._log("All programs match the known baseline.", 'success', 'startup')
                self._update_status("No changes")

            self.msg_queue.put(('update_known_count', None, None, None))
            self._update_detail("")

        except Exception as e:
            self._log(f"\nError: {str(e)}", 'error', 'startup')
        finally:
            self._finish_scan()

    def _run_startup_list(self):
        if not self._run_in_thread(self._do_startup_list):
            return

    def _do_startup_list(self):
        try:
            self._log("=" * 60, 'header', 'startup')
            self._log("ALL STARTUP PROGRAMS", 'header', 'startup')
            self._log("=" * 60, 'header', 'startup')
            self._log("", target='startup')

            self._update_status("Scanning...")

            programs = self.startup_monitor.scan_startup_programs()

            self._log(f"Found {len(programs)} startup programs:\n", 'info', 'startup')

            by_location = {}
            for prog_id, prog in programs.items():
                loc = prog.get('location', 'unknown')
                if loc not in by_location:
                    by_location[loc] = []
                by_location[loc].append(prog)

            for location, progs in sorted(by_location.items()):
                self._log(f"\n[{location.upper()}] ({len(progs)} programs)", 'header', 'startup')
                for p in progs:
                    self._log(f"  - {p.get('name', 'unknown')}", 'info', 'startup')
                    self._log(f"    Type: {p.get('type', 'unknown')}", target='startup')
                    self._log(f"    Path: {p.get('path', 'unknown')}", target='startup')
                    if p.get('exec'):
                        self._log(f"    Exec: {p['exec'][:60]}...", target='startup')

            self._update_status("Ready")

        except Exception as e:
            self._log(f"\nError: {str(e)}", 'error', 'startup')
        finally:
            self._finish_scan()

    def _toggle_startup_monitor(self):
        if self.startup_monitor_running:
            self.startup_monitor.stop()
            self.startup_monitor_running = False
            self.startup_monitor_btn.configure(text="Start Hourly Monitor")
            self._log("Startup monitor stopped.", 'info', 'startup')
            self._update_status("Monitor stopped")
        else:
            if not self.startup_monitor.get_known_programs():
                messagebox.showinfo("No Baseline", "Please initialize baseline first.")
                return
            self.startup_monitor.start()
            self.startup_monitor_running = True
            self.startup_monitor_btn.configure(text="Stop Hourly Monitor")
            self._log("Startup monitor started (checking every hour).", 'success', 'startup')
            self._update_status("Monitoring")

    def _on_startup_notification(self, message: str, program: dict):
        name = program.get('name', 'Unknown')
        self._log("", target='startup')
        self._log("=" * 60, 'warning', 'startup')
        self._log("NEW STARTUP PROGRAM DETECTED", 'warning', 'startup')
        self._log("=" * 60, 'warning', 'startup')
        self._log(f"\nProgram: {name}", 'warning', 'startup')
        self._log(f"Type: {program.get('type', 'unknown')}", target='startup')
        self._log(f"Location: {program.get('path', 'unknown')}", target='startup')
        if program.get('exec'):
            self._log(f"Command: {program['exec'][:80]}", target='startup')
        self._log("", target='startup')
        self._log("If you installed this recently, no action needed.", 'info', 'startup')
        self._log("=" * 60, 'warning', 'startup')
        self.msg_queue.put(('update_known_count', None, None, None))

    # ==================== Network Tab Methods ====================

    def _run_network_scan(self):
        if not self._run_in_thread(self._do_network_scan):
            return

    def _do_network_scan(self):
        try:
            self._log("=" * 60, 'header', 'network')
            self._log("NETWORK CONNECTION SCAN", 'header', 'network')
            self._log("=" * 60, 'header', 'network')
            self._log("", target='network')

            self._update_status("Scanning network...")
            self._update_detail("Checking for suspicious connections...")

            result = self.scanner.scan_network_connections()

            self._log(f"Check types: {result.items_scanned}", 'info', 'network')
            self._log(f"Issues found: {result.threat_count}",
                     'error' if result.threat_count > 0 else 'success', 'network')
            self._log("", target='network')

            if result.threats_found:
                self._display_threats(result.threats_found, 'network')
            else:
                self._log("No suspicious network activity detected.", 'success', 'network')

            self._update_status("Ready")

        except Exception as e:
            self._log(f"\nError: {str(e)}", 'error', 'network')
        finally:
            self._finish_scan()

    def _show_ssh_sessions(self):
        if not self._run_in_thread(self._do_show_ssh):
            return

    def _do_show_ssh(self):
        try:
            self._log("=" * 60, 'header', 'network')
            self._log("SSH SESSIONS", 'header', 'network')
            self._log("=" * 60, 'header', 'network')
            self._log("", target='network')

            self._update_status("Getting SSH sessions...")

            sessions = self.scanner.get_ssh_sessions()

            if sessions:
                for s in sessions:
                    if s.get('type') == 'incoming':
                        self._log(f"\n[INCOMING] User: {s.get('user')}", 'info', 'network')
                        self._log(f"  Terminal: {s.get('terminal')}", target='network')
                        self._log(f"  Time: {s.get('time')}", target='network')
                        self._log(f"  From: {s.get('from')}", target='network')
                    else:
                        self._log(f"\n[OUTGOING] PID: {s.get('pid')}", 'info', 'network')
                        self._log(f"  Command: {s.get('command')}", target='network')
            else:
                self._log("No active SSH sessions.", 'success', 'network')

            self._update_status("Ready")

        except Exception as e:
            self._log(f"\nError: {str(e)}", 'error', 'network')
        finally:
            self._finish_scan()

    def _show_ftp_connections(self):
        if not self._run_in_thread(self._do_show_ftp):
            return

    def _do_show_ftp(self):
        try:
            self._log("=" * 60, 'header', 'network')
            self._log("FTP CONNECTIONS", 'header', 'network')
            self._log("=" * 60, 'header', 'network')
            self._log("", target='network')

            self._update_status("Getting FTP connections...")

            connections = self.scanner.get_ftp_connections()

            if connections:
                for c in connections:
                    if c.get('type') == 'client':
                        self._log(f"\n[CLIENT] {c.get('process')} (PID: {c.get('pid')})", 'info', 'network')
                        self._log(f"  Command: {c.get('command')}", target='network')
                    else:
                        self._log(f"\n[CONNECTION] {c.get('local')} -> {c.get('remote')}", 'info', 'network')
                        self._log(f"  State: {c.get('state')}", target='network')
            else:
                self._log("No active FTP connections.", 'success', 'network')

            self._update_status("Ready")

        except Exception as e:
            self._log(f"\nError: {str(e)}", 'error', 'network')
        finally:
            self._finish_scan()

    def _show_all_connections(self):
        if not self._run_in_thread(self._do_show_connections):
            return

    def _do_show_connections(self):
        try:
            self._log("=" * 60, 'header', 'network')
            self._log("ALL ACTIVE CONNECTIONS", 'header', 'network')
            self._log("=" * 60, 'header', 'network')
            self._log("", target='network')

            self._update_status("Getting connections...")

            connections = self.scanner.get_active_connections()

            for category, conns in connections.items():
                if conns:
                    self._log(f"\n[{category.upper()}] ({len(conns)} connections)", 'header', 'network')
                    for c in conns[:10]:
                        local = c.get('local', 'N/A')
                        remote = c.get('remote', 'N/A')
                        state = c.get('state', 'N/A')
                        self._log(f"  {local} -> {remote} [{state}]", 'info', 'network')
                    if len(conns) > 10:
                        self._log(f"  ... and {len(conns) - 10} more", target='network')

            self._update_status("Ready")

        except Exception as e:
            self._log(f"\nError: {str(e)}", 'error', 'network')
        finally:
            self._finish_scan()

    # ==================== Screen Tab Methods ====================

    def _run_screen_scan(self):
        if not self._run_in_thread(self._do_screen_scan):
            return

    def _do_screen_scan(self):
        try:
            self._log("=" * 60, 'header', 'screen')
            self._log("SCREEN SHARING SCAN", 'header', 'screen')
            self._log("=" * 60, 'header', 'screen')
            self._log("", target='screen')

            self._update_status("Scanning for screen sharing...")
            self._update_detail("Checking VNC, RDP, TeamViewer, X11, D-Bus...")

            result = self.scanner.scan_screen_sharing()

            self._log(f"Check types: {result.items_scanned}", 'info', 'screen')
            self._log(f"Indicators found: {result.threat_count}",
                     'warning' if result.threat_count > 0 else 'success', 'screen')
            self._log("", target='screen')

            if result.threats_found:
                self._log("SCREEN SHARING DETECTED:", 'warning', 'screen')
                self._log("", target='screen')
                for threat in result.threats_found:
                    level = threat.level.value.upper()
                    self._log(f"[{level}] {threat.name}", 'warning', 'screen')
                    self._log(f"  {threat.description}", target='screen')
                    self._log(f"  Location: {threat.location}", target='screen')
                    if threat.evidence:
                        self._log(f"  Evidence: {threat.evidence[:80]}", target='screen')
                    self._log("", target='screen')
            else:
                self._log("No screen sharing detected.", 'success', 'screen')

            self._update_status("Ready")
            self._update_detail("")

        except Exception as e:
            self._log(f"\nError: {str(e)}", 'error', 'screen')
        finally:
            self._finish_scan()

    def _run_screen_quick_check(self):
        if not self._run_in_thread(self._do_screen_quick):
            return

    def _do_screen_quick(self):
        try:
            self._log("=" * 60, 'header', 'screen')
            self._log("QUICK SCREEN CHECK", 'header', 'screen')
            self._log("=" * 60, 'header', 'screen')
            self._log("", target='screen')

            self._update_status("Checking...")

            is_shared, details = self.scanner.is_screen_being_shared()

            if is_shared:
                self._log("SCREEN IS BEING SHARED!", 'warning', 'screen')
                self._log("", target='screen')
                for d in details:
                    self._log(f"  - {d.get('name', 'Unknown')}", 'warning', 'screen')
                    self._log(f"    {d.get('description', '')}", target='screen')
            else:
                self._log("Screen is NOT being shared.", 'success', 'screen')

            self._update_status("Ready")

        except Exception as e:
            self._log(f"\nError: {str(e)}", 'error', 'screen')
        finally:
            self._finish_scan()

    # ==================== Monitor Tab Methods ====================

    def _toggle_realtime_monitor(self):
        if self.realtime_monitor_running:
            self.realtime_monitor.stop()
            self.realtime_monitor_running = False
            self.realtime_btn.configure(text="Start Real-Time Monitor")
            self.realtime_status.configure(text="Status: Stopped")
            self._log("Real-time monitor stopped.", 'info', 'monitor')
        else:
            self.realtime_monitor.start()
            self.realtime_monitor_running = True
            self.realtime_btn.configure(text="Stop Real-Time Monitor")
            self.realtime_status.configure(text="Status: Running")
            self._log("Real-time monitor started.", 'success', 'monitor')
            self._log("Watching for new suspicious processes...", 'info', 'monitor')

    def _on_realtime_threat(self, threats):
        """Handle threat detected by real-time monitor."""
        for threat in threats:
            self._log("", target='monitor')
            self._log("=" * 50, 'error', 'monitor')
            self._log("THREAT DETECTED!", 'critical', 'monitor')
            self._log("=" * 50, 'error', 'monitor')
            self._log(f"Name: {threat.name}", 'error', 'monitor')
            self._log(f"Category: {threat.category.value}", target='monitor')
            self._log(f"Level: {threat.level.value.upper()}", target='monitor')
            self._log(f"Location: {threat.location}", target='monitor')
            self._log(f"Description: {threat.description}", target='monitor')
            if threat.remediation:
                self._log(f"Remediation: {threat.remediation}", 'info', 'monitor')

    def _update_scanner_status(self):
        """Update scanner status display."""
        status = self.scanner.get_status()

        self.scanner_status_labels['signatures'].configure(text=str(status.get('signatures_loaded', 0)))
        self.scanner_status_labels['patterns'].configure(text=str(status.get('file_patterns', 0)))
        self.scanner_status_labels['directories'].configure(text=str(status.get('monitored_dirs', 0)))
        self.scanner_status_labels['screen_sigs'].configure(text=str(status.get('screen_sharing_sigs', 0)))
        self.scanner_status_labels['network_ports'].configure(text=str(status.get('network_ports_monitored', 0)))
        self.scanner_status_labels['network_procs'].configure(text=str(status.get('network_process_sigs', 0)))

    def on_closing(self):
        """Handle window close."""
        if self.startup_monitor_running:
            self.startup_monitor.stop()
        if self.realtime_monitor_running:
            self.realtime_monitor.stop()
        self.root.destroy()


def main():
    """Main entry point."""
    root = tk.Tk()
    app = AntivirusGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == '__main__':
    main()
