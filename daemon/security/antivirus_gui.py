#!/usr/bin/env python3
"""
Antivirus Scanner GUI

A simple graphical interface for the antivirus scanner and startup monitor.
Uses tkinter for cross-platform compatibility.

Usage:
    python -m daemon.security.antivirus_gui
    # or
    ./daemon/security/antivirus_gui.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
from datetime import datetime

# Import scanner components
from .antivirus import AntivirusScanner, StartupMonitor, ThreatLevel


class AntivirusGUI:
    """Main GUI application for the antivirus scanner."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Boundary Daemon - Security Scanner")
        self.root.geometry("800x600")
        self.root.minsize(600, 400)

        # Initialize scanner components
        self.scanner = AntivirusScanner()
        self.startup_monitor = StartupMonitor(
            notification_callback=self._on_startup_notification
        )

        # Message queue for thread-safe GUI updates
        self.msg_queue = queue.Queue()

        # Track running operations
        self.scan_running = False
        self.monitor_running = False

        # Build the GUI
        self._create_widgets()
        self._setup_styles()

        # Start queue processor
        self._process_queue()

    def _setup_styles(self):
        """Configure ttk styles."""
        style = ttk.Style()
        style.configure('Title.TLabel', font=('Helvetica', 14, 'bold'))
        style.configure('Status.TLabel', font=('Helvetica', 10))
        style.configure('Scan.TButton', padding=10)

    def _create_widgets(self):
        """Create all GUI widgets."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)

        # === Header Section ===
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        ttk.Label(
            header_frame,
            text="Security Scanner",
            style='Title.TLabel'
        ).pack(side="left")

        self.status_label = ttk.Label(
            header_frame,
            text="Ready",
            style='Status.TLabel'
        )
        self.status_label.pack(side="right")

        # === Button Section ===
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        # Startup Scan Button (prominent)
        self.startup_scan_btn = ttk.Button(
            button_frame,
            text="Initialize Startup Scan",
            command=self._run_startup_init,
            style='Scan.TButton'
        )
        self.startup_scan_btn.pack(side="left", padx=(0, 5))

        # Check for New Programs Button
        self.check_startup_btn = ttk.Button(
            button_frame,
            text="Check for New Programs",
            command=self._run_startup_check,
            style='Scan.TButton'
        )
        self.check_startup_btn.pack(side="left", padx=5)

        # Quick Scan Button
        self.quick_scan_btn = ttk.Button(
            button_frame,
            text="Quick Scan",
            command=self._run_quick_scan,
            style='Scan.TButton'
        )
        self.quick_scan_btn.pack(side="left", padx=5)

        # Full Scan Button
        self.full_scan_btn = ttk.Button(
            button_frame,
            text="Full Scan",
            command=self._run_full_scan,
            style='Scan.TButton'
        )
        self.full_scan_btn.pack(side="left", padx=5)

        # Monitor Toggle Button
        self.monitor_btn = ttk.Button(
            button_frame,
            text="Start Monitor",
            command=self._toggle_monitor
        )
        self.monitor_btn.pack(side="right", padx=5)

        # === Results Section ===
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="5")
        results_frame.grid(row=2, column=0, sticky="nsew", pady=(0, 10))
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
        self.results_text.tag_configure('info', foreground='#2196F3')
        self.results_text.tag_configure('success', foreground='#4CAF50')
        self.results_text.tag_configure('warning', foreground='#FF9800')
        self.results_text.tag_configure('error', foreground='#F44336')
        self.results_text.tag_configure('critical', foreground='#D32F2F', font=('Courier', 10, 'bold'))
        self.results_text.tag_configure('header', font=('Courier', 11, 'bold'))

        # === Status Bar ===
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=3, column=0, sticky="ew")

        self.progress = ttk.Progressbar(
            status_frame,
            mode='indeterminate',
            length=200
        )
        self.progress.pack(side="left", padx=(0, 10))

        self.detail_label = ttk.Label(status_frame, text="")
        self.detail_label.pack(side="left", fill="x", expand=True)

        # Known programs count
        self.known_count_label = ttk.Label(
            status_frame,
            text=f"Known programs: {len(self.startup_monitor.get_known_programs())}"
        )
        self.known_count_label.pack(side="right")

    def _log(self, message: str, tag: str = None):
        """Add message to the results text area."""
        self.msg_queue.put(('log', message, tag))

    def _update_status(self, status: str):
        """Update status label."""
        self.msg_queue.put(('status', status, None))

    def _update_detail(self, detail: str):
        """Update detail label."""
        self.msg_queue.put(('detail', detail, None))

    def _process_queue(self):
        """Process messages from the queue (thread-safe GUI updates)."""
        try:
            while True:
                msg_type, content, tag = self.msg_queue.get_nowait()

                if msg_type == 'log':
                    self.results_text.configure(state='normal')
                    if tag:
                        self.results_text.insert(tk.END, content + '\n', tag)
                    else:
                        self.results_text.insert(tk.END, content + '\n')
                    self.results_text.see(tk.END)
                    self.results_text.configure(state='disabled')

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
                    self.known_count_label.configure(text=f"Known programs: {count}")

                elif msg_type == 'enable_buttons':
                    self._set_buttons_state('normal')

        except queue.Empty:
            pass

        # Schedule next check
        self.root.after(100, self._process_queue)

    def _set_buttons_state(self, state: str):
        """Enable or disable scan buttons."""
        self.startup_scan_btn.configure(state=state)
        self.check_startup_btn.configure(state=state)
        self.quick_scan_btn.configure(state=state)
        self.full_scan_btn.configure(state=state)

    def _run_startup_init(self):
        """Run initial startup program scan in background thread."""
        if self.scan_running:
            return

        self.scan_running = True
        self._set_buttons_state('disabled')
        self.msg_queue.put(('progress_start', None, None))
        self._update_status("Scanning...")

        def do_scan():
            try:
                self._log("=" * 60, 'header')
                self._log("INITIALIZING STARTUP PROGRAM BASELINE", 'header')
                self._log("=" * 60, 'header')
                self._log("")

                self._update_detail("Scanning startup locations...")

                # Scan all startup programs
                programs = self.startup_monitor.scan_startup_programs()

                self._log(f"Found {len(programs)} startup programs:\n", 'info')

                # Group by location
                by_location = {}
                for prog_id, prog in programs.items():
                    loc = prog.get('location', 'unknown')
                    if loc not in by_location:
                        by_location[loc] = []
                    by_location[loc].append(prog)

                for location, progs in sorted(by_location.items()):
                    self._log(f"\n[{location.upper()}] ({len(progs)} programs)", 'header')
                    for p in progs:
                        name = p.get('name', 'unknown')
                        self._log(f"  - {name}", 'info')
                        if p.get('exec'):
                            cmd = p['exec'][:60]
                            self._log(f"    Command: {cmd}...", None)

                # Initialize baseline
                self._update_detail("Saving baseline...")
                count = self.startup_monitor.initialize_baseline()

                self._log("")
                self._log("=" * 60, 'success')
                self._log(f"Baseline initialized with {count} programs", 'success')
                self._log("Future checks will alert you to new additions", 'success')
                self._log("=" * 60, 'success')

                self._update_status("Ready")
                self._update_detail(f"Baseline saved: {count} programs")
                self.msg_queue.put(('update_known_count', None, None))

            except Exception as e:
                self._log(f"\nError: {str(e)}", 'error')
                self._update_status("Error")

            finally:
                self.scan_running = False
                self.msg_queue.put(('progress_stop', None, None))
                self.msg_queue.put(('enable_buttons', None, None))

        threading.Thread(target=do_scan, daemon=True).start()

    def _run_startup_check(self):
        """Check for new startup programs."""
        if self.scan_running:
            return

        # Check if baseline exists
        if not self.startup_monitor.get_known_programs():
            messagebox.showinfo(
                "No Baseline",
                "No baseline found. Please run 'Initialize Startup Scan' first."
            )
            return

        self.scan_running = True
        self._set_buttons_state('disabled')
        self.msg_queue.put(('progress_start', None, None))
        self._update_status("Checking...")

        def do_check():
            try:
                self._log("=" * 60, 'header')
                self._log("CHECKING FOR NEW STARTUP PROGRAMS", 'header')
                self._log("=" * 60, 'header')
                self._log("")

                self._update_detail("Comparing to baseline...")

                new_programs = self.startup_monitor.check_for_new_programs()

                if new_programs:
                    self._log(f"Found {len(new_programs)} NEW startup programs:\n", 'warning')

                    for prog in new_programs:
                        name = prog.get('name', 'unknown')
                        self._log(f"\n  NEW: {name}", 'warning')
                        self._log(f"  Type: {prog.get('type', 'unknown')}")
                        self._log(f"  Location: {prog.get('path', 'unknown')}")
                        if prog.get('exec'):
                            self._log(f"  Command: {prog['exec'][:80]}")
                        self._log("")
                        self._log("  If you recently installed this, no action needed.", 'info')
                        self._log("  Otherwise, you may want to investigate.", 'info')

                    self._update_status(f"{len(new_programs)} new programs found")
                else:
                    self._log("No new startup programs detected.", 'success')
                    self._log("All programs match the known baseline.", 'success')
                    self._update_status("No changes")

                self._log("")
                count = len(self.startup_monitor.get_known_programs())
                self._log(f"Known programs: {count}", 'info')
                self.msg_queue.put(('update_known_count', None, None))
                self._update_detail("")

            except Exception as e:
                self._log(f"\nError: {str(e)}", 'error')
                self._update_status("Error")

            finally:
                self.scan_running = False
                self.msg_queue.put(('progress_stop', None, None))
                self.msg_queue.put(('enable_buttons', None, None))

        threading.Thread(target=do_check, daemon=True).start()

    def _run_quick_scan(self):
        """Run quick antivirus scan."""
        if self.scan_running:
            return

        self.scan_running = True
        self._set_buttons_state('disabled')
        self.msg_queue.put(('progress_start', None, None))
        self._update_status("Quick scanning...")

        def do_scan():
            try:
                self._log("=" * 60, 'header')
                self._log("QUICK SCAN", 'header')
                self._log("=" * 60, 'header')
                self._log("")

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
                self._update_status("Error")

            finally:
                self.scan_running = False
                self.msg_queue.put(('progress_stop', None, None))
                self.msg_queue.put(('enable_buttons', None, None))

        threading.Thread(target=do_scan, daemon=True).start()

    def _run_full_scan(self):
        """Run full antivirus scan."""
        if self.scan_running:
            return

        self.scan_running = True
        self._set_buttons_state('disabled')
        self.msg_queue.put(('progress_start', None, None))
        self._update_status("Full scanning...")

        def do_scan():
            try:
                self._log("=" * 60, 'header')
                self._log("FULL SCAN", 'header')
                self._log("=" * 60, 'header')
                self._log("")
                self._log("This may take a few minutes...", 'info')
                self._log("")

                self._update_detail("Scanning all areas...")

                result = self.scanner.full_scan()

                self._log(f"Items scanned: {result.items_scanned}", 'info')
                self._log(f"Threats found: {result.threat_count}",
                         'error' if result.threat_count > 0 else 'success')
                self._log(f"Duration: {result.start_time} - {result.end_time}", 'info')
                self._log("")

                if result.threats_found:
                    self._display_threats(result.threats_found)
                else:
                    self._log("No threats detected.", 'success')

                if result.errors:
                    self._log("\nErrors during scan:", 'warning')
                    for err in result.errors[:5]:
                        self._log(f"  - {err}", 'warning')
                    if len(result.errors) > 5:
                        self._log(f"  ... and {len(result.errors) - 5} more", 'warning')

                self._update_status("Ready")
                self._update_detail(f"Scanned {result.items_scanned} items")

            except Exception as e:
                self._log(f"\nError: {str(e)}", 'error')
                self._update_status("Error")

            finally:
                self.scan_running = False
                self.msg_queue.put(('progress_stop', None, None))
                self.msg_queue.put(('enable_buttons', None, None))

        threading.Thread(target=do_scan, daemon=True).start()

    def _display_threats(self, threats):
        """Display detected threats."""
        self._log("THREATS DETECTED:", 'error')
        self._log("")

        for threat in threats:
            level = threat.level.value.upper()
            tag = 'critical' if threat.level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH] else 'warning'

            self._log(f"[{level}] {threat.name}", tag)
            self._log(f"  Category: {threat.category.value}")
            self._log(f"  Location: {threat.location}")
            self._log(f"  Description: {threat.description}")
            if threat.evidence:
                self._log(f"  Evidence: {threat.evidence[:100]}")
            if threat.remediation:
                self._log(f"  Remediation: {threat.remediation}", 'info')
            self._log("")

    def _toggle_monitor(self):
        """Toggle the background startup monitor."""
        if self.monitor_running:
            self.startup_monitor.stop()
            self.monitor_running = False
            self.monitor_btn.configure(text="Start Monitor")
            self._log("Startup monitor stopped.", 'info')
            self._update_status("Monitor stopped")
        else:
            # Check if baseline exists
            if not self.startup_monitor.get_known_programs():
                messagebox.showinfo(
                    "No Baseline",
                    "Please run 'Initialize Startup Scan' first to create a baseline."
                )
                return

            self.startup_monitor.start()
            self.monitor_running = True
            self.monitor_btn.configure(text="Stop Monitor")
            self._log("Startup monitor started (checking every hour).", 'success')
            self._update_status("Monitoring")

    def _on_startup_notification(self, message: str, program: dict):
        """Handle notification from startup monitor."""
        name = program.get('name', 'Unknown')
        self._log("")
        self._log("=" * 60, 'warning')
        self._log("NEW STARTUP PROGRAM DETECTED", 'warning')
        self._log("=" * 60, 'warning')
        self._log(f"\nProgram: {name}", 'warning')
        self._log(f"Type: {program.get('type', 'unknown')}")
        self._log(f"Location: {program.get('path', 'unknown')}")
        if program.get('exec'):
            self._log(f"Command: {program['exec'][:80]}")
        self._log("")
        self._log("If you recently installed this, no action needed.", 'info')
        self._log("Otherwise, you may want to investigate.", 'info')
        self._log("=" * 60, 'warning')

        self.msg_queue.put(('update_known_count', None, None))

    def on_closing(self):
        """Handle window close."""
        if self.monitor_running:
            self.startup_monitor.stop()
        self.root.destroy()


def main():
    """Main entry point."""
    root = tk.Tk()
    app = AntivirusGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == '__main__':
    main()
