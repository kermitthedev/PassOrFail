#!/usr/bin/env python3
"""
PassOrFail v3.0 - Advanced Password Security Checker
Enhanced with animations, password generator, tooltips, and export features
"""

import tkinter as tk
from tkinter import ttk
import re
import math
import hashlib
import requests
from typing import Dict, List, Tuple
import threading
import random
import string
import secrets

class ToolTip:
    """Tooltip widget for hover information"""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)
    
    def show_tooltip(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        
        label = tk.Label(
            self.tooltip,
            text=self.text,
            background="#1a2347",
            foreground="#e0e6ff",
            relief=tk.SOLID,
            borderwidth=1,
            font=("Courier New", 9),
            padx=10,
            pady=5,
            wraplength=300
        )
        label.pack()
    
    def hide_tooltip(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None


class PassOrFail:
    def __init__(self, root):
        self.root = root
        self.root.title("PassOrFail v3.0 - Password Security Checker")
        self.root.geometry("700x750")
        self.root.minsize(600, 600)
        self.root.maxsize(900, 1000)
        self.root.resizable(True, True)
        self.root.configure(bg="#0a0e27")
        
        # Color scheme
        self.colors = {
            'bg_primary': '#0a0e27',
            'bg_secondary': '#131a3a',
            'bg_input': '#1a2347',
            'text_primary': '#e0e6ff',
            'text_secondary': '#8892b0',
            'accent_green': '#00ff88',
            'accent_red': '#ff0055',
            'accent_yellow': '#ffd500',
            'accent_blue': '#00d4ff',
            'accent_cyan': '#00ffff',
            'border': '#2a3f5f',
            'glow': '#00ff88'
        }
        
        # Common weak passwords
        self.common_passwords = {
            'password', '123456', '12345678', 'qwerty', 'abc123', 
            'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
            'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
            'bailey', 'passw0rd', 'shadow', '123123', '654321',
            'superman', 'qazwsx', 'michael', 'football', 'password1'
        }
        
        # Animation variables
        self.glow_intensity = 0
        self.glow_direction = 1
        self.strength_bar_width = 0
        self.target_bar_width = 0
        
        # State variables
        self.hibp_status = None
        self.checking_hibp = False
        self.passphrase_mode = tk.BooleanVar(value=False)
        self.current_score = 0
        self.current_entropy = 0.0
        
        self.setup_ui()
        self.animate_glow()
        
    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.root, bg=self.colors['bg_primary'], height=120)
        header_frame.pack(fill=tk.X, pady=(15, 10))
        
        logo_title_frame = tk.Frame(header_frame, bg=self.colors['bg_primary'])
        logo_title_frame.pack()
        
        self.logo_canvas = tk.Canvas(
            logo_title_frame,
            width=45,
            height=45,
            bg=self.colors['bg_primary'],
            highlightthickness=0
        )
        self.logo_canvas.pack(side=tk.LEFT, padx=(0, 12))
        self.draw_shield_logo()
        
        title_frame = tk.Frame(logo_title_frame, bg=self.colors['bg_primary'])
        title_frame.pack(side=tk.LEFT)
        
        self.title_label = tk.Label(
            title_frame,
            text="PASS OR FAIL",
            font=("Courier New", 32, "bold"),
            bg=self.colors['bg_primary'],
            fg=self.colors['accent_green']
        )
        self.title_label.pack()
        
        subtitle_label = tk.Label(
            header_frame,
            text="[ PASSWORD SECURITY ANALYZER v3.0 ]",
            font=("Courier New", 10),
            bg=self.colors['bg_primary'],
            fg=self.colors['text_secondary']
        )
        subtitle_label.pack(pady=(3, 0))
        
        tagline_label = tk.Label(
            header_frame,
            text="Test your password strength in real-time. Stay secure.",
            font=("Courier New", 8, "italic"),
            bg=self.colors['bg_primary'],
            fg=self.colors['accent_cyan']
        )
        tagline_label.pack(pady=(3, 0))
        
        # Privacy notice
        privacy_label = tk.Label(
            header_frame,
            text="🔒 100% Private - No data stored or transmitted (optional HIBP check uses k-anonymity)",
            font=("Courier New", 7),
            bg=self.colors['bg_primary'],
            fg=self.colors['accent_green']
        )
        privacy_label.pack(pady=(3, 0))
        
        # Create scrollable main container
        main_container = tk.Frame(self.root, bg=self.colors['bg_primary'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=25, pady=(10, 15))
        
        self.canvas = tk.Canvas(main_container, bg=self.colors['bg_primary'], highlightthickness=0)
        scrollbar = tk.Scrollbar(main_container, orient="vertical", command=self.canvas.yview)
        
        main_frame = tk.Frame(self.canvas, bg=self.colors['bg_primary'])
        
        main_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=main_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", self._on_mousewheel)
        self.canvas.bind_all("<Button-5>", self._on_mousewheel)
        
        # Password input section with glow
        input_container = tk.Frame(
            main_frame,
            bg=self.colors['bg_secondary'],
            highlightbackground=self.colors['accent_green'],
            highlightthickness=1
        )
        input_container.pack(fill=tk.X, pady=(0, 12))
        
        # Passphrase mode toggle
        mode_frame = tk.Frame(input_container, bg=self.colors['bg_secondary'])
        mode_frame.pack(fill=tk.X, padx=15, pady=(12, 5))
        
        mode_label = tk.Label(
            mode_frame,
            text="ENTER PASSWORD:",
            font=("Courier New", 10, "bold"),
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_secondary']
        )
        mode_label.pack(side=tk.LEFT)
        
        passphrase_check = tk.Checkbutton(
            mode_frame,
            text="Passphrase Mode",
            variable=self.passphrase_mode,
            command=self.check_password,
            font=("Courier New", 8),
            bg=self.colors['bg_secondary'],
            fg=self.colors['accent_cyan'],
            selectcolor=self.colors['bg_input'],
            activebackground=self.colors['bg_secondary'],
            activeforeground=self.colors['accent_green'],
            relief=tk.FLAT
        )
        passphrase_check.pack(side=tk.RIGHT)
        ToolTip(passphrase_check, "Enable to evaluate multi-word passphrases\n(e.g., 'correct horse battery staple')")
        
        # Password entry
        entry_frame = tk.Frame(input_container, bg=self.colors['bg_secondary'])
        entry_frame.pack(fill=tk.X, padx=15, pady=(0, 12))
        
        self.password_var = tk.StringVar()
        self.password_var.trace('w', self.check_password)
        
        self.password_entry = tk.Entry(
            entry_frame,
            textvariable=self.password_var,
            font=("Courier New", 13),
            bg=self.colors['bg_input'],
            fg=self.colors['text_primary'],
            insertbackground=self.colors['accent_green'],
            relief=tk.FLAT,
            show="●"
        )
        self.password_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, ipady=8)
        self.password_entry.focus()
        
        self.show_var = tk.BooleanVar()
        show_btn = tk.Checkbutton(
            entry_frame,
            text="👁",
            variable=self.show_var,
            command=self.toggle_password,
            font=("Arial", 11),
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_primary'],
            selectcolor=self.colors['bg_input'],
            activebackground=self.colors['bg_secondary'],
            activeforeground=self.colors['accent_green'],
            relief=tk.FLAT
        )
        show_btn.pack(side=tk.LEFT, padx=(8, 0))
        
        # Password Generator Button
        gen_btn = tk.Button(
            input_container,
            text="🎲 Generate Strong Password",
            command=self.generate_password,
            font=("Courier New", 9, "bold"),
            bg=self.colors['bg_input'],
            fg=self.colors['accent_cyan'],
            activebackground=self.colors['accent_green'],
            activeforeground=self.colors['bg_primary'],
            relief=tk.FLAT,
            padx=15,
            pady=6,
            cursor="hand2"
        )
        gen_btn.pack(padx=15, pady=(0, 12))
        ToolTip(gen_btn, "Generate a cryptographically secure random password")
        
        # Metrics section
        metrics_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        metrics_frame.pack(fill=tk.X, pady=(0, 12))
        
        # Strength meter
        strength_frame = tk.Frame(metrics_frame, bg=self.colors['bg_primary'])
        strength_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        
        strength_label = tk.Label(
            strength_frame,
            text="STRENGTH:",
            font=("Courier New", 8, "bold"),
            bg=self.colors['bg_primary'],
            fg=self.colors['text_secondary']
        )
        strength_label.pack(anchor=tk.W)
        
        self.strength_canvas = tk.Canvas(
            strength_frame,
            height=22,
            bg=self.colors['bg_secondary'],
            highlightthickness=0
        )
        self.strength_canvas.pack(fill=tk.X, pady=(4, 0))
        
        self.strength_label = tk.Label(
            strength_frame,
            text="",
            font=("Courier New", 8, "bold"),
            bg=self.colors['bg_primary'],
            fg=self.colors['text_secondary']
        )
        self.strength_label.pack(anchor=tk.W, pady=(4, 0))
        
        # Entropy display with tooltip
        entropy_frame = tk.Frame(metrics_frame, bg=self.colors['bg_primary'])
        entropy_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        entropy_header_frame = tk.Frame(entropy_frame, bg=self.colors['bg_primary'])
        entropy_header_frame.pack(anchor=tk.W)
        
        entropy_header = tk.Label(
            entropy_header_frame,
            text="ENTROPY: ℹ️",
            font=("Courier New", 8, "bold"),
            bg=self.colors['bg_primary'],
            fg=self.colors['text_secondary']
        )
        entropy_header.pack(side=tk.LEFT)
        ToolTip(entropy_header, 
                "Entropy measures password unpredictability.\n\n"
                "< 28 bits = Very Weak\n"
                "28-36 bits = Weak\n"
                "36-60 bits = Reasonable\n"
                "60+ bits = Strong\n\n"
                "Aim for 60+ bits for strong security!")
        
        self.entropy_label = tk.Label(
            entropy_frame,
            text="0.0 bits",
            font=("Courier New", 15, "bold"),
            bg=self.colors['bg_primary'],
            fg=self.colors['accent_blue']
        )
        self.entropy_label.pack(anchor=tk.W, pady=(4, 0))
        
        self.entropy_desc = tk.Label(
            entropy_frame,
            text="",
            font=("Courier New", 7),
            bg=self.colors['bg_primary'],
            fg=self.colors['text_secondary']
        )
        self.entropy_desc.pack(anchor=tk.W)
        
        # HIBP Status with glow
        hibp_frame = tk.Frame(
            main_frame,
            bg=self.colors['bg_secondary'],
            highlightbackground=self.colors['accent_blue'],
            highlightthickness=1
        )
        hibp_frame.pack(fill=tk.X, pady=(0, 12))
        
        hibp_header = tk.Label(
            hibp_frame,
            text="🌐 BREACH CHECK (Have I Been Pwned)",
            font=("Courier New", 8, "bold"),
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_secondary']
        )
        hibp_header.pack(anchor=tk.W, padx=15, pady=(8, 4))
        
        self.hibp_status_label = tk.Label(
            hibp_frame,
            text="Enter a password to check...",
            font=("Courier New", 8),
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_secondary'],
            wraplength=600,
            justify=tk.LEFT
        )
        self.hibp_status_label.pack(anchor=tk.W, padx=15, pady=(0, 8))
        
        # Compact security checks
        checks_container = tk.Frame(
            main_frame,
            bg=self.colors['bg_secondary'],
            highlightbackground=self.colors['accent_yellow'],
            highlightthickness=1
        )
        checks_container.pack(fill=tk.BOTH, expand=True, pady=(0, 12))
        
        checks_header = tk.Label(
            checks_container,
            text="SECURITY REQUIREMENTS",
            font=("Courier New", 9, "bold"),
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_secondary']
        )
        checks_header.pack(anchor=tk.W, padx=15, pady=(12, 8))
        
        # Create compact check items
        self.check_labels = {}
        checks = [
            ('length', 'Min 8 chars', 'At least 8 characters long'),
            ('uppercase', 'Uppercase', 'Contains uppercase letter (A-Z)'),
            ('lowercase', 'Lowercase', 'Contains lowercase letter (a-z)'),
            ('digit', 'Number', 'Contains number (0-9)'),
            ('special', 'Special char', 'Contains special character (!@#$%^&*)'),
            ('common', 'Not common', 'Not in common password list'),
            ('passphrase', 'Passphrase', '4+ meaningful words (bonus)')
        ]
        
        for key, short_text, full_text in checks:
            check_frame = tk.Frame(checks_container, bg=self.colors['bg_secondary'])
            check_frame.pack(fill=tk.X, padx=15, pady=2)
            
            icon_label = tk.Label(
                check_frame,
                text="○",
                font=("Arial", 12),
                bg=self.colors['bg_secondary'],
                fg=self.colors['text_secondary'],
                width=2
            )
            icon_label.pack(side=tk.LEFT)
            
            text_label = tk.Label(
                check_frame,
                text=short_text,
                font=("Courier New", 8),
                bg=self.colors['bg_secondary'],
                fg=self.colors['text_secondary'],
                anchor=tk.W
            )
            text_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
            
            self.check_labels[key] = (icon_label, text_label)
            ToolTip(text_label, full_text)
        
        # Passphrase tip
        tip_label = tk.Label(
            checks_container,
            text='💡 "correct horse battery staple" > "P@ssw0rd!"',
            font=("Courier New", 7, "italic"),
            bg=self.colors['bg_secondary'],
            fg=self.colors['accent_cyan'],
            wraplength=600,
            justify=tk.LEFT
        )
        tip_label.pack(anchor=tk.W, padx=15, pady=(8, 12))
        
        # Export/Copy button
        export_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        export_frame.pack(fill=tk.X, pady=(0, 12))
        
        self.export_btn = tk.Button(
            export_frame,
            text="📋 Copy Security Report",
            command=self.export_report,
            font=("Courier New", 9, "bold"),
            bg=self.colors['bg_input'],
            fg=self.colors['accent_green'],
            activebackground=self.colors['accent_green'],
            activeforeground=self.colors['bg_primary'],
            relief=tk.FLAT,
            padx=20,
            pady=8,
            cursor="hand2",
            state=tk.DISABLED
        )
        self.export_btn.pack()
        
        self.export_status = tk.Label(
            export_frame,
            text="",
            font=("Courier New", 7),
            bg=self.colors['bg_primary'],
            fg=self.colors['accent_green']
        )
        self.export_status.pack(pady=(4, 0))
        
        # Footer
        footer_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        footer_frame.pack(side=tk.BOTTOM, pady=(12, 0))
        
        footer = tk.Label(
            footer_frame,
            text="© 2025 PassOrFail v3.0",
            font=("Courier New", 8, "bold"),
            bg=self.colors['bg_primary'],
            fg=self.colors['accent_green']
        )
        footer.pack()
        
        footer_sub = tk.Label(
            footer_frame,
            text="Secure Your Digital Life | Open Source Security Tool",
            font=("Courier New", 6),
            bg=self.colors['bg_primary'],
            fg=self.colors['text_secondary']
        )
        footer_sub.pack()
    
    def draw_shield_logo(self):
        """Draw shield/lock logo"""
        points = [22, 4, 40, 12, 40, 32, 22, 42, 4, 32, 4, 12]
        self.logo_canvas.create_polygon(
            points,
            fill=self.colors['bg_secondary'],
            outline=self.colors['accent_green'],
            width=2
        )
        
        self.logo_canvas.create_rectangle(16, 22, 28, 34, fill=self.colors['accent_green'], outline="")
        self.logo_canvas.create_arc(18, 13, 26, 24, start=0, extent=180, style=tk.ARC,
                                    outline=self.colors['accent_green'], width=2)
        self.logo_canvas.create_oval(20, 25, 24, 29, fill=self.colors['bg_primary'], outline="")
    
    def animate_glow(self):
        """Animate title glow"""
        self.glow_intensity += self.glow_direction * 2
        
        if self.glow_intensity >= 100:
            self.glow_direction = -1
        elif self.glow_intensity <= 0:
            self.glow_direction = 1
        
        intensity = self.glow_intensity / 100
        g = int(255 * (0.7 + 0.3 * intensity))
        glow_color = f'#00{g:02x}88'
        self.title_label.config(fg=glow_color)
        
        self.root.after(30, self.animate_glow)
    
    def animate_strength_bar(self):
        """Smooth strength bar animation"""
        if abs(self.strength_bar_width - self.target_bar_width) > 1:
            diff = (self.target_bar_width - self.strength_bar_width) * 0.2
            self.strength_bar_width += diff
            self.draw_strength_bar()
            self.root.after(20, self.animate_strength_bar)
        else:
            self.strength_bar_width = self.target_bar_width
            self.draw_strength_bar()
    
    def draw_strength_bar(self):
        """Draw the strength bar"""
        self.strength_canvas.delete("all")
        
        width = self.strength_canvas.winfo_width()
        if width <= 1:
            width = 300
        
        height = 22
        
        percentage = (self.current_score / 7) * 100
        
        if percentage < 40:
            color = self.colors['accent_red']
        elif percentage < 70:
            color = self.colors['accent_yellow']
        else:
            color = self.colors['accent_green']
        
        self.strength_canvas.create_rectangle(0, 0, width, height, fill=self.colors['bg_input'], outline="")
        
        bar_width = self.strength_bar_width
        self.strength_canvas.create_rectangle(0, 0, bar_width, height, fill=color, outline="")
        
        self.strength_canvas.create_text(
            width / 2, height / 2,
            text=f"{int(percentage)}%",
            font=("Courier New", 10, "bold"),
            fill=self.colors['text_primary']
        )
    
    def toggle_password(self):
        self.password_entry.config(show="" if self.show_var.get() else "●")
    
    def generate_password(self):
        """Generate a strong random password"""
        length = 16
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(chars) for _ in range(length))
        
        self.password_var.set(password)
        self.password_entry.config(show="")
        self.show_var.set(True)
        
        # Copy to clipboard
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
    
    def check_password(self, *args):
        password = self.password_var.get()
        
        if not password:
            self.reset_checks()
            return
        
        checks = self.validate_password(password)
        score = sum(checks.values())
        
        entropy = self.calculate_entropy(password)
        
        if self.passphrase_mode.get():
            is_passphrase = self.is_passphrase(password)
            checks['passphrase'] = is_passphrase
            if is_passphrase:
                score += 1
        else:
            checks['passphrase'] = False
        
        self.current_score = score
        self.current_entropy = entropy
        
        # Animate check updates
        for key, (icon_label, text_label) in self.check_labels.items():
            if checks.get(key, False):
                self.root.after(50, lambda i=icon_label, t=text_label: self._update_check(i, t, True))
            else:
                self.root.after(50, lambda i=icon_label, t=text_label: self._update_check(i, t, False))
        
        self.update_strength_meter(score, 7)
        self.update_entropy_display(entropy)
        
        self.export_btn.config(state=tk.NORMAL)
        
        if len(password) >= 4:
            self.schedule_hibp_check(password)
    
    def _update_check(self, icon_label, text_label, passed):
        """Smooth check update with transition"""
        if passed:
            icon_label.config(text="✓", fg=self.colors['accent_green'])
            text_label.config(fg=self.colors['accent_green'])
        else:
            icon_label.config(text="✗", fg=self.colors['accent_red'])
            text_label.config(fg=self.colors['text_secondary'])
    
    def validate_password(self, password: str) -> Dict[str, bool]:
        checks = {
            'length': len(password) >= 8,
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'digit': bool(re.search(r'\d', password)),
            'special': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password)),
            'common': password.lower() not in self.common_passwords
        }
        return checks
    
    def is_passphrase(self, password: str) -> bool:
        words = re.split(r'[\s\-_]+', password)
        meaningful_words = [w for w in words if len(w) >= 3]
        return len(meaningful_words) >= 4
    
    def calculate_entropy(self, password: str) -> float:
        if not password:
            return 0.0
        
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~\s]', password):
            charset_size += 33
        
        if charset_size == 0:
            return 0.0
        
        entropy = len(password) * math.log2(charset_size)
        return entropy
    
    def update_entropy_display(self, entropy: float):
        self.entropy_label.config(text=f"{entropy:.1f} bits")
        
        if entropy < 28:
            self.entropy_label.config(fg=self.colors['accent_red'])
            self.entropy_desc.config(text="Very Weak", fg=self.colors['accent_red'])
        elif entropy < 36:
            self.entropy_label.config(fg=self.colors['accent_yellow'])
            self.entropy_desc.config(text="Weak", fg=self.colors['accent_yellow'])
        elif entropy < 60:
            self.entropy_label.config(fg=self.colors['accent_blue'])
            self.entropy_desc.config(text="Reasonable", fg=self.colors['accent_blue'])
        else:
            self.entropy_label.config(fg=self.colors['accent_green'])
            self.entropy_desc.config(text="Strong", fg=self.colors['accent_green'])
    
    def update_strength_meter(self, score: int, max_score: int):
        width = self.strength_canvas.winfo_width()
        if width <= 1:
            width = 300
        
        percentage = (score / max_score) * 100
        self.target_bar_width = (width * percentage) / 100
        
        if percentage < 40:
            level = "WEAK"
            color = self.colors['accent_red']
        elif percentage < 70:
            level = "MODERATE"
            color = self.colors['accent_yellow']
        else:
            level = "STRONG"
            color = self.colors['accent_green']
        
        self.animate_strength_bar()
        
        self.strength_label.config(
            text=f"[{level}] - {score}/{max_score} checks passed",
            fg=color
        )
    
    def schedule_hibp_check(self, password: str):
        if hasattr(self, '_hibp_after_id'):
            self.root.after_cancel(self._hibp_after_id)
        self._hibp_after_id = self.root.after(800, lambda: self.check_hibp(password))
    
    def check_hibp(self, password: str):
        if self.checking_hibp:
            return
        
        self.checking_hibp = True
        self.hibp_status_label.config(text="🔄 Checking breach database...", fg=self.colors['accent_blue'])
        
        thread = threading.Thread(target=self._hibp_check_thread, args=(password,))
        thread.daemon = True
        thread.start()
    
    def _hibp_check_thread(self, password: str):
        try:
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                hashes = response.text.split('\r\n')
                for hash_line in hashes:
                    hash_suffix, count = hash_line.split(':')
                    if hash_suffix == suffix:
                        count = int(count)
                        self.root.after(0, lambda: self._update_hibp_ui(
                            f"⚠️ WARNING: This password has been seen {count:,} times in data breaches!",
                            self.colors['accent_red']
                        ))
                        return
                
                self.root.after(0, lambda: self._update_hibp_ui(
                    "✓ Good news! This password has not been found in known breaches.",
                    self.colors['accent_green']
                ))
            else:
                self.root.after(0, lambda: self._update_hibp_ui(
                    "⚠️ Could not check breach database (service unavailable)",
                    self.colors['text_secondary']
                ))
        
        except Exception:
            self.root.after(0, lambda: self._update_hibp_ui(
                "⚠️ Could not connect to breach database (check internet connection)",
                self.colors['text_secondary']
            ))
        
        finally:
            self.checking_hibp = False
    
    def _update_hibp_ui(self, message: str, color: str):
        self.hibp_status_label.config(text=message, fg=color)
    
    def export_report(self):
        """Export security report to clipboard"""
        password = self.password_var.get()
        if not password:
            return
        
        report = f"""PASSWORD SECURITY REPORT
========================
Generated by PassOrFail v3.0

Entropy: {self.current_entropy:.1f} bits
Strength: {int((self.current_score / 7) * 100)}%
Checks Passed: {self.current_score}/7

Security Assessment:
"""
        
        checks = self.validate_password(password)
        if self.passphrase_mode.get():
            checks['passphrase'] = self.is_passphrase(password)
        
        check_names = {
            'length': '✓ Min 8 characters' if checks.get('length') else '✗ Min 8 characters',
            'uppercase': '✓ Uppercase letter' if checks.get('uppercase') else '✗ Uppercase letter',
            'lowercase': '✓ Lowercase letter' if checks.get('lowercase') else '✗ Lowercase letter',
            'digit': '✓ Number' if checks.get('digit') else '✗ Number',
            'special': '✓ Special character' if checks.get('special') else '✗ Special character',
            'common': '✓ Not common password' if checks.get('common') else '✗ Common password',
            'passphrase': '✓ Passphrase (4+ words)' if checks.get('passphrase') else '✗ Not a passphrase'
        }
        
        for check in check_names.values():
            report += f"  {check}\n"
        
        report += f"\nRecommendation: "
        if self.current_entropy < 36:
            report += "Use a longer password with more character variety"
        elif self.current_entropy < 60:
            report += "Consider using a passphrase or adding more complexity"
        else:
            report += "Strong password! Keep it secure and don't reuse it"
        
        self.root.clipboard_clear()
        self.root.clipboard_append(report)
        
        self.export_status.config(text="✓ Report copied to clipboard!")
        self.root.after(2000, lambda: self.export_status.config(text=""))
    
    def reset_checks(self):
        for icon_label, text_label in self.check_labels.values():
            icon_label.config(text="○", fg=self.colors['text_secondary'])
            text_label.config(fg=self.colors['text_secondary'])
        
        self.strength_canvas.delete("all")
        self.strength_label.config(text="")
        self.entropy_label.config(text="0.0 bits", fg=self.colors['accent_blue'])
        self.entropy_desc.config(text="")
        self.hibp_status_label.config(text="Enter a password to check...", fg=self.colors['text_secondary'])
        self.export_btn.config(state=tk.DISABLED)
        self.export_status.config(text="")
        
        self.current_score = 0
        self.current_entropy = 0.0
        self.strength_bar_width = 0
        self.target_bar_width = 0
    
    def _on_mousewheel(self, event):
        if event.num == 5 or event.delta < 0:
            self.canvas.yview_scroll(1, "units")
        elif event.num == 4 or event.delta > 0:
            self.canvas.yview_scroll(-1, "units")


def main():
    root = tk.Tk()
    app = PassOrFail(root)
    root.mainloop()


if __name__ == "__main__":
    main()
