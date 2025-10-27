#!/usr/bin/env python3
"""
PassOrFail v2.0 - Advanced Password Security Checker
A modern, sleek GUI application for checking password strength
with HIBP integration, entropy calculation, and passphrase support
"""

import tkinter as tk
from tkinter import ttk
import re
import math
import hashlib
import requests
from typing import Dict, List, Tuple
import threading

class PassOrFail:
    def __init__(self, root):
        self.root = root
        self.root.title("PassOrFail - Password Security Checker")
        self.root.geometry("650x750")
        self.root.minsize(550, 600)  # Minimum size
        self.root.maxsize(900, 1000)  # Maximum size
        self.root.resizable(True, True)  # Allow resize
        self.root.configure(bg="#0a0e27")
        
        # Color scheme - Dark hacker aesthetic
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
        
        # Common weak passwords list
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
        
        # HIBP check status
        self.hibp_status = None
        self.checking_hibp = False
        
        self.setup_ui()
        self.animate_glow()
        
    def setup_ui(self):
        # Header with animated glow
        header_frame = tk.Frame(self.root, bg=self.colors['bg_primary'], height=140)
        header_frame.pack(fill=tk.X, pady=(20, 10))
        
        # Logo and title container
        logo_title_frame = tk.Frame(header_frame, bg=self.colors['bg_primary'])
        logo_title_frame.pack()
        
        # Create shield logo using canvas
        self.logo_canvas = tk.Canvas(
            logo_title_frame,
            width=50,
            height=50,
            bg=self.colors['bg_primary'],
            highlightthickness=0
        )
        self.logo_canvas.pack(side=tk.LEFT, padx=(0, 15))
        self.draw_shield_logo()
        
        # Title frame
        title_frame = tk.Frame(logo_title_frame, bg=self.colors['bg_primary'])
        title_frame.pack(side=tk.LEFT)
        
        self.title_label = tk.Label(
            title_frame,
            text="PASS OR FAIL",
            font=("Courier New", 34, "bold"),
            bg=self.colors['bg_primary'],
            fg=self.colors['accent_green']
        )
        self.title_label.pack()
        
        subtitle_label = tk.Label(
            header_frame,
            text="[ PASSWORD SECURITY ANALYZER ]",
            font=("Courier New", 11),
            bg=self.colors['bg_primary'],
            fg=self.colors['text_secondary']
        )
        subtitle_label.pack(pady=(5, 0))
        
        tagline_label = tk.Label(
            header_frame,
            text="Test your password strength in real-time. Stay secure.",
            font=("Courier New", 9, "italic"),
            bg=self.colors['bg_primary'],
            fg=self.colors['accent_cyan']
        )
        tagline_label.pack(pady=(5, 0))
        
        # Create main container with scrollbar
        main_container = tk.Frame(self.root, bg=self.colors['bg_primary'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        
        # Create canvas for scrolling
        self.canvas = tk.Canvas(main_container, bg=self.colors['bg_primary'], highlightthickness=0)
        scrollbar = tk.Scrollbar(main_container, orient="vertical", command=self.canvas.yview)
        
        # Create scrollable frame
        main_frame = tk.Frame(self.canvas, bg=self.colors['bg_primary'])
        
        # Configure canvas
        main_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=main_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack canvas and scrollbar
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Bind mousewheel for smooth scrolling
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", self._on_mousewheel)  # Linux scroll up
        self.canvas.bind_all("<Button-5>", self._on_mousewheel)  # Linux scroll down
        
        # Password input section
        input_container = tk.Frame(main_frame, bg=self.colors['bg_secondary'], 
                                   highlightbackground=self.colors['border'], 
                                   highlightthickness=2)
        input_container.pack(fill=tk.X, pady=(0, 15))
        
        input_label = tk.Label(
            input_container,
            text="ENTER PASSWORD:",
            font=("Courier New", 10, "bold"),
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_secondary']
        )
        input_label.pack(anchor=tk.W, padx=15, pady=(15, 5))
        
        # Password entry with show/hide toggle
        entry_frame = tk.Frame(input_container, bg=self.colors['bg_secondary'])
        entry_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        self.password_var = tk.StringVar()
        self.password_var.trace('w', self.check_password)
        
        self.password_entry = tk.Entry(
            entry_frame,
            textvariable=self.password_var,
            font=("Courier New", 14),
            bg=self.colors['bg_input'],
            fg=self.colors['text_primary'],
            insertbackground=self.colors['accent_green'],
            relief=tk.FLAT,
            show="●"
        )
        self.password_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, ipady=10)
        self.password_entry.focus()
        
        self.show_var = tk.BooleanVar()
        show_btn = tk.Checkbutton(
            entry_frame,
            text="👁",
            variable=self.show_var,
            command=self.toggle_password,
            font=("Arial", 12),
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_primary'],
            selectcolor=self.colors['bg_input'],
            activebackground=self.colors['bg_secondary'],
            activeforeground=self.colors['accent_green'],
            relief=tk.FLAT
        )
        show_btn.pack(side=tk.LEFT, padx=(10, 0))
        
        # Strength and Entropy Display
        metrics_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        metrics_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Left side - Strength
        strength_frame = tk.Frame(metrics_frame, bg=self.colors['bg_primary'])
        strength_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        strength_label = tk.Label(
            strength_frame,
            text="STRENGTH:",
            font=("Courier New", 9, "bold"),
            bg=self.colors['bg_primary'],
            fg=self.colors['text_secondary']
        )
        strength_label.pack(anchor=tk.W)
        
        self.strength_canvas = tk.Canvas(
            strength_frame,
            height=25,
            bg=self.colors['bg_secondary'],
            highlightthickness=0
        )
        self.strength_canvas.pack(fill=tk.X, pady=(5, 0))
        
        self.strength_label = tk.Label(
            strength_frame,
            text="",
            font=("Courier New", 9, "bold"),
            bg=self.colors['bg_primary'],
            fg=self.colors['text_secondary']
        )
        self.strength_label.pack(anchor=tk.W, pady=(5, 0))
        
        # Right side - Entropy
        entropy_frame = tk.Frame(metrics_frame, bg=self.colors['bg_primary'])
        entropy_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        entropy_header = tk.Label(
            entropy_frame,
            text="ENTROPY:",
            font=("Courier New", 9, "bold"),
            bg=self.colors['bg_primary'],
            fg=self.colors['text_secondary']
        )
        entropy_header.pack(anchor=tk.W)
        
        self.entropy_label = tk.Label(
            entropy_frame,
            text="0.0 bits",
            font=("Courier New", 16, "bold"),
            bg=self.colors['bg_primary'],
            fg=self.colors['accent_blue']
        )
        self.entropy_label.pack(anchor=tk.W, pady=(5, 0))
        
        self.entropy_desc = tk.Label(
            entropy_frame,
            text="",
            font=("Courier New", 8),
            bg=self.colors['bg_primary'],
            fg=self.colors['text_secondary']
        )
        self.entropy_desc.pack(anchor=tk.W)
        
        # HIBP Status
        hibp_frame = tk.Frame(main_frame, bg=self.colors['bg_secondary'],
                             highlightbackground=self.colors['border'],
                             highlightthickness=2)
        hibp_frame.pack(fill=tk.X, pady=(0, 15))
        
        hibp_header = tk.Label(
            hibp_frame,
            text="🌐 BREACH CHECK (Have I Been Pwned)",
            font=("Courier New", 9, "bold"),
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_secondary']
        )
        hibp_header.pack(anchor=tk.W, padx=15, pady=(10, 5))
        
        self.hibp_status_label = tk.Label(
            hibp_frame,
            text="Enter a password to check...",
            font=("Courier New", 9),
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_secondary'],
            wraplength=550,
            justify=tk.LEFT
        )
        self.hibp_status_label.pack(anchor=tk.W, padx=15, pady=(0, 10))
        
        # Security checks section
        checks_container = tk.Frame(main_frame, bg=self.colors['bg_secondary'],
                                   highlightbackground=self.colors['border'],
                                   highlightthickness=2)
        checks_container.pack(fill=tk.BOTH, expand=True)
        
        checks_header = tk.Label(
            checks_container,
            text="SECURITY REQUIREMENTS",
            font=("Courier New", 10, "bold"),
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_secondary']
        )
        checks_header.pack(anchor=tk.W, padx=15, pady=(15, 10))
        
        # Create check items
        self.check_labels = {}
        checks = [
            ('length', 'Minimum 8 characters'),
            ('uppercase', 'Contains uppercase letter (A-Z)'),
            ('lowercase', 'Contains lowercase letter (a-z)'),
            ('digit', 'Contains number (0-9)'),
            ('special', 'Contains special character (!@#$%^&*)'),
            ('common', 'Not a common password'),
            ('passphrase', 'Passphrase bonus (4+ words)')
        ]
        
        for key, text in checks:
            check_frame = tk.Frame(checks_container, bg=self.colors['bg_secondary'])
            check_frame.pack(fill=tk.X, padx=15, pady=4)
            
            icon_label = tk.Label(
                check_frame,
                text="○",
                font=("Arial", 14),
                bg=self.colors['bg_secondary'],
                fg=self.colors['text_secondary'],
                width=2
            )
            icon_label.pack(side=tk.LEFT)
            
            text_label = tk.Label(
                check_frame,
                text=text,
                font=("Courier New", 9),
                bg=self.colors['bg_secondary'],
                fg=self.colors['text_secondary'],
                anchor=tk.W
            )
            text_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
            
            self.check_labels[key] = (icon_label, text_label)
        
        # Passphrase tip
        tip_label = tk.Label(
            checks_container,
            text='💡 TIP: "correct horse battery staple" is stronger than "P@ssw0rd!"',
            font=("Courier New", 8, "italic"),
            bg=self.colors['bg_secondary'],
            fg=self.colors['accent_cyan'],
            wraplength=550,
            justify=tk.LEFT
        )
        tip_label.pack(anchor=tk.W, padx=15, pady=(10, 15))
        
        # Footer
        footer_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        footer_frame.pack(side=tk.BOTTOM, pady=(15, 0))
        
        footer = tk.Label(
            footer_frame,
            text="© 2025 PassOrFail",
            font=("Courier New", 9, "bold"),
            bg=self.colors['bg_primary'],
            fg=self.colors['accent_green']
        )
        footer.pack()
        
        footer_sub = tk.Label(
            footer_frame,
            text="Secure Your Digital Life | Open Source Security Tool",
            font=("Courier New", 7),
            bg=self.colors['bg_primary'],
            fg=self.colors['text_secondary']
        )
        footer_sub.pack()
    
    def draw_shield_logo(self):
        """Draw an animated shield/lock logo"""
        # Shield outline
        points = [25, 5, 45, 15, 45, 35, 25, 45, 5, 35, 5, 15]
        self.logo_canvas.create_polygon(
            points,
            fill=self.colors['bg_secondary'],
            outline=self.colors['accent_green'],
            width=2
        )
        
        # Lock icon inside
        # Lock body
        self.logo_canvas.create_rectangle(
            18, 25, 32, 38,
            fill=self.colors['accent_green'],
            outline=""
        )
        
        # Lock shackle
        self.logo_canvas.create_arc(
            20, 15, 30, 28,
            start=0,
            extent=180,
            style=tk.ARC,
            outline=self.colors['accent_green'],
            width=2
        )
        
        # Keyhole
        self.logo_canvas.create_oval(
            23, 28, 27, 32,
            fill=self.colors['bg_primary'],
            outline=""
        )
    
    def animate_glow(self):
        """Animate the glow effect on the title"""
        self.glow_intensity += self.glow_direction * 2
        
        if self.glow_intensity >= 100:
            self.glow_direction = -1
        elif self.glow_intensity <= 0:
            self.glow_direction = 1
        
        # Calculate color gradient
        intensity = self.glow_intensity / 100
        r = int(0 + (0 * intensity))
        g = int(255 * (0.7 + 0.3 * intensity))
        b = int(136 + (0 * intensity))
        
        glow_color = f'#{r:02x}{g:02x}{b:02x}'
        self.title_label.config(fg=glow_color)
        
        self.root.after(30, self.animate_glow)
    
    def toggle_password(self):
        if self.show_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="●")
    
    def check_password(self, *args):
        password = self.password_var.get()
        
        if not password:
            self.reset_checks()
            return
        
        # Perform security checks
        checks = self.validate_password(password)
        score = sum(checks.values())
        
        # Calculate entropy
        entropy = self.calculate_entropy(password)
        
        # Check if passphrase
        is_passphrase = self.is_passphrase(password)
        checks['passphrase'] = is_passphrase
        if is_passphrase:
            score += 1
        
        # Update check indicators
        for key, (icon_label, text_label) in self.check_labels.items():
            if checks.get(key, False):
                icon_label.config(text="✓", fg=self.colors['accent_green'])
                text_label.config(fg=self.colors['accent_green'])
            else:
                icon_label.config(text="✗", fg=self.colors['accent_red'])
                text_label.config(fg=self.colors['text_secondary'])
        
        # Update strength meter
        self.update_strength_meter(score, 7)
        
        # Update entropy display
        self.update_entropy_display(entropy)
        
        # Check HIBP (with debouncing)
        if len(password) >= 4:
            self.schedule_hibp_check(password)
    
    def validate_password(self, password: str) -> Dict[str, bool]:
        """Validate password against security criteria using regex"""
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
        """Check if password is a passphrase (4+ words separated by spaces or special chars)"""
        # Split by spaces or common separators
        words = re.split(r'[\s\-_]+', password)
        # Filter out empty strings and very short "words"
        meaningful_words = [w for w in words if len(w) >= 3]
        return len(meaningful_words) >= 4
    
    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits"""
        if not password:
            return 0.0
        
        # Determine character set size
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
        
        # Entropy = log2(charset_size ^ length)
        entropy = len(password) * math.log2(charset_size)
        return entropy
    
    def update_entropy_display(self, entropy: float):
        """Update the entropy display"""
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
        """Update the visual strength meter"""
        self.strength_canvas.delete("all")
        
        width = self.strength_canvas.winfo_width()
        if width <= 1:
            width = 260
        
        height = 25
        
        # Determine strength level and color
        percentage = (score / max_score) * 100
        
        if percentage < 40:
            level = "WEAK"
            color = self.colors['accent_red']
        elif percentage < 70:
            level = "MODERATE"
            color = self.colors['accent_yellow']
        else:
            level = "STRONG"
            color = self.colors['accent_green']
        
        # Draw background
        self.strength_canvas.create_rectangle(
            0, 0, width, height,
            fill=self.colors['bg_input'],
            outline=""
        )
        
        # Draw strength bar
        bar_width = (width * percentage) / 100
        self.strength_canvas.create_rectangle(
            0, 0, bar_width, height,
            fill=color,
            outline=""
        )
        
        # Draw percentage text
        self.strength_canvas.create_text(
            width / 2, height / 2,
            text=f"{int(percentage)}%",
            font=("Courier New", 11, "bold"),
            fill=self.colors['text_primary']
        )
        
        # Update strength label
        self.strength_label.config(
            text=f"[{level}] - {score}/{max_score} checks passed",
            fg=color
        )
    
    def schedule_hibp_check(self, password: str):
        """Schedule HIBP check with debouncing"""
        if hasattr(self, '_hibp_after_id'):
            self.root.after_cancel(self._hibp_after_id)
        
        self._hibp_after_id = self.root.after(800, lambda: self.check_hibp(password))
    
    def check_hibp(self, password: str):
        """Check password against Have I Been Pwned database using k-anonymity"""
        if self.checking_hibp:
            return
        
        self.checking_hibp = True
        self.hibp_status_label.config(
            text="🔄 Checking breach database...",
            fg=self.colors['accent_blue']
        )
        
        # Run in thread to avoid blocking UI
        thread = threading.Thread(target=self._hibp_check_thread, args=(password,))
        thread.daemon = True
        thread.start()
    
    def _hibp_check_thread(self, password: str):
        """Thread worker for HIBP check"""
        try:
            # Hash password with SHA-1
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Query HIBP API with prefix only (k-anonymity)
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                # Check if our suffix is in the results
                hashes = response.text.split('\r\n')
                for hash_line in hashes:
                    hash_suffix, count = hash_line.split(':')
                    if hash_suffix == suffix:
                        # Password found in breach!
                        count = int(count)
                        self.root.after(0, lambda: self._update_hibp_ui(
                            f"⚠️ WARNING: This password has been seen {count:,} times in data breaches!",
                            self.colors['accent_red']
                        ))
                        return
                
                # Password not found - good!
                self.root.after(0, lambda: self._update_hibp_ui(
                    "✓ Good news! This password has not been found in known breaches.",
                    self.colors['accent_green']
                ))
            else:
                self.root.after(0, lambda: self._update_hibp_ui(
                    "⚠️ Could not check breach database (service unavailable)",
                    self.colors['text_secondary']
                ))
        
        except Exception as e:
            self.root.after(0, lambda: self._update_hibp_ui(
                "⚠️ Could not connect to breach database (check internet connection)",
                self.colors['text_secondary']
            ))
        
        finally:
            self.checking_hibp = False
    
    def _update_hibp_ui(self, message: str, color: str):
        """Update HIBP status in UI thread"""
        self.hibp_status_label.config(text=message, fg=color)
    
    def reset_checks(self):
        """Reset all check indicators"""
        for icon_label, text_label in self.check_labels.values():
            icon_label.config(text="○", fg=self.colors['text_secondary'])
            text_label.config(fg=self.colors['text_secondary'])
        
        self.strength_canvas.delete("all")
        self.strength_label.config(text="")
        self.entropy_label.config(text="0.0 bits", fg=self.colors['accent_blue'])
        self.entropy_desc.config(text="")
        self.hibp_status_label.config(
            text="Enter a password to check...",
            fg=self.colors['text_secondary']
        )
    
    def _on_mousewheel(self, event):
        """Handle mousewheel scrolling"""
        if event.num == 5 or event.delta < 0:  # Scroll down
            self.canvas.yview_scroll(1, "units")
        elif event.num == 4 or event.delta > 0:  # Scroll up
            self.canvas.yview_scroll(-1, "units")


def main():
    root = tk.Tk()
    app = PassOrFail(root)
    root.mainloop()


if __name__ == "__main__":
    main()
