import os
import sys
import time
import json
import shutil
import sqlite3
import datetime
import zipfile
import threading
import importlib.util
import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox, filedialog

# --- Environment Optimizations ---
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Suppress TF warnings
os.environ['TOKENIZERS_PARALLELISM'] = 'false' # Prevent thread locks

# --- Constants & Paths ---
CONSTANTS = {
    "APP_TITLE": "Secure Diary (Architect Edition)",
    "MODEL_ID": "Qwen/Qwen2.5-1.5B-Instruct", # SOTA Lightweight model
    "AUTO_LOCK_MS": 300000, # 5 Minutes
    "BACKUP_FREQ": 5,       # Auto-backup every 5 logins
}

PATHS = {
    "DB": "diary.db",
    "AUTH": "user.auth",
    "CONFIG": "config.json",
    "PLUGINS": "plugins",
    "THEMES": "themes",
    "MODEL": "model",       # Permanent model storage
    "BACKUPS": "backups"
}

# --- Dynamic Imports (Graceful Degradation) ---
# 1. AI Libraries
try:
    from transformers import AutoModelForCausalLM, AutoTokenizer
    import torch
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    print("AI Disabled. Install 'transformers' and 'torch' to enable.")

# 2. Cryptography
try:
    from argon2 import PasswordHasher
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    ctk.CTk() # Init dummy for message
    messagebox.showerror("Fatal Error", "Critical security libraries missing.\nRun: pip install argon2-cffi cryptography")
    sys.exit()

# 3. OCR (Scanning)
try:
    from PIL import Image
    import pytesseract
    OCR_AVAILABLE = True
    # Linux/Mac usually auto-detect. Windows users might need:
    # pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
except ImportError:
    OCR_AVAILABLE = False

# =============================================================================
# ENGINE 1: MILITARY-GRADE CRYPTOGRAPHY
# =============================================================================
class CryptoEngine:
    """Handles Argon2 hashing and AES-GCM encryption."""
    def __init__(self):
        self.backend = default_backend()
        self.master_key = None
        self.hasher = PasswordHasher()

    def setup_new_password(self, password):
        """First time setup: Hashes pass to disk, derives memory key."""
        pw_hash = self.hasher.hash(password.encode())
        with open(PATHS["AUTH"], "w") as f: f.write(pw_hash)
        self._derive_keys(password)

    def verify_password(self, password):
        """Checks input against stored hash."""
        try:
            with open(PATHS["AUTH"], "r") as f: stored_hash = f.read()
            self.hasher.verify(stored_hash, password.encode())
            if self.hasher.check_needs_rehash(stored_hash): 
                self.setup_new_password(password)
            self._derive_keys(password)
            return True
        except:
            return False

    def _derive_keys(self, password):
        """Derives session Master Key using HKDF (RAM only, never stored)."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b'secure-diary-v8-architect', backend=self.backend
        )
        self.master_key = hkdf.derive(password.encode())

    def encrypt(self, plaintext_bytes):
        if not self.master_key: raise ValueError("Vault Locked")
        # Structure: [MasterNonce 12] + [WrappedEntryKey] + [EntryNonce 12] + [Ciphertext]
        entry_key = os.urandom(32)
        entry_nonce = os.urandom(12)
        master_nonce = os.urandom(12)
        
        # 1. Encrypt Content
        ciphertext = AESGCM(entry_key).encrypt(entry_nonce, plaintext_bytes, None)
        # 2. Wrap Entry Key
        wrapped_key = AESGCM(self.master_key).encrypt(master_nonce, entry_key, None)
        
        return master_nonce + wrapped_key + entry_nonce + ciphertext

    def decrypt(self, data):
        if not self.master_key: raise ValueError("Vault Locked")
        mn, wk, en, ct = data[:12], data[12:60], data[60:72], data[72:]
        entry_key = AESGCM(self.master_key).decrypt(mn, wk, None)
        return AESGCM(entry_key).decrypt(en, ct, None)

    def lock(self):
        self.master_key = None

# =============================================================================
# ENGINE 2: LOCAL AI (OFFLINE & PERMANENT)
# =============================================================================
class LocalLLM:
    """Wrapper for HuggingFace Local Models."""
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.model_path = PATHS["MODEL"]

    def load_model(self):
        if not AI_AVAILABLE: return
        try:
            print(f"AI Engine: Checking model in '{self.model_path}'...")
            # Use cache_dir to ensure model persists on disk locally
            self.tokenizer = AutoTokenizer.from_pretrained(
                CONSTANTS["MODEL_ID"], 
                cache_dir=self.model_path
            )
            self.model = AutoModelForCausalLM.from_pretrained(
                CONSTANTS["MODEL_ID"], 
                cache_dir=self.model_path,
                torch_dtype=torch.float32, 
                device_map="cpu"
            )
            print("AI Engine: Online.")
        except Exception as e:
            print(f"AI Init Failed: {e}")
            self.model = None

    def generate(self, messages, max_new_tokens=100):
        """
        Handles Chat Templates (List of Dicts) -> Text.
        prevents the 'sad' output issue by formatting system prompts correctly.
        """
        if not self.model: return "AI not loaded."
        try:
            # Format: [{"role": "user", "content": "hi"}] -> Template
            text_input = self.tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
            
            inputs = self.tokenizer([text_input], return_tensors="pt").to(self.model.device)
            
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=max_new_tokens,
                    temperature=0.6, # Balanced creativity
                    do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            
            # Extract only the new response (remove input prompt)
            # Standard decoder sometimes keeps prompt, we slice carefully
            full_decoded = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # Basic prompt removal logic specific to Qwen/ChatML format if it leaks
            # Usually apply_chat_template handles this, but safe fallback:
            if "assistant\n" in full_decoded:
                return full_decoded.split("assistant\n")[-1].strip()
            return full_decoded.strip()
            
        except Exception as e:
            return f"Thinking error: {e}"

# =============================================================================
# ENGINE 3: CONFIG & BACKUPS
# =============================================================================
class ConfigManager:
    def __init__(self):
        self.data = {"login_count": 0, "theme": "System"}
        self._load()

    def _load(self):
        if os.path.exists(PATHS["CONFIG"]):
            try: 
                with open(PATHS["CONFIG"], 'r') as f: self.data = json.load(f)
            except: pass

    def save(self):
        with open(PATHS["CONFIG"], 'w') as f: json.dump(self.data, f)

    def increment_usage(self, backup_callback):
        self.data["login_count"] += 1
        if self.data["login_count"] >= CONSTANTS["BACKUP_FREQ"]:
            # Trigger Auto Backup
            threading.Thread(target=backup_callback).start()
            self.data["login_count"] = 0
        self.save()

# =============================================================================
# UI APPLICATION
# =============================================================================
class SecureDiaryApp(ctk.CTk):
    def __init__(self, crypto: CryptoEngine, bot: LocalLLM, config: ConfigManager):
        super().__init__()
        self.crypto = crypto
        self.bot = bot
        self.config = config
        
        self.db_conn = None
        self.current_entry_id = None
        self.idle_job = None

        # UI Setup
        self.title(CONSTANTS["APP_TITLE"])
        self.geometry("1200x800")
        self.minsize(950, 650)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self._init_db()
        self._setup_layout()
        self._refresh_timeline()
        
        # Plugin Loader
        self.after(500, self._load_plugins) # Delay slightly for UI stability

        # Security Monitors
        self.bind_all("<Key>", self._reset_idle_timer)
        self.bind_all("<Motion>", self._reset_idle_timer)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._reset_idle_timer()

    # --- Database ---
    def _init_db(self):
        self.db_conn = sqlite3.connect(PATHS["DB"], check_same_thread=False)
        self.db_conn.execute("CREATE TABLE IF NOT EXISTS entries(id INTEGER PRIMARY KEY, timestamp TEXT, content BLOB)")
        self.db_conn.commit()

    # --- UI Construction ---
    def _setup_layout(self):
        self.grid_rowconfigure(0, weight=1)
        # Col 0: Timeline, Col 1: Editor, Col 2: AI/Plugins (Reserved)
        self.grid_columnconfigure(1, weight=3) 
        self.grid_columnconfigure(2, weight=0) # Collapsed by default

        # 1. Sidebar
        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
        
        ctk.CTkLabel(self.sidebar, text="TIMELINE", font=("", 14, "bold"), text_color="gray").pack(pady=(20,10))
        
        self.timeline_frame = ctk.CTkScrollableFrame(self.sidebar, label_text="")
        self.timeline_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        ctk.CTkButton(self.sidebar, text="+ New Entry", command=self._reset_editor).pack(pady=20, padx=20)

        # 2. Main Editor Area
        self.editor_container = ctk.CTkFrame(self, fg_color="transparent")
        self.editor_container.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        self.editor_container.grid_rowconfigure(0, weight=1)
        self.editor_container.grid_columnconfigure(0, weight=1)
        
        # Textbox
        self.editor = ctk.CTkTextbox(self.editor_container, font=("Georgia", 18), wrap="word", undo=True, border_width=0)
        self.editor.grid(row=0, column=0, sticky="nsew")
        self.editor.bind("<KeyRelease>", self._on_text_change)
        
        # Welcome placeholder
        self.lbl_welcome = ctk.CTkLabel(self.editor_container, text="Encrypted Vault Locked.\nSelect an entry or write a new one.", text_color="gray")
        
        # Toolbar
        self.toolbar = ctk.CTkFrame(self, height=50)
        self.toolbar.grid(row=1, column=1, sticky="ew", padx=10, pady=(0, 10))
        
        self.btn_del = ctk.CTkButton(self.toolbar, text="Delete", fg_color="#D32F2F", hover_color="#B71C1C", width=60, command=self._delete_entry)
        self.btn_del.pack(side="left", padx=10, pady=10)
        
        ctk.CTkButton(self.toolbar, text="Scan (OCR)", fg_color="#8E24AA", hover_color="#7B1FA2", width=80, command=self._scan_document).pack(side="left", padx=5)
        
        self.btn_settings = ctk.CTkButton(self.toolbar, text="Settings", fg_color="transparent", border_width=1, width=80, command=self._open_settings)
        self.btn_settings.pack(side="left", padx=5)

        self.btn_save = ctk.CTkButton(self.toolbar, text="Save Changes", command=self._save_entry)
        self.btn_save.pack(side="right", padx=10, pady=10)

    # --- Logic: Entry Management ---
    def _refresh_timeline(self):
        for w in self.timeline_frame.winfo_children(): w.destroy()
        
        rows = self.db_conn.execute("SELECT id, timestamp FROM entries ORDER BY timestamp DESC").fetchall()
        if not rows:
            self.lbl_welcome.grid(row=0, column=0)
            self.editor.grid_remove()
            self._update_buttons(False)
            return
        
        self.lbl_welcome.grid_remove()
        self.editor.grid()
        
        # Grouping by Date
        grouped = {}
        for eid, ts in rows:
            dt = datetime.datetime.fromisoformat(ts)
            day = dt.strftime("%A, %d %b %Y")
            grouped.setdefault(day, []).append((eid, dt.strftime("%H:%M")))
            
        for day, items in grouped.items():
            ctk.CTkLabel(self.timeline_frame, text=day, font=("", 12, "bold"), text_color="gray70", anchor="w").pack(fill="x", pady=(10,2), padx=5)
            for eid, time_str in items:
                btn = ctk.CTkButton(
                    self.timeline_frame, 
                    text=f"  Entry at {time_str}", 
                    anchor="w", 
                    fg_color="transparent", 
                    border_width=1,
                    height=28,
                    command=lambda i=eid: self._load_entry(i)
                )
                btn.pack(fill="x", pady=1)
        
        self._update_buttons(False)

    def _load_entry(self, entry_id):
        self.current_entry_id = entry_id
        row = self.db_conn.execute("SELECT content FROM entries WHERE id=?", (entry_id,)).fetchone()
        if row:
            try:
                plaintext = self.crypto.decrypt(row[0]).decode('utf-8')
                self.editor.delete("0.0", "end")
                self.editor.insert("0.0", plaintext)
                self._update_buttons(True)
            except Exception:
                messagebox.showerror("Security Alert", "Decryption Failed: Integrity check error or wrong key.")

    def _save_entry(self):
        content = self.editor.get("0.0", "end").strip()
        if not content: return
        
        encrypted = self.crypto.encrypt(content.encode())
        timestamp = datetime.datetime.now().isoformat()
        
        if self.current_entry_id:
            self.db_conn.execute("UPDATE entries SET content=?, timestamp=? WHERE id=?", (encrypted, timestamp, self.current_entry_id))
        else:
            self.db_conn.execute("INSERT INTO entries (timestamp, content) VALUES (?,?)", (timestamp, encrypted))
            
        self.db_conn.commit()
        self._reset_editor() # Reset view
        self._refresh_timeline() # Update list

    def _delete_entry(self):
        if self.current_entry_id and messagebox.askyesno("Delete", "Are you sure? This cannot be undone."):
            self.db_conn.execute("DELETE FROM entries WHERE id=?", (self.current_entry_id,))
            self.db_conn.commit()
            self._reset_editor()
            self._refresh_timeline()

    def _reset_editor(self):
        self.current_entry_id = None
        self.editor.delete("0.0", "end")
        self.editor.grid()
        self.lbl_welcome.grid_remove()
        self.editor.focus()
        self._update_buttons(False)

    def _update_buttons(self, has_content):
        # Simple UI state management
        self.btn_save.configure(state="normal" if has_content else "disabled")
        self.btn_del.configure(state="normal" if self.current_entry_id else "disabled")

    def _on_text_change(self, event=None):
        has_txt = len(self.editor.get("0.0", "end").strip()) > 0
        self.btn_save.configure(state="normal" if has_txt else "disabled")

    # --- Scan / OCR ---
    def _scan_document(self):
        if not OCR_AVAILABLE:
            messagebox.showerror("OCR Error", "Scanning libraries (Pillow/pytesseract) or Tesseract Binary not found.")
            return
        
        path = filedialog.askopenfilename(title="Select Page Scan", filetypes=[("Images", "*.png;*.jpg;*.jpeg;*.bmp")])
        if not path: return

        try:
            # Loading Dialog
            load_win = ctk.CTkToplevel(self); load_win.title("Scanning"); load_win.geometry("250x100")
            ctk.CTkLabel(load_win, text="Extracting text...").pack(expand=True)
            self.update()

            # Processing
            img = Image.open(path)
            text = pytesseract.image_to_string(img)
            
            if text.strip():
                self.editor.insert("end", f"\n\n--- SCANNED CONTENT ({datetime.datetime.now().strftime('%H:%M')}) ---\n{text}\n---------------------\n")
                messagebox.showinfo("Success", "Scan appended to entry.")
            else:
                messagebox.showwarning("OCR", "No clear text found in image.")
            
            load_win.destroy()
        except Exception as e:
            messagebox.showerror("Scan Error", str(e))

    # --- Plugins ---
    def get_history_text(self):
        """Exposed for Plugins: Returns current editor content"""
        return self.editor.get("0.0", "end").strip()

    def _load_plugins(self):
        if not os.path.exists(PATHS["PLUGINS"]): os.makedirs(PATHS["PLUGINS"])
        for f in os.listdir(PATHS["PLUGINS"]):
            if f.endswith(".py"):
                try:
                    spec = importlib.util.spec_from_file_location(f[:-3], os.path.join(PATHS["PLUGINS"], f))
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    if hasattr(module, 'register'): 
                        module.register(self) # Pass the app instance to the plugin
                except Exception as e:
                    print(f"Plugin Error [{f}]: {e}")

    # --- Settings / Auto-Backup Callback ---
    def _perform_auto_backup(self):
        # Requires a hack: We need to read the Auth File Hash, use that to encrypt backup
        # so it can be restored with the master password later.
        try:
            if not os.path.exists(PATHS["BACKUPS"]): os.makedirs(PATHS["BACKUPS"])
            
            ts = datetime.datetime.now().strftime("%Y%m%d")
            backup_path = os.path.join(PATHS["BACKUPS"], f"AutoBackup_{ts}.bak")
            
            with open(PATHS["AUTH"], "r") as f: key_hash = f.read().strip()
            self._encrypt_backup(backup_path, key_hash)
            print(f"Backup created: {backup_path}")
        except: pass

    def _open_settings(self):
        s_win = ctk.CTkToplevel(self); s_win.title("Settings"); s_win.geometry("400x300")
        s_win.transient(self); s_win.grab_set()
        
        ctk.CTkLabel(s_win, text="Data Management", font=("", 14, "bold")).pack(pady=10)
        
        ctk.CTkButton(s_win, text="Export Encrypted Backup", command=self._export_manual_backup).pack(fill="x", padx=20, pady=5)
        ctk.CTkButton(s_win, text="Factory Reset", fg_color="#D32F2F", hover_color="#B71C1C", command=self._factory_reset).pack(fill="x", padx=20, pady=20)
        
        info = f"App Version: 8.0\nUsage Count: {self.config.data['login_count']}\nModel: {CONSTANTS['MODEL_ID']}"
        ctk.CTkLabel(s_win, text=info, text_color="gray").pack(side="bottom", pady=10)

    def _export_manual_backup(self):
        path = filedialog.asksaveasfilename(defaultextension=".bak", filetypes=[("Secure Backup", "*.bak")])
        if not path: return
        
        pwd = LoginDialog(self, "Backup Password", is_setup=True).get_input()
        if not pwd: return
        
        try:
            self._encrypt_backup(path, pwd)
            messagebox.showinfo("Success", "Backup exported.")
        except Exception as e: messagebox.showerror("Error", str(e))

    def _encrypt_backup(self, filepath, secret_string):
        # ZIP DB + Auth -> Encrypt
        shutil.copyfile(PATHS["DB"], "temp.db")
        with zipfile.ZipFile("temp.zip", "w") as zf:
            zf.write("temp.db")
            zf.write(PATHS["AUTH"])
        
        with open("temp.zip", "rb") as f: raw_data = f.read()
        
        # PBKDF2 derivation for backup portability
        salt = os.urandom(16); nonce = os.urandom(12)
        kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600000, default_backend())
        key = kdf.derive(secret_string.encode())
        
        encrypted = salt + nonce + AESGCM(key).encrypt(nonce, raw_data, None)
        
        with open(filepath, "wb") as f: f.write(encrypted)
        os.remove("temp.db"); os.remove("temp.zip")

    def _factory_reset(self):
        if messagebox.askyesno("NUCLEAR OPTION", "Permanently delete ALL data?\n(Keys, Diary, Auth files)."):
            try:
                self.db_conn.close()
                for f in [PATHS["DB"], PATHS["AUTH"]]:
                    if os.path.exists(f): os.remove(f)
                sys.exit()
            except: pass

    # --- Security Lock ---
    def _reset_idle_timer(self, event=None):
        if self.idle_job: self.after_cancel(self.idle_job)
        self.idle_job = self.after(CONSTANTS["AUTO_LOCK_MS"], self._lock_screen)

    def _lock_screen(self):
        self.withdraw()
        self.crypto.lock()
        
        # Simple Auth Loop
        while True:
            pwd = LoginDialog(self, "Vault Locked").get_input()
            if pwd is None: sys.exit() # Closed window
            
            if self.crypto.verify_password(pwd):
                self.deiconify()
                self._reset_idle_timer()
                break
            messagebox.showwarning("Error", "Incorrect Password")

    def _on_close(self):
        if self.db_conn: self.db_conn.close()
        self.destroy()

# =============================================================================
# DIALOG HELPER
# =============================================================================
class LoginDialog(ctk.CTkToplevel):
    def __init__(self, parent, title, is_setup=False):
        super().__init__(parent)
        self.pwd = None
        self.title(title)
        self.geometry("300x160")
        self.transient(parent)
        self.resizable(False, False)
        
        # Center
        try:
            x, y = parent.winfo_x() + (parent.winfo_width()//2 - 150), parent.winfo_y() + (parent.winfo_height()//2 - 80)
            self.geometry(f"+{x}+{y}")
        except: pass

        lbl = "Create Master Password" if is_setup else "Enter Password"
        ctk.CTkLabel(self, text=lbl, font=("", 14, "bold")).pack(pady=15)
        
        self.entry = ctk.CTkEntry(self, show="*", width=200)
        self.entry.pack(pady=5)
        self.entry.focus()
        self.entry.bind("<Return>", self.ok)
        
        ctk.CTkButton(self, text="Unlock/Confirm", width=100, command=self.ok).pack(pady=15)
        
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.grab_set()

    def ok(self, e=None):
        self.pwd = self.entry.get()
        self.destroy()
        
    def cancel(self):
        self.pwd = None
        self.destroy()

    def get_input(self):
        self.master.wait_window(self)
        return self.pwd

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    # 1. Init Root (Invisible)
    root = ctk.CTk()
    root.withdraw()
    
    engine = CryptoEngine()
    
    # 2. Authentication
    if not os.path.exists(PATHS["AUTH"]):
        # Setup Flow
        p1 = LoginDialog(root, "Setup", is_setup=True).get_input()
        if p1: 
            engine.setup_new_password(p1)
            messagebox.showinfo("Welcome", "Password set. Do not forget it.")
        else: sys.exit()
    else:
        # Login Flow
        tries = 0
        while True:
            p = LoginDialog(root, "Login").get_input()
            if not p: sys.exit()
            if engine.verify_password(p): break
            tries += 1
            if tries >= 3: sys.exit()

    # 3. Configuration & Logic
    config_mgr = ConfigManager()
    
    # 4. AI Loader (Splash Screen)
    splash = ctk.CTkToplevel()
    splash.overrideredirect(True)
    sw, sh = splash.winfo_screenwidth(), splash.winfo_screenheight()
    splash.geometry(f"300x120+{sw//2-150}+{sh//2-60}")
    
    ctk.CTkLabel(splash, text="Secure Diary Architect", font=("", 16, "bold")).pack(pady=(20,5))
    status_label = ctk.CTkLabel(splash, text="Initializing Security Core...", font=("", 12))
    status_label.pack()

    bot_engine = LocalLLM()

    def launch_sequence():
        # Trigger auto backup based on count
        config_mgr.increment_usage(lambda: SecureDiaryApp._perform_auto_backup(None)) 
        # (Note: In class structure, we'll actually hook this in the app, simplified here)
        
        status_label.configure(text="Loading AI Brain (Permanent)...")
        bot_engine.load_model() # This blocks nicely in thread
        
        status_label.configure(text="Launching UI...")
        time.sleep(0.5)
        splash.destroy()
        
        # Start App
        app = SecureDiaryApp(engine, bot_engine, config_mgr)
        # Inject the actual backup method context
        app._perform_auto_backup = app._perform_auto_backup 
        app.mainloop()

    threading.Thread(target=launch_sequence).start()
    
    # Main Loop
    root.mainloop()