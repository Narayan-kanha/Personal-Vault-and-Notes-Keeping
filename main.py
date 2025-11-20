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
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TOKENIZERS_PARALLELISM'] = 'false' 

# --- Constants & Paths ---
CONSTANTS = {
    "APP_TITLE": "Secure Diary (Architect Edition)",
    "MODEL_ID": "Qwen/Qwen2.5-1.5B-Instruct",
    "AUTO_LOCK_MS": 300000, # 5 Minutes
    "BACKUP_FREQ": 5,       # Auto-backup every 5 logins
}

PATHS = {
    "DB": "diary.db",
    "AUTH": "user.auth",
    "CONFIG": "config.json",
    "PLUGINS": "plugins",
    "THEMES": "themes",
    "MODEL": "model",
    "BACKUPS": "backups"
}

# --- Dynamic Imports ---
# 1. AI Libraries
try:
    from transformers import AutoModelForCausalLM, AutoTokenizer
    import torch
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    print("AI Disabled. Install 'transformers' and 'torch'.")

# 2. Cryptography
try:
    from argon2 import PasswordHasher
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    # Safe exit if libs missing
    import tkinter
    root = tkinter.Tk()
    root.withdraw()
    tkinter.messagebox.showerror("Error", "Crypto libraries missing. Run: pip install argon2-cffi cryptography")
    sys.exit()

# 3. OCR (Scanning)
try:
    from PIL import Image
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False

# =============================================================================
# ENGINE 1: CRYPTOGRAPHY
# =============================================================================
class CryptoEngine:
    def __init__(self):
        self.backend = default_backend()
        self.master_key = None
        self.hasher = PasswordHasher()

    def setup_new_password(self, password):
        pw_hash = self.hasher.hash(password.encode())
        with open(PATHS["AUTH"], "w") as f: f.write(pw_hash)
        self._derive_keys(password)

    def verify_password(self, password):
        try:
            with open(PATHS["AUTH"], "r") as f: stored_hash = f.read()
            self.hasher.verify(stored_hash, password.encode())
            if self.hasher.check_needs_rehash(stored_hash): 
                self.setup_new_password(password)
            self._derive_keys(password)
            return True
        except: return False

    def _derive_keys(self, password):
        hkdf = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b'secure-diary-v8-architect', backend=self.backend
        )
        self.master_key = hkdf.derive(password.encode())

    def encrypt(self, plaintext_bytes):
        if not self.master_key: raise ValueError("Locked")
        entry_key, entry_nonce, master_nonce = os.urandom(32), os.urandom(12), os.urandom(12)
        ciphertext = AESGCM(entry_key).encrypt(entry_nonce, plaintext_bytes, None)
        wrapped_key = AESGCM(self.master_key).encrypt(master_nonce, entry_key, None)
        return master_nonce + wrapped_key + entry_nonce + ciphertext

    def decrypt(self, data):
        if not self.master_key: raise ValueError("Locked")
        mn, wk, en, ct = data[:12], data[12:60], data[60:72], data[72:]
        entry_key = AESGCM(self.master_key).decrypt(mn, wk, None)
        return AESGCM(entry_key).decrypt(en, ct, None)

    def lock(self): self.master_key = None

# =============================================================================
# ENGINE 2: AI (Offline)
# =============================================================================
class LocalLLM:
    def __init__(self):
        self.model = None; self.tokenizer = None
        self.model_path = PATHS["MODEL"]

    def load_model(self):
        if not AI_AVAILABLE: return
        try:
            print(f"AI Engine: Loading from '{self.model_path}'...")
            self.tokenizer = AutoTokenizer.from_pretrained(CONSTANTS["MODEL_ID"], cache_dir=self.model_path)
            self.model = AutoModelForCausalLM.from_pretrained(
                CONSTANTS["MODEL_ID"], cache_dir=self.model_path,
                torch_dtype=torch.float32, device_map="cpu"
            )
            print("AI Engine: Online.")
        except Exception as e:
            print(f"AI Init Failed: {e}"); self.model = None

    def generate(self, messages, max_new_tokens=100):
        if not self.model: return "AI not loaded."
        try:
            text_input = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            inputs = self.tokenizer([text_input], return_tensors="pt").to(self.model.device)
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs, max_new_tokens=max_new_tokens, temperature=0.6, do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            decoded = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            # Clean extraction of assistant response
            if "assistant\n" in decoded: return decoded.split("assistant\n")[-1].strip()
            return decoded.strip()
        except Exception as e: return f"Error: {e}"

# =============================================================================
# ENGINE 3: CONFIG MANAGER
# =============================================================================
class ConfigManager:
    def __init__(self):
        self.data = {"login_count": 0}
        self._load()

    def _load(self):
        if os.path.exists(PATHS["CONFIG"]):
            try: 
                with open(PATHS["CONFIG"], 'r') as f: self.data = json.load(f)
            except: pass

    def save(self):
        with open(PATHS["CONFIG"], 'w') as f: json.dump(self.data, f)
    
    def check_backup_due(self):
        self.data["login_count"] += 1
        self.save()
        return (self.data["login_count"] % CONSTANTS["BACKUP_FREQ"] == 0)

# =============================================================================
# UI APPLICATION
# =============================================================================
class SecureDiaryApp(ctk.CTk):
    def __init__(self, crypto: CryptoEngine, bot: LocalLLM, config: ConfigManager):
        super().__init__()
        self.crypto = crypto; self.bot = bot; self.config = config
        self.db_conn = None; self.current_entry_id = None; self.idle_job = None

        self.title(CONSTANTS["APP_TITLE"]); self.geometry("1200x800"); self.minsize(950, 650)
        ctk.set_appearance_mode("dark"); ctk.set_default_color_theme("blue")

        self._init_db(); self._setup_layout(); self._refresh_timeline()
        self.after(100, self._load_plugins)
        
        # Auto Backup Check
        if self.config.check_backup_due():
            self.after(2000, self._perform_auto_backup)

        # Security Monitor
        self.bind_all("<Key>", self._reset_idle_timer); self.bind_all("<Motion>", self._reset_idle_timer)
        self.protocol("WM_DELETE_WINDOW", self._on_close); self._reset_idle_timer()

    def _init_db(self):
        self.db_conn = sqlite3.connect(PATHS["DB"], check_same_thread=False)
        self.db_conn.execute("CREATE TABLE IF NOT EXISTS entries(id INTEGER PRIMARY KEY, timestamp TEXT, content BLOB)")
        self.db_conn.commit()

    def _setup_layout(self):
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=3) # Editor
        self.grid_columnconfigure(2, weight=0) # AI Panel

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
        ctk.CTkLabel(self.sidebar, text="TIMELINE", font=("", 14, "bold"), text_color="gray").pack(pady=(20,10))
        self.timeline_frame = ctk.CTkScrollableFrame(self.sidebar, label_text=""); self.timeline_frame.pack(fill="both", expand=True, padx=5, pady=5)
        ctk.CTkButton(self.sidebar, text="+ New Entry", command=self._reset_editor).pack(pady=20, padx=20)

        # Editor Container
        self.editor_container = ctk.CTkFrame(self, fg_color="transparent")
        self.editor_container.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        self.editor_container.grid_rowconfigure(0, weight=1); self.editor_container.grid_columnconfigure(0, weight=1)
        
        self.editor = ctk.CTkTextbox(self.editor_container, font=("Georgia", 18), wrap="word", undo=True, border_width=0)
        self.editor.grid(row=0, column=0, sticky="nsew")
        self.editor.bind("<KeyRelease>", self._on_text_change)
        self.lbl_welcome = ctk.CTkLabel(self.editor_container, text="Locked. Select entry.", text_color="gray")
        
        # Toolbar
        self.toolbar = ctk.CTkFrame(self, height=50)
        self.toolbar.grid(row=1, column=1, sticky="ew", padx=10, pady=(0, 10))
        self.btn_del = ctk.CTkButton(self.toolbar, text="Delete", fg_color="#D32F2F", hover_color="#B71C1C", width=60, command=self._delete_entry); self.btn_del.pack(side="left", padx=10, pady=10)
        ctk.CTkButton(self.toolbar, text="Scan (OCR)", fg_color="#8E24AA", hover_color="#7B1FA2", width=80, command=self._scan_document).pack(side="left", padx=5)
        self.btn_settings = ctk.CTkButton(self.toolbar, text="Settings", fg_color="transparent", border_width=1, width=80, command=self._open_settings); self.btn_settings.pack(side="left", padx=5)
        self.btn_save = ctk.CTkButton(self.toolbar, text="Save", command=self._save_entry); self.btn_save.pack(side="right", padx=10, pady=10)

    def _refresh_timeline(self):
        for w in self.timeline_frame.winfo_children(): w.destroy()
        rows = self.db_conn.execute("SELECT id, timestamp FROM entries ORDER BY timestamp DESC").fetchall()
        
        if not rows:
            self.lbl_welcome.grid(row=0, column=0); self.editor.grid_remove(); self._update_buttons(False); return
        
        self.lbl_welcome.grid_remove(); self.editor.grid()
        grouped = {}
        for eid, ts in rows:
            day = datetime.datetime.fromisoformat(ts).strftime("%A, %d %b")
            grouped.setdefault(day, []).append((eid, datetime.datetime.fromisoformat(ts).strftime("%H:%M")))
            
        for day, items in grouped.items():
            ctk.CTkLabel(self.timeline_frame, text=day, font=("", 12, "bold"), text_color="gray", anchor="w").pack(fill="x", pady=(10,2), padx=5)
            for eid, time_str in items:
                ctk.CTkButton(self.timeline_frame, text=f"  Entry at {time_str}", anchor="w", fg_color="transparent", border_width=1, height=28, command=lambda i=eid: self._load_entry(i)).pack(fill="x", pady=1)
        self._update_buttons(False)

    def _load_entry(self, entry_id):
        self.current_entry_id = entry_id
        row = self.db_conn.execute("SELECT content FROM entries WHERE id=?", (entry_id,)).fetchone()
        if row:
            try:
                pt = self.crypto.decrypt(row[0]).decode('utf-8')
                self.editor.delete("0.0", "end"); self.editor.insert("0.0", pt); self._update_buttons(True)
            except: messagebox.showerror("Error", "Decryption Failed.")

    def _save_entry(self):
        content = self.editor.get("0.0", "end").strip()
        if not content: return
        enc = self.crypto.encrypt(content.encode()); ts = datetime.datetime.now().isoformat()
        if self.current_entry_id: self.db_conn.execute("UPDATE entries SET content=?, timestamp=? WHERE id=?", (enc, ts, self.current_entry_id))
        else: self.db_conn.execute("INSERT INTO entries (timestamp, content) VALUES (?,?)", (ts, enc))
        self.db_conn.commit(); self._reset_editor(); self._refresh_timeline()

    def _delete_entry(self):
        if self.current_entry_id and messagebox.askyesno("Confirm", "Delete this entry?"):
            self.db_conn.execute("DELETE FROM entries WHERE id=?", (self.current_entry_id,)); self.db_conn.commit(); self._reset_editor(); self._refresh_timeline()

    def _reset_editor(self):
        self.current_entry_id = None; self.editor.delete("0.0", "end"); self.editor.grid(); self.lbl_welcome.grid_remove(); self.editor.focus(); self._update_buttons(False)
    def _update_buttons(self, state):
        self.btn_save.configure(state="normal" if state else "disabled")
        self.btn_del.configure(state="normal" if self.current_entry_id else "disabled")
    def _on_text_change(self, e): self.btn_save.configure(state="normal" if len(self.editor.get("0.0", "end").strip()) > 0 else "disabled")
    def get_history_text(self): return self.editor.get("0.0", "end").strip()

    def _scan_document(self):
        if not OCR_AVAILABLE: return messagebox.showerror("Error", "Pillow/pytesseract libraries not found.")
        path = filedialog.askopenfilename(filetypes=[("Images", "*.png;*.jpg;*.jpeg")])
        if path:
            try:
                text = pytesseract.image_to_string(Image.open(path))
                self.editor.insert("end", f"\n[Scan]\n{text}"); messagebox.showinfo("Scan", "Success")
            except Exception as e: messagebox.showerror("OCR Error", str(e))

    def _load_plugins(self):
        if not os.path.exists(PATHS["PLUGINS"]): os.makedirs(PATHS["PLUGINS"])
        for f in os.listdir(PATHS["PLUGINS"]):
            if f.endswith(".py"):
                try:
                    spec = importlib.util.spec_from_file_location(f[:-3], os.path.join(PATHS["PLUGINS"], f))
                    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.register(self)
                except Exception as e: print(f"Plugin Error {f}: {e}")

    # --- Backup & Settings ---
    def _perform_auto_backup(self):
        try:
            if not os.path.exists(PATHS["BACKUPS"]): os.makedirs(PATHS["BACKUPS"])
            backup_path = os.path.join(PATHS["BACKUPS"], f"AutoBackup_{datetime.datetime.now().strftime('%Y%m%d')}.bak")
            with open(PATHS["AUTH"], "r") as f: secret = f.read().strip()
            self._encrypt_backup(backup_path, secret)
        except: pass

    def _open_settings(self):
        s = ctk.CTkToplevel(self); s.title("Settings"); s.geometry("300x200"); s.grab_set()
        ctk.CTkButton(s, text="Manual Backup", command=self._manual_backup).pack(pady=20)
        ctk.CTkButton(s, text="Factory Reset", fg_color="red", command=self._reset_all).pack(pady=10)

    def _manual_backup(self):
        path = filedialog.asksaveasfilename(defaultextension=".bak")
        pwd = LoginDialog(self, "Backup Password", is_setup=True).get_input()
        if path and pwd:
            try: self._encrypt_backup(path, pwd); messagebox.showinfo("Success", "Backup Saved")
            except Exception as e: messagebox.showerror("Error", str(e))

    def _encrypt_backup(self, path, pwd):
        shutil.copyfile(PATHS["DB"], "temp.db")
        with zipfile.ZipFile("temp.zip","w") as z: z.write("temp.db"); z.write(PATHS["AUTH"])
        with open("temp.zip","rb") as f: data = f.read()
        salt, nonce = os.urandom(16), os.urandom(12)
        key = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600000, default_backend()).derive(pwd.encode())
        with open(path, "wb") as f: f.write(salt + nonce + AESGCM(key).encrypt(nonce, data, None))
        os.remove("temp.db"); os.remove("temp.zip")

    def _reset_all(self):
        if messagebox.askyesno("Reset", "Delete ALL data?"):
            self.db_conn.close()
            if os.path.exists(PATHS["DB"]): os.remove(PATHS["DB"])
            if os.path.exists(PATHS["AUTH"]): os.remove(PATHS["AUTH"])
            sys.exit()

    def _reset_idle_timer(self, e=None):
        if self.idle_job: self.after_cancel(self.idle_job)
        self.idle_job = self.after(CONSTANTS["AUTO_LOCK_MS"], self._lock_screen)

    def _lock_screen(self):
        self.withdraw(); self.crypto.lock()
        while True:
            p = LoginDialog(self, "Locked").get_input()
            if not p: sys.exit()
            if self.crypto.verify_password(p): self.deiconify(); self._reset_idle_timer(); break
    
    def _on_close(self): 
        if self.db_conn: self.db_conn.close()
        self.destroy()

# =============================================================================
# HELPER
# =============================================================================
class LoginDialog(ctk.CTkToplevel):
    def __init__(self, parent, title, is_setup=False):
        super().__init__(parent); self.val=None; self.title(title); self.geometry("300x150")
        try: self.geometry(f"+{parent.winfo_x()+100}+{parent.winfo_y()+100}")
        except: pass
        self.resizable(False, False); self.transient(parent); self.grab_set()
        ctk.CTkLabel(self, text="Enter Master Password" if not is_setup else "Create Password").pack(pady=15)
        self.e = ctk.CTkEntry(self, show="*"); self.e.pack(); self.e.focus(); self.e.bind("<Return>", self.ok)
        ctk.CTkButton(self, text="OK", command=self.ok, width=100).pack(pady=15)
        self.protocol("WM_DELETE_WINDOW", self.cancel)
    def ok(self,e=None): self.val=self.e.get(); self.destroy()
    def cancel(self): self.val=None; self.destroy()
    def get_input(self): self.master.wait_window(self); return self.val

# =============================================================================
# BOOTSTRAP (THREAD SAFE)
# =============================================================================
if __name__ == "__main__":
    # 1. Setup & Auth
    root = ctk.CTk(); root.withdraw()
    engine = CryptoEngine()
    
    if not os.path.exists(PATHS["AUTH"]):
        p = LoginDialog(root, "Setup", True).get_input()
        if p: engine.setup_new_password(p)
        else: sys.exit()
    else:
        valid = False
        for _ in range(3):
            if engine.verify_password(LoginDialog(root, "Login").get_input()): valid=True; break
        if not valid: sys.exit()

    # 2. Loading Splash
    config = ConfigManager()
    splash = ctk.CTkToplevel()
    splash.overrideredirect(True)
    splash.geometry(f"350x120+{root.winfo_screenwidth()//2-175}+{root.winfo_screenheight()//2-60}")
    
    ctk.CTkLabel(splash, text="Secure Diary Architect", font=("", 16, "bold")).pack(pady=15)
    lbl_stat = ctk.CTkLabel(splash, text="Loading Neural Network..."); lbl_stat.pack()

    bot_engine = LocalLLM()

    def load_thread():
        # Heavy loading in background
        bot_engine.load_model()
        # Signal main thread to start
        splash.after(500, start_main_app)

    def start_main_app():
        splash.destroy()
        root.destroy() # destroy dummy root, create real app
        
        # Main GUI requires its own loop, but since we used 'root' for dialogs
        # we can now launch the real app object
        real_app = SecureDiaryApp(engine, bot_engine, config)
        real_app.mainloop()

    threading.Thread(target=load_thread).start()
    root.mainloop()