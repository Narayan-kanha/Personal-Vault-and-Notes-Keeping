import os
# --- Optimizations & Warning Suppression ---
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TOKENIZERS_PARALLELISM'] = 'false' 

import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox, filedialog
import shutil
import datetime
import threading
import sqlite3
import json
import importlib.util
import zipfile

# --- AI Imports ---
try:
    from transformers import AutoModelForCausalLM, AutoTokenizer
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    print("AI Warning: Install 'transformers' and 'torch' for AI features.")

# --- Cryptography Imports ---
try:
    from argon2 import PasswordHasher, exceptions as argon_exc
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
except ImportError:
    messagebox.showerror("Critical Error", "Crypto libraries missing.\nPlease install: pip install argon2-cffi cryptography")
    exit()

# --- Configuration ---
DB_FILE = "diary.db"
AUTH_FILE = "user.auth"
PLUGINS_DIR = "plugins"
THEMES_DIR = "themes"
AUTO_LOCK_TIME_MS = 300000  # 5 Minutes
MODEL_ID = "Qwen/Qwen2.5-1.5B-Instruct" 
APP_TITLE = "Secure Diary (Architect Edition)"

# =============================================================================
# CORE ENGINE: CRYPTOGRAPHY
# =============================================================================
class CryptoEngine:
    def __init__(self):
        self.backend = default_backend()
        self.master_key = None
        self.hasher = PasswordHasher()
        
    def setup_new_password(self, p):
        """Hash pass to disk and derive session key."""
        hp = self.hasher.hash(p.encode())
        with open(AUTH_FILE, "w") as f: f.write(hp)
        self._derive_master_key(p)

    def verify_password(self, p):
        try:
            with open(AUTH_FILE, "r") as f: h = f.read()
            self.hasher.verify(h, p.encode())
            if self.hasher.check_needs_rehash(h): self.setup_new_password(p)
            self._derive_master_key(p)
            return True
        except: return False

    def _derive_master_key(self, p):
        self.master_key = HKDF(hashes.SHA256(),32,None,b's-d-v7-final',self.backend).derive(p.encode())

    def encrypt(self, b):
        if not self.master_key: raise ValueError("Locked")
        ek, en, mn = os.urandom(32), os.urandom(12), os.urandom(12)
        # Double encryption layer: Key Wrap + Content Enc
        ct = AESGCM(ek).encrypt(en, b, None)
        wk = AESGCM(self.master_key).encrypt(mn, ek, None)
        return mn + wk + en + ct

    def decrypt(self, b):
        if not self.master_key: raise ValueError("Locked")
        mn, wk, en, ct = b[:12], b[12:60], b[60:72], b[72:]
        ek = AESGCM(self.master_key).decrypt(mn, wk, None)
        return AESGCM(ek).decrypt(en, ct, None)

    def lock(self): self.master_key = None

# =============================================================================
# AI ENGINE (Local Qwen 1.5B)
# =============================================================================
class LocalLLM:
    def __init__(self):
        self.model = None; self.tokenizer = None
        
    def load_model(self):
        if TRANSFORMERS_AVAILABLE:
            try:
                # CPU-friendly FP32 load
                self.tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
                self.model = AutoModelForCausalLM.from_pretrained(
                    MODEL_ID, torch_dtype=torch.float32, device_map="cpu"
                )
            except Exception as e:
                print(f"AI Load Error: {e}"); self.model = None

    def is_ready(self): return self.model is not None

    def generate(self, prompt, max_new_tokens=100):
        if not self.model: return "Model not loaded."
        try:
            inputs = self.tokenizer([prompt], return_tensors="pt").to(self.model.device)
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs, max_new_tokens=max_new_tokens, temperature=0.7, do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            full_text = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            # Strip input prompt from output for cleaner UI
            if full_text.startswith(prompt): return full_text[len(prompt):].strip()
            return full_text.strip()
        except Exception as e: return f"Error: {e}"

# =============================================================================
# UI HELPERS
# =============================================================================
class PasswordDialog(ctk.CTkToplevel):
    def __init__(self, parent, title="Password", text_label="Enter pass:"):
        super().__init__(parent); self.result_str=None; self._setup_window(parent, title); self._create_widgets(text_label)
    
    def _setup_window(self, parent, title):
        self.withdraw(); self.transient(parent); self.title(title); self.resizable(False, False); self.geometry("350x160")
        self.grid_columnconfigure(0, weight=1); self.protocol("WM_DELETE_WINDOW", self._on_cancel); parent.update_idletasks()
        try: x, y = parent.winfo_x()+(parent.winfo_width()//2)-175, parent.winfo_y()+(parent.winfo_height()//2)-80
        except: x,y = 100,100
        self.geometry(f"+{x}+{y}"); self.deiconify(); self.grab_set()

    def _create_widgets(self, text_label):
        ctk.CTkLabel(self, text=text_label).grid(row=0, column=0, padx=20, pady=(20, 5))
        self.entry=ctk.CTkEntry(self, show="*"); self.entry.grid(row=1, column=0, padx=20, pady=5, sticky="ew")
        self.entry.focus(); self.entry.bind("<Return>", self._on_ok)
        ctk.CTkButton(self, text="OK", command=self._on_ok).grid(row=2, column=0, padx=20, pady=(10, 20))

    def _on_ok(self, e=None): self.result_str=self.entry.get(); self.grab_release(); self.destroy()
    def _on_cancel(self): self.result_str=None; self.grab_release(); self.destroy()
    def get_input(self): self.master.wait_window(self); return self.result_str

# =============================================================================
# MAIN APPLICATION
# =============================================================================
class SecureDiaryApp(ctk.CTk):
    def __init__(self, crypto: CryptoEngine, bot: LocalLLM):
        super().__init__()
        self.crypto = crypto; self.bot = bot
        self.db_conn = None; self.inactivity_timer_id = None; self.current_entry_id = None
        
        self.title(APP_TITLE); self.geometry("1200x768"); self.minsize(900, 600)
        self._connect_db(); self._create_db_tables()
        self._load_ui_setup()
        self._load_plugins()
        self._reset_inactivity_timer()
        
        self.bind_all("<Key>", self._reset_inactivity_timer); self.bind_all("<Motion>", self._reset_inactivity_timer)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _connect_db(self): 
        if self.db_conn is None: self.db_conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    
    def _create_db_tables(self): 
        self.db_conn.execute("CREATE TABLE IF NOT EXISTS entries(id INTEGER PRIMARY KEY, timestamp TEXT, content BLOB)")

    def _load_ui_setup(self):
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=3) # Main editor
        self.grid_columnconfigure(2, weight=0) # Plugin sidebar (collapsed initially)

        self._create_menubar()
        
        # 1. Sidebar (Timeline)
        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar.grid_rowconfigure(1, weight=1); self.sidebar.grid_columnconfigure(0, weight=1)
        
        ctk.CTkLabel(self.sidebar, text="Timeline", font=("", 20, "bold")).grid(row=0, column=0, padx=20, pady=(20, 10))
        self.timeline_scroll = ctk.CTkScrollableFrame(self.sidebar, label_text=""); self.timeline_scroll.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        ctk.CTkButton(self.sidebar, text="+ New Entry", command=self._reset_to_new).grid(row=2, column=0, padx=20, pady=10)

        # 2. Main Editor
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        self.main_frame.grid_rowconfigure(0, weight=1); self.main_frame.grid_columnconfigure(0, weight=1)
        
        self.text_area = ctk.CTkTextbox(self.main_frame, font=("Georgia", 16), wrap="word", undo=True)
        self.text_area.grid(row=0, column=0, sticky="nsew")
        self.text_area.bind("<KeyRelease>", self._check_state)
        
        self.lbl_welcome = ctk.CTkLabel(self.main_frame, text="Private. Encrypted.\nSelect an entry to begin.", font=("", 18), text_color="gray50")

        # 3. Action Bar
        self.action_bar = ctk.CTkFrame(self, height=50, corner_radius=0)
        self.action_bar.grid(row=1, column=1, padx=10, pady=(0, 10), sticky="ew")
        
        self.btn_delete = ctk.CTkButton(self.action_bar, text="Delete", command=self._delete_entry, fg_color="#D32F2F", hover_color="#B71C1C")
        self.btn_delete.pack(side="left", padx=10, pady=10)
        
        self.btn_settings = ctk.CTkButton(self.action_bar, text="Settings ⚙️", command=self._open_settings, fg_color="transparent", border_width=1, text_color=("gray10", "gray90"))
        self.btn_settings.pack(side="right", padx=10, pady=10)

        self.btn_save = ctk.CTkButton(self.action_bar, text="Save Entry", command=self._save_entry)
        self.btn_save.pack(side="right", padx=10, pady=10)

        # Load defaults
        self._refresh_timeline()
        ctk.set_appearance_mode("dark"); ctk.set_default_color_theme("blue")

    def _create_menubar(self):
        self.menubar=tk.Menu(self); self.configure(menu=self.menubar)
        # Note: macOS/Standard menus won't render correctly inside ctk but useful for hotkeys later
        self.plugins_menu=tk.Menu(self.menubar, tearoff=0) 

    # --- Entry Management ---
    def _refresh_timeline(self):
        for w in self.timeline_scroll.winfo_children(): w.destroy()
        rows = self.db_conn.execute("SELECT id, timestamp FROM entries ORDER BY timestamp DESC").fetchall()
        
        if not rows:
            self.lbl_welcome.grid(row=0, column=0); self.text_area.grid_remove(); self._check_state(); return
            
        self.lbl_welcome.grid_remove(); self.text_area.grid()
        grouped = {}
        for pid, ts in rows:
            d = datetime.datetime.fromisoformat(ts).strftime("%A, %B %d, %Y")
            grouped.setdefault(d, []).append((pid, datetime.datetime.fromisoformat(ts).strftime("%I:%M %p")))
            
        for d, items in grouped.items():
            ctk.CTkLabel(self.timeline_scroll, text=d, font=("",14,"bold"), anchor="w").pack(fill="x", padx=5, pady=10)
            for pid, t in items:
                ctk.CTkButton(self.timeline_scroll, text=f"  {t}", anchor="w", fg_color="transparent", 
                            command=lambda i=pid:self._load_entry(i)).pack(fill="x", pady=1)

    def _load_entry(self, eid):
        self.current_entry_id = eid
        row = self.db_conn.execute("SELECT content FROM entries WHERE id=?", (eid,)).fetchone()
        if row:
            try:
                pt = self.crypto.decrypt(row[0]).decode('utf-8')
                self.text_area.delete("1.0", "end"); self.text_area.insert("1.0", pt)
            except: messagebox.showerror("Error", "Decryption failed.")
        self._check_state()

    def _save_entry(self):
        c = self.text_area.get("1.0", "end-1c").strip()
        if not c: return
        try:
            enc = self.crypto.encrypt(c.encode('utf-8'))
            ts = datetime.datetime.now().isoformat()
            if self.current_entry_id: 
                self.db_conn.execute("UPDATE entries SET content=?, timestamp=? WHERE id=?", (enc, ts, self.current_entry_id))
            else: 
                self.db_conn.execute("INSERT INTO entries (timestamp, content) VALUES (?,?)", (ts, enc))
            self.db_conn.commit(); self._reset_to_new(); self._refresh_timeline()
        except Exception as e: messagebox.showerror("Save Error", str(e))

    def _delete_entry(self):
        if self.current_entry_id and messagebox.askyesno("Confirm", "Delete this entry?"):
            self.db_conn.execute("DELETE FROM entries WHERE id=?", (self.current_entry_id,)); self.db_conn.commit()
            self._reset_to_new(); self._refresh_timeline()

    def _reset_to_new(self):
        self.current_entry_id = None; self.text_area.delete("1.0", "end")
        self.lbl_welcome.grid_remove(); self.text_area.grid()
        self._check_state(); self.text_area.focus()

    def _check_state(self, e=None):
        has_text = bool(self.text_area.get("1.0", "end-1c").strip())
        self.btn_save.configure(state="normal" if has_text else "disabled")
        self.btn_delete.configure(state="normal" if self.current_entry_id else "disabled")

    # --- Plugin API (For AI Companion) ---
    def get_entry_history(self, limit=3):
        if not self.crypto.master_key: return []
        try:
            q = "SELECT content FROM entries WHERE id != ? ORDER BY timestamp DESC LIMIT ?" if self.current_entry_id else "SELECT content FROM entries ORDER BY timestamp DESC LIMIT ?"
            args = (self.current_entry_id, limit) if self.current_entry_id else (limit,)
            rows = self.db_conn.execute(q, args).fetchall()
            return [self.crypto.decrypt(r[0]).decode('utf-8') for r in rows if self.crypto.master_key]
        except: return []

    def _load_plugins(self):
        if not os.path.exists(PLUGINS_DIR): os.makedirs(PLUGINS_DIR)
        for f in os.listdir(PLUGINS_DIR):
            if f.endswith('.py') and not f.startswith('__'):
                try:
                    spec = importlib.util.spec_from_file_location(f[:-3], os.path.join(PLUGINS_DIR, f))
                    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
                    if hasattr(mod, 'register'): mod.register(self)
                except Exception as e: print(f"Plugin error: {e}")

    # --- Settings Panel & Features ---
    def _open_settings(self):
        sw = ctk.CTkToplevel(self); sw.title("Settings"); sw.geometry("500x650")
        sw.transient(self); sw.grab_set(); sw.grid_columnconfigure(0, weight=1)
        
        # Header
        ctk.CTkLabel(sw, text="Settings", font=("", 20, "bold")).pack(pady=(20, 10))
        
        # 1. Appearance
        frame_app = ctk.CTkFrame(sw); frame_app.pack(padx=20, pady=10, fill="x")
        ctk.CTkLabel(frame_app, text="Appearance", font=("", 14, "bold")).pack(anchor="w", padx=10, pady=5)
        
        ctk.CTkOptionMenu(frame_app, values=["Dark", "Light", "System"], 
                         command=ctk.set_appearance_mode).pack(fill="x", padx=10, pady=5)
        ctk.CTkOptionMenu(frame_app, values=["blue", "green", "dark-blue"], 
                         command=ctk.set_default_color_theme).pack(fill="x", padx=10, pady=(5, 10))

        # 2. Data Management
        frame_data = ctk.CTkFrame(sw); frame_data.pack(padx=20, pady=10, fill="x")
        ctk.CTkLabel(frame_data, text="Data Backup", font=("", 14, "bold")).pack(anchor="w", padx=10, pady=5)
        
        ctk.CTkButton(frame_data, text="Export Encrypted Backup (.bak)", command=self._export_backup).pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(frame_data, text="Import Backup", command=self._import_backup).pack(fill="x", padx=10, pady=(5, 10))

        # 3. Security
        frame_sec = ctk.CTkFrame(sw); frame_sec.pack(padx=20, pady=10, fill="x")
        ctk.CTkLabel(frame_sec, text="Security Zone", font=("", 14, "bold"), text_color="#FF5555").pack(anchor="w", padx=10, pady=5)
        
        ctk.CTkButton(frame_sec, text="Change Master Password", command=self._change_password).pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(frame_sec, text="Factory Reset (Delete All Data)", command=self._factory_reset, 
                      fg_color="#D32F2F", hover_color="#B71C1C").pack(fill="x", padx=10, pady=(20, 10))
        
        ctk.CTkLabel(sw, text=f"v7.0 | {MODEL_ID.split('/')[1]}", text_color="gray").pack(side="bottom", pady=10)

    def _change_password(self):
        if not messagebox.askyesno("Security", "Changing the password requires re-encrypting the entire database.\nThis may take a moment.\nProceed?"): return
        
        new_pass = PasswordDialog(self, title="New Password", text_label="Enter NEW Master Password:").get_input()
        if not new_pass: return
        
        confirm = PasswordDialog(self, title="Confirm", text_label="Confirm NEW Password:").get_input()
        if new_pass != confirm: messagebox.showerror("Error", "Passwords do not match."); return

        try:
            # 1. Create new crypto instance for the new key
            new_crypto = CryptoEngine()
            new_crypto.setup_new_password(new_pass)
            
            # 2. Re-encrypt Data
            cur = self.db_conn.cursor()
            all_rows = cur.execute("SELECT id, content FROM entries").fetchall()
            
            for eid, blob in all_rows:
                # Decrypt with OLD key (self.crypto) -> Encrypt with NEW key
                plain = self.crypto.decrypt(blob)
                new_blob = new_crypto.encrypt(plain)
                cur.execute("UPDATE entries SET content=? WHERE id=?", (new_blob, eid))
            
            self.db_conn.commit()
            
            # 3. Swap Engines
            self.crypto = new_crypto
            messagebox.showinfo("Success", "Password changed and database re-encrypted.")
        except Exception as e:
            messagebox.showerror("Critical Error", f"Re-encryption failed: {e}\nRestoring old state recommended.")

    def _export_backup(self):
        path = filedialog.asksaveasfilename(defaultextension=".bak", filetypes=[("Backup", "*.bak")])
        if not path: return
        pwd = PasswordDialog(self, title="Backup", text_label="Create Backup Password:").get_input()
        if not pwd: return
        
        try:
            # Copy DB to temp
            shutil.copyfile(DB_FILE, "temp.db")
            # Zip DB + Auth
            with zipfile.ZipFile("pack.zip", 'w') as zf:
                zf.write("temp.db"); zf.write(AUTH_FILE)
            # Read Zip Bytes
            with open("pack.zip", 'rb') as f: raw_data = f.read()
            
            # Encrypt the entire zip file
            salt = os.urandom(16); nonce = os.urandom(12)
            kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600000, self.crypto.backend)
            key = kdf.derive(pwd.encode())
            enc_bytes = salt + nonce + AESGCM(key).encrypt(nonce, raw_data, None)
            
            with open(path, 'wb') as f: f.write(enc_bytes)
            messagebox.showinfo("Backup", "Export Successful.")
        except Exception as e: messagebox.showerror("Error", str(e))
        finally: 
            for f in ["temp.db", "pack.zip"]: 
                if os.path.exists(f): os.remove(f)

    def _import_backup(self):
        if not messagebox.askyesno("Warning", "This will ERASE your current diary and replace it with the backup.\nContinue?"): return
        path = filedialog.askopenfilename(filetypes=[("Backup", "*.bak")])
        if not path: return
        pwd = PasswordDialog(self, title="Import", text_label="Enter Backup Password:").get_input()
        if not pwd: return
        
        try:
            with open(path, 'rb') as f: data = f.read()
            salt, nonce, ct = data[:16], data[16:28], data[28:]
            
            kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600000, self.crypto.backend)
            key = kdf.derive(pwd.encode())
            zip_data = AESGCM(key).decrypt(nonce, ct, None)
            
            # Success - Nuke old DB setup
            self.db_conn.close()
            if os.path.exists(DB_FILE): os.remove(DB_FILE)
            if os.path.exists(AUTH_FILE): os.remove(AUTH_FILE)
            
            with open("pack.zip", "wb") as f: f.write(zip_data)
            with zipfile.ZipFile("pack.zip", "r") as zf:
                if "temp.db" in zf.namelist(): 
                    zf.extract("temp.db"); os.rename("temp.db", DB_FILE)
                if AUTH_FILE in zf.namelist(): zf.extract(AUTH_FILE)
            
            messagebox.showinfo("Restart", "Import successful. The app will now close.\nPlease restart and log in.")
            self.destroy()
        except Exception as e: 
            messagebox.showerror("Error", f"Import failed (Wrong password?): {e}")
            self._connect_db() # Reconnect if failed
        finally:
             if os.path.exists("pack.zip"): os.remove("pack.zip")

    def _factory_reset(self):
        if not messagebox.askyesno("NUCLEAR OPTION", "Delete ALL diaries? Passwords? Keys?\nThis cannot be undone."): return
        pass_chk = PasswordDialog(self, title="Verification", text_label="Enter Master Password to CONFIRM DELETION:").get_input()
        if pass_chk and self.crypto.verify_password(pass_chk):
            self.db_conn.close()
            try:
                if os.path.exists(DB_FILE): os.remove(DB_FILE)
                if os.path.exists(AUTH_FILE): os.remove(AUTH_FILE)
                messagebox.showinfo("Reset", "App reset completely. Closing."); self.destroy()
            except Exception as e: messagebox.showerror("Error", str(e))
        else:
            messagebox.showwarning("Aborted", "Incorrect password. Reset aborted.")

    # --- Core Flow ---
    def _reset_inactivity_timer(self, event=None):
        if self.inactivity_timer_id: self.after_cancel(self.inactivity_timer_id)
        self.inactivity_timer_id = self.after(AUTO_LOCK_TIME_MS, self._lock_app)
    
    def _lock_app(self):
        self.withdraw(); self.crypto.lock()
        if handle_login_flow(self, self.crypto, lock_mode=True): self.deiconify(); self._reset_inactivity_timer()
        else: self.destroy()

    def _on_close(self):
        if self.db_conn: self.db_conn.close()
        self.destroy()

# =============================================================================
# STARTUP & AUTH
# =============================================================================
def handle_login_flow(root, crypto, lock_mode=False):
    for i in range(3):
        pwd = PasswordDialog(root, title="Login", text_label="Unlock:" if lock_mode else f"Master Pass (Try {i+1}/3):").get_input()
        if pwd is None: return False
        if crypto.verify_password(pwd): return True
        messagebox.showwarning("Failed", "Incorrect Password")
    return False

def first_time_setup(root, crypto):
    while True:
        p1 = PasswordDialog(root, title="Setup", text_label="Create Master Password (Save this!):").get_input()
        if not p1: return False
        p2 = PasswordDialog(root, title="Confirm", text_label="Confirm Password:").get_input()
        if p1 == p2: crypto.setup_new_password(p1); return True
        messagebox.showerror("Error", "Passwords did not match.")

if __name__ == "__main__":
    # 1. Auth Phase
    root = ctk.CTk(); root.withdraw()
    engine = CryptoEngine()
    if not os.path.exists(AUTH_FILE):
        if not first_time_setup(root, engine): exit()
    else:
        if not handle_login_flow(root, engine): exit()
    root.destroy()

    # 2. Loading Phase
    splash = ctk.CTk(); splash.overrideredirect(True)
    ws, hs = splash.winfo_screenwidth(), splash.winfo_screenheight()
    splash.geometry(f"400x150+{ws//2-200}+{hs//2-75}")
    ctk.CTkLabel(splash, text="Initialize AI Engine...", font=("", 16, "bold")).pack(pady=40)
    
    bot_engine = LocalLLM()
    def loader(): 
        bot_engine.load_model()
        splash.after(500, splash.destroy)
    
    threading.Thread(target=loader, daemon=True).start()
    splash.mainloop()

    # 3. App Phase
    app = SecureDiaryApp(engine, bot_engine)
    app.mainloop()