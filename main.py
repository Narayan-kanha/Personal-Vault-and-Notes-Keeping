import os
# --- Suppress TF/AI Warnings before imports ---
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

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

# --- Optional AI Imports ---
try:
    from transformers import pipeline
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    print("AI Warning: 'transformers' or 'torch' not found. AI features disabled.")

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
MODEL_NAME = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
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
        hp = self.hasher.hash(p.encode())
        with open(AUTH_FILE, "w") as f:
            f.write(hp)
        self._derive_master_key(p)

    def verify_password(self, p):
        try:
            with open(AUTH_FILE, "r") as f:
                h = f.read()
            self.hasher.verify(h, p.encode())
            if self.hasher.check_needs_rehash(h):
                self.setup_new_password(p)
            self._derive_master_key(p)
            return True
        except (argon_exc.VerifyMismatchError, FileNotFoundError, Exception):
            return False

    def _derive_master_key(self, p):
        self.master_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b's-d-v7-final',
            backend=self.backend
        ).derive(p.encode())

    def encrypt(self, b):
        if not self.master_key:
            raise ValueError("Vault is locked")
        ek = os.urandom(32)
        en = os.urandom(12)
        mn = os.urandom(12)
        
        ct = AESGCM(ek).encrypt(en, b, None)
        wk = AESGCM(self.master_key).encrypt(mn, ek, None)
        
        return mn + wk + en + ct

    def decrypt(self, b):
        if not self.master_key:
            raise ValueError("Vault is locked")
        
        mn, wk, en, ct = b[:12], b[12:60], b[60:72], b[72:]
        ek = AESGCM(self.master_key).decrypt(mn, wk, None)
        return AESGCM(ek).decrypt(en, ct, None)

    def lock(self):
        self.master_key = None

# =============================================================================
# AI ENGINE
# =============================================================================
class HuggingFaceBot:
    def __init__(self):
        self.generator = None
        
    def load_model(self):
        if TRANSFORMERS_AVAILABLE:
            try:
                self.generator = pipeline('text-generation', model=MODEL_NAME, torch_dtype=torch.float32, device_map="auto")
            except Exception as e:
                print(f"AI Load Failed: {e}")
                self.generator = None

    def is_ready(self):
        return self.generator is not None

# =============================================================================
# UI COMPONENTS
# =============================================================================
class PasswordDialog(ctk.CTkToplevel):
    def __init__(self, parent, title="Password", text_label="Enter pass:"):
        super().__init__(parent)
        self.result_str = None
        self._setup_window(parent, title)
        self._create_widgets(text_label)

    def _setup_window(self, parent, title):
        self.withdraw()
        self.transient(parent)
        self.title(title)
        self.resizable(False, False)
        self.geometry("350x160")
        
        # FIX: Must specify 'weight=' explicitly to avoid int len() error
        self.grid_columnconfigure(0, weight=1) 
        
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        
        parent.update_idletasks()
        # Robust centering
        try:
            x = parent.winfo_x() + (parent.winfo_width() // 2) - 175
            y = parent.winfo_y() + (parent.winfo_height() // 2) - 80
        except:
            x, y = 100, 100
        self.geometry(f"+{x}+{y}")
        self.deiconify()
        self.grab_set()

    def _create_widgets(self, text_label):
        ctk.CTkLabel(self, text=text_label).grid(row=0, column=0, padx=20, pady=(20, 5))
        self.entry = ctk.CTkEntry(self, show="*")
        self.entry.grid(row=1, column=0, padx=20, pady=5, sticky="ew")
        self.entry.focus()
        self.entry.bind("<Return>", self._on_ok)
        ctk.CTkButton(self, text="OK", command=self._on_ok).grid(row=2, column=0, padx=20, pady=(10, 20))

    def _on_ok(self, event=None):
        self.result_str = self.entry.get()
        self.grab_release()
        self.destroy()

    def _on_cancel(self):
        self.result_str = None
        self.grab_release()
        self.destroy()

    def get_input(self):
        self.master.wait_window(self)
        return self.result_str

# =============================================================================
# MAIN APPLICATION
# =============================================================================
class SecureDiaryApp(ctk.CTk):
    def __init__(self, crypto: CryptoEngine, bot: HuggingFaceBot):
        super().__init__()
        self.crypto = crypto
        self.bot = bot
        self.db_conn = None
        self.inactivity_timer_id = None
        self.current_entry_id = None
        self.themes = {}

        self.title(APP_TITLE)
        self.geometry("1024x768")
        self.minsize(800, 600)
        
        self._connect_db()
        self._create_db_tables()
        self._load_and_apply_themes()
        
        self._setup_ui()
        self._load_plugins()
        self._reset_inactivity_timer()
        
        self.bind_all("<Key>", self._reset_inactivity_timer)
        self.bind_all("<Motion>", self._reset_inactivity_timer)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _connect_db(self):
        if self.db_conn is None:
            self.db_conn = sqlite3.connect(DB_FILE)

    def _create_db_tables(self):
        cur = self.db_conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS entries(id INTEGER PRIMARY KEY, timestamp TEXT, content BLOB)")
        self.db_conn.commit()

    def _load_and_apply_themes(self):
        self.themes = {"Default Dark": {"appearance_mode": "dark", "color_theme": "blue", "app_bg": "#2B2B2B"}}
        if os.path.exists(THEMES_DIR):
            for f in os.listdir(THEMES_DIR):
                if f.endswith(".json"):
                    try:
                        name = f.replace(".json", "").replace("_", " ").title()
                        with open(os.path.join(THEMES_DIR, f), 'r') as file:
                            self.themes[name] = json.load(file)
                    except:
                        pass
        self._apply_theme(self.themes.get("Default Dark"))

    def _apply_theme(self, theme):
        ctk.set_appearance_mode(theme.get("appearance_mode", "dark"))
        ctk.set_default_color_theme(theme.get("color_theme", "blue"))
        if "app_bg" in theme:
             self.configure(fg_color=theme["app_bg"])

    def _setup_ui(self):
        # FIX: Specify weight=1 explicitely for newer Tkinter/CTK versions
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self._create_menubar()
        
        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar.grid_rowconfigure(1, weight=1)
        self.sidebar.grid_columnconfigure(0, weight=1)
        
        ctk.CTkLabel(self.sidebar, text="Timeline", font=("", 20, "bold")).grid(row=0, column=0, padx=20, pady=(20, 10))
        
        self.timeline_scroll = ctk.CTkScrollableFrame(self.sidebar, label_text="")
        self.timeline_scroll.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        
        ctk.CTkButton(self.sidebar, text="+ New Entry", command=self._reset_to_new).grid(row=2, column=0, padx=20, pady=10)
        
        # Main Area
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)
        
        # FIX: Renamed to self.text_area to match Plugin contract
        self.text_area = ctk.CTkTextbox(self.main_frame, font=("", 16), wrap="word")
        self.text_area.grid(row=0, column=0, sticky="nsew")
        self.text_area.bind("<KeyRelease>", self._check_state)
        
        self.lbl_welcome = ctk.CTkLabel(self.main_frame, text="Welcome!", font=("", 18), text_color="gray50")
        
        self.action_bar = ctk.CTkFrame(self, height=50, corner_radius=0)
        self.action_bar.grid(row=1, column=1, padx=10, pady=(0, 10), sticky="ew")
        
        self.btn_delete = ctk.CTkButton(self.action_bar, text="Delete Entry", command=self._delete_entry, 
                                      fg_color="#D32F2F", hover_color="#B71C1C")
        self.btn_delete.pack(side="left", padx=10, pady=10)
        
        self.btn_ai = ctk.CTkButton(self.action_bar, text="Analyze ✨", command=self._ai_analysis)
        self.btn_ai.pack(side="right", padx=10, pady=10)
        
        self.btn_save = ctk.CTkButton(self.action_bar, text="Save Entry", command=self._save_entry)
        self.btn_save.pack(side="right", padx=10, pady=10)
        
        self._refresh_timeline()

    def _create_menubar(self):
        self.menubar = tk.Menu(self)
        self.configure(menu=self.menubar)
        
        self.settings_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="File", menu=self.settings_menu)
        self.settings_menu.add_command(label="Settings...", command=self._open_settings)
        self.settings_menu.add_separator()
        self.settings_menu.add_command(label="Exit", command=self._on_close)
        
        self.plugins_menu = tk.Menu(self.menubar, tearoff=0) 
        # Will be added to menubar if plugins are found

    def _refresh_timeline(self):
        for w in self.timeline_scroll.winfo_children():
            w.destroy()
        
        cur = self.db_conn.cursor()
        cur.execute("SELECT id, timestamp FROM entries ORDER BY timestamp DESC")
        rows = cur.fetchall()
        
        if not rows:
            self.lbl_welcome.grid(row=0, column=0)
            self.text_area.grid_remove() # FIX: updated variable name
            self._check_state()
            return
            
        self.lbl_welcome.grid_remove()
        self.text_area.grid() # FIX: updated variable name
        
        grouped = {}
        for pid, ts in rows:
            dt_obj = datetime.datetime.fromisoformat(ts)
            date_key = dt_obj.strftime("%A, %B %d, %Y")
            time_str = dt_obj.strftime("%I:%M %p")
            if date_key not in grouped:
                grouped[date_key] = []
            grouped[date_key].append((pid, time_str))
            
        for date_str, items in grouped.items():
            ctk.CTkLabel(self.timeline_scroll, text=date_str, font=("", 14, "bold"), anchor="w").pack(fill="x", padx=5, pady=(10, 5))
            for pid, time_val in items:
                btn = ctk.CTkButton(self.timeline_scroll, text=f"   {time_val}", anchor="w", fg_color="transparent")
                btn.configure(command=lambda i=pid: self._load_entry(i))
                btn.pack(fill="x", pady=1)

    def _load_entry(self, eid):
        self.current_entry_id = eid
        cur = self.db_conn.cursor()
        cur.execute("SELECT content FROM entries WHERE id=?", (eid,))
        row = cur.fetchone()
        if row:
            try:
                pt = self.crypto.decrypt(row[0]).decode('utf-8')
                self.text_area.delete("1.0", "end") # FIX: updated variable name
                self.text_area.insert("1.0", pt)
            except Exception:
                messagebox.showerror("Error", "Decryption failed.")
        self._check_state()

    def _save_entry(self):
        content = self.text_area.get("1.0", "end-1c").strip() # FIX: updated variable name
        if not content:
            return
        try:
            enc = self.crypto.encrypt(content.encode('utf-8'))
            ts = datetime.datetime.now().isoformat()
            cur = self.db_conn.cursor()
            
            if self.current_entry_id:
                cur.execute("UPDATE entries SET content=?, timestamp=? WHERE id=?", (enc, ts, self.current_entry_id))
            else:
                cur.execute("INSERT INTO entries (timestamp, content) VALUES (?,?)", (ts, enc))
            
            self.db_conn.commit()
            self._reset_to_new()
            self._refresh_timeline()
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    def _delete_entry(self):
        if self.current_entry_id and messagebox.askyesno("Delete", "Permanently delete?", icon="warning"):
            cur = self.db_conn.cursor()
            cur.execute("DELETE FROM entries WHERE id=?", (self.current_entry_id,))
            self.db_conn.commit()
            self._reset_to_new()
            self._refresh_timeline()

    def _reset_to_new(self):
        self.current_entry_id = None
        self.text_area.delete("1.0", "end") # FIX: updated variable name
        self._check_state()
        self.lbl_welcome.grid_remove()
        self.text_area.grid(row=0, column=0, sticky="nsew") # FIX: updated variable name
        self.text_area.focus()

    def _check_state(self, event=None):
        # FIX: updated variable name
        has_content = bool(self.text_area.get("1.0", "end-1c").strip())
        is_existing = bool(self.current_entry_id)
        
        self.btn_save.configure(state="normal" if has_content else "disabled")
        self.btn_delete.configure(state="normal" if is_existing else "disabled")
        self.btn_ai.configure(state="normal" if has_content and self.bot.is_ready() else "disabled")

    def _open_settings(self):
        win = ctk.CTkToplevel(self)
        win.title("Settings")
        win.transient(self)
        win.geometry("400x380")
        # FIX: Weight specified explicitly
        win.grid_columnconfigure(0, weight=1)
        
        ctk.CTkLabel(win, text="Appearance", font=("", 14, "bold")).grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")
        theme_menu = ctk.CTkOptionMenu(win, values=list(self.themes.keys()), 
                                     command=lambda t: self._apply_theme(self.themes.get(t)))
        theme_menu.grid(row=1, column=0, padx=20, pady=5, sticky="ew")
        
        ctk.CTkLabel(win, text="Security & Data", font=("", 14, "bold")).grid(row=2, column=0, padx=20, pady=(20, 5), sticky="w")
        ctk.CTkButton(win, text="Change Master Password...", command=self._change_password).grid(row=3, column=0, padx=20, pady=5, sticky="ew")
        ctk.CTkButton(win, text="Export Encrypted Backup...", command=self._export_backup).grid(row=4, column=0, padx=20, pady=5, sticky="ew")
        ctk.CTkButton(win, text="Import Encrypted Backup...", command=self._import_backup).grid(row=5, column=0, padx=20, pady=5, sticky="ew")
        ctk.CTkButton(win, text="Reset Diary (Delete All!)...", command=self._reset_diary, fg_color="#D32F2F", hover_color="#B71C1C").grid(row=6, column=0, padx=20, pady=(15, 20), sticky="ew")

    def _load_plugins(self):
        if not os.path.exists(PLUGINS_DIR):
            os.makedirs(PLUGINS_DIR)
        
        has_plugins = any(f.endswith('.py') for f in os.listdir(PLUGINS_DIR))
        if has_plugins:
            self.menubar.add_cascade(label="Plugins", menu=self.plugins_menu)
        
        for f in os.listdir(PLUGINS_DIR):
            if f.endswith('.py') and not f.startswith('__'):
                try:
                    spec = importlib.util.spec_from_file_location(f[:-3], os.path.join(PLUGINS_DIR, f))
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    if hasattr(mod, 'register'):
                        mod.register(self)
                except Exception as e:
                    print(f"Plugin Error ({f}): {e}")

    def _ai_analysis(self):
        # Implementation hint only - bot usage dependent on library availability
        if self.bot.is_ready():
            content = self.text_area.get("1.0", "end-1c")
            try:
                output = self.bot.generator(content, max_new_tokens=100)[0]['generated_text']
                messagebox.showinfo("AI Analysis", output)
            except Exception as e:
                messagebox.showerror("AI Error", str(e))
        else:
            messagebox.showinfo("AI", "AI Model is loading or unavailable.")

    def _reset_inactivity_timer(self, event=None):
        if self.inactivity_timer_id:
            self.after_cancel(self.inactivity_timer_id)
        self.inactivity_timer_id = self.after(AUTO_LOCK_TIME_MS, self._lock_app)

    def _lock_app(self):
        self.withdraw()
        self.crypto.lock()
        success = handle_login_flow(self, self.crypto, lock_mode=True)
        if success:
            self.deiconify()
            self._reset_inactivity_timer()
        else:
            self.destroy()

    def _change_password(self):
        if not messagebox.askyesno("Change Password", "Re-encrypt all data? This may take a moment."):
            return
        pwd = PasswordDialog(self, title="New Password").get_input()
        if pwd and pwd == PasswordDialog(self, title="Confirm").get_input():
            try:
                new_crypto = CryptoEngine()
                new_crypto.setup_new_password(pwd)
                
                cur = self.db_conn.cursor()
                cur.execute("SELECT id, content FROM entries")
                all_entries = cur.fetchall()
                
                for eid, enc_blob in all_entries:
                    pt = self.crypto.decrypt(enc_blob)
                    new_blob = new_crypto.encrypt(pt)
                    cur.execute("UPDATE entries SET content = ? WHERE id = ?", (new_blob, eid))
                
                self.db_conn.commit()
                self.crypto = new_crypto
                messagebox.showinfo("Success", "Password Changed.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed: {e}")
        elif pwd is not None:
            messagebox.showerror("Error", "Passwords do not match.")
        
    def _export_backup(self):
        path = filedialog.asksaveasfilename(defaultextension=".bak")
        if not path: return
        
        pwd = PasswordDialog(self, title="Backup Password").get_input()
        if not pwd: return
        
        try:
            temp_db_path = "backup.db"
            shutil.copyfile(DB_FILE, temp_db_path)
            
            with zipfile.ZipFile("temp.zip", 'w') as zf:
                zf.write(temp_db_path)
                zf.write(AUTH_FILE)
                
            with open("temp.zip", 'rb') as f:
                data = f.read()
                
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600000, self.crypto.backend)
            key = kdf.derive(pwd.encode())
            nonce = os.urandom(12)
            
            enc_data = salt + nonce + AESGCM(key).encrypt(nonce, data, None)
            
            with open(path, 'wb') as f:
                f.write(enc_data)
            messagebox.showinfo("Success", "Backup exported.")
        except Exception as e:
            messagebox.showerror("Error", f"Backup failed: {e}")
        finally:
            if os.path.exists("backup.db"): os.remove("backup.db")
            if os.path.exists("temp.zip"): os.remove("temp.zip")

    def _import_backup(self):
        if not messagebox.askyesno("Warning", "This will OVERWRITE current diary.", icon="warning"):
            return
        
        path = filedialog.askopenfilename(filetypes=[("Backup", "*.bak")])
        if not path: return
        
        pwd = PasswordDialog(self, title="Import").get_input()
        if not pwd: return
        
        try:
            with open(path, 'rb') as f:
                data_in = f.read()
                
            salt, nonce, enc_data = data_in[:16], data_in[16:28], data_in[28:]
            kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600000, self.crypto.backend)
            key = kdf.derive(pwd.encode())
            dec_data = AESGCM(key).decrypt(nonce, enc_data, None)
            
            self.db_conn.close()
            self.db_conn = None
            
            if os.path.exists(DB_FILE): os.remove(DB_FILE)
            if os.path.exists(AUTH_FILE): os.remove(AUTH_FILE)
            
            with open("temp.zip", 'wb') as f:
                f.write(dec_data)
                
            with zipfile.ZipFile("temp.zip", 'r') as zf:
                zf.extractall()
                
            messagebox.showinfo("Success", "Imported. Please restart.")
            self.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Import failed. Bad password or corrupt file: {e}")
        finally:
            if os.path.exists("temp.zip"): os.remove("temp.zip")

    def _reset_diary(self):
        if messagebox.askyesno("ARE YOU SURE?", "Delete ALL data?", icon="warning"):
            self.db_conn.close()
            self.db_conn = None
            if os.path.exists(DB_FILE): os.remove(DB_FILE)
            if os.path.exists(AUTH_FILE): os.remove(AUTH_FILE)
            messagebox.showinfo("Reset", "Diary reset. Please restart.")
            self.destroy()
            
    def _on_close(self):
        if self.db_conn:
            self.db_conn.close()
        self.destroy()

# =============================================================================
# FLOW CONTROL
# =============================================================================
def handle_login_flow(root, crypto, lock_mode=False):
    for i in range(3):
        msg = "Unlock:" if lock_mode else f"Master Pass (Try {i+1}/3):"
        pwd = PasswordDialog(root, title="Unlock", text_label=msg).get_input()
        
        if pwd is None:
            if not lock_mode and i < 2:
                if messagebox.askyesno("Exit?", "Login required. Exit?"):
                    return False
            elif lock_mode:
                return False
            continue
            
        if pwd and crypto.verify_password(pwd):
            return True
            
        if i < 2:
            messagebox.showwarning("Access Denied", "Incorrect password.")
            
    return False

def perform_first_setup(root, crypto):
    while True:
        pwd = PasswordDialog(root, title="Setup", text_label="Create Master Password (cannot be recovered)").get_input()
        if pwd is None:
            if messagebox.askyesno("Exit?", "Setup required. Exit?"):
                return False
            continue
            
        if not pwd:
            messagebox.showwarning("Error", "Password cannot be empty.")
            continue
            
        conf = PasswordDialog(root, title="Confirm", text_label="Confirm:").get_input()
        if pwd == conf:
            crypto.setup_new_password(pwd)
            messagebox.showinfo("Success", "Encryption keys generated.")
            return True
        else:
            messagebox.showerror("Error", "Passwords do not match.")

# =============================================================================
# MAIN EXECUTION
# =============================================================================
if __name__ == "__main__":
    # Create hidden root for dialogs
    root = ctk.CTk()
    root.withdraw()
    
    engine = CryptoEngine()
    access_granted = False
    
    # Login / Setup
    if not os.path.exists(AUTH_FILE):
        if perform_first_setup(root, engine):
            access_granted = True
    else:
        if handle_login_flow(root, engine):
            access_granted = True
            
    # Launch
    if access_granted:
        root.destroy() # Clear auth dialog root
        
        # Splash screen root
        splash_root = ctk.CTk()
        splash_root.overrideredirect(True)
        ws, hs = splash_root.winfo_screenwidth(), splash_root.winfo_screenheight()
        splash_root.geometry(f"300x120+{(ws//2)-150}+{(hs//2)-60}")
        
        ctk.CTkLabel(splash_root, text=APP_TITLE, font=("", 16, "bold")).pack(pady=(20, 10))
        ctk.CTkLabel(splash_root, text="Loading AI Engine & Plugins...").pack(pady=5)
        
        bot_instance = HuggingFaceBot()
        
        def loading_thread():
            bot_instance.load_model()
            # Slightly longer splash to ensure main window loads cleanly
            splash_root.after(500, splash_root.destroy)
            
        threading.Thread(target=loading_thread, daemon=True).start()
        splash_root.mainloop()
        
        # Main App
        app = SecureDiaryApp(engine, bot_instance)
        app.mainloop()
    else:
        root.destroy()