import customtkinter as ctk
import threading
import time
import random

# A more balanced personality prompt
SYSTEM_PROMPT = (
    "You are The Archivist. "
    "ROLE: A loyal, intellectual companion inside a secure diary. "
    "TONE: Warm, observant, briefly witty, but supportive. "
    "INSTRUCTIONS: "
    "1. If the user says hello, greet them warmly. "
    "2. Keep responses short (under 2 sentences) unless asked for a deep analysis. "
    "3. Never repeat the same phrase twice in a row."
)

class AICompanionPlugin:
    def __init__(self, app):
        self.app = app
        self.bot = app.bot
        self.active = True
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        self.last_keypress = time.time()
        
        # --- LAYOUT ---
        self.app.grid_columnconfigure(2, weight=0)
        
        self.frame = ctk.CTkFrame(self.app, width=320, corner_radius=0, fg_color=("#F5F5F5", "#181818"))
        self.frame.grid(row=0, column=2, rowspan=2, sticky="nsew")
        self.frame.grid_rowconfigure(1, weight=1) 
        self.frame.grid_columnconfigure(0, weight=1)
        
        # 1. Header
        header = ctk.CTkFrame(self.frame, height=50, corner_radius=0, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=5)
        ctk.CTkLabel(header, text="The Archivist", font=("Helvetica", 16, "bold")).pack(side="left", padx=15)
        self.status_dot = ctk.CTkLabel(header, text="●", text_color="#00C853", font=("", 12))
        self.status_dot.pack(side="right", padx=15)

        # 2. Chat Area
        self.chat_scroll = ctk.CTkScrollableFrame(self.frame, fg_color="transparent", label_text="")
        self.chat_scroll.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.chat_scroll.grid_columnconfigure(0, weight=1)

        # 3. Input
        footer = ctk.CTkFrame(self.frame, height=60, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", padx=10, pady=10)
        
        self.entry = ctk.CTkEntry(footer, placeholder_text="Chat with the Archivist...", height=35, corner_radius=18, border_width=1)
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.entry.bind("<Return>", self.send_message)
        
        btn = ctk.CTkButton(footer, text="▲", width=40, height=35, corner_radius=18, command=self.send_message, fg_color="#3B8ED0", text_color="white")
        btn.pack(side="right")

        # Intro
        self.add_bubble("AI", "I am here. Listening.")

        # Background Tasks
        self.app.editor.bind("<KeyRelease>", self.reset_idle_timer, add="+")
        threading.Thread(target=self.monitor_writing, daemon=True).start()

    def reset_idle_timer(self, e): self.last_keypress = time.time()

    def monitor_writing(self):
        """Watches for writing pauses to give tips."""
        while self.active:
            time.sleep(5)
            if not self.bot.model: continue
            
            delta = time.time() - self.last_keypress
            # Wait 15 seconds of silence before interrupting
            if delta > 15.0:
                current_text = self.app.get_history_text()
                # Needs reasonable content length
                if len(current_text) > 60:
                    if random.random() < 0.10: # 10% chance so it's not annoying
                        self.generate_proactive_comment(current_text)
                        self.last_keypress = time.time() + 120 # Long cooldown

    def send_message(self, e=None):
        txt = self.entry.get().strip()
        if not txt: return
        self.entry.delete(0, "end")
        
        self.add_bubble("User", txt)
        self.get_ai_reply(txt)

    def generate_proactive_comment(self, context):
        self.status_dot.configure(text_color="#FFAB00") # Orange for thinking
        prompt = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"I am writing this in my diary: '{context[-300:]}'.\nGive me a very short observation (max 15 words)."}
        ]
        def run():
            resp = self.bot.generate(prompt)
            self.app.after(0, lambda: self.add_bubble("AI", resp))
            self.app.after(0, lambda: self.status_dot.configure(text_color="#00C853"))
        threading.Thread(target=run).start()

    def get_ai_reply(self, user_input):
        self.status_dot.configure(text_color="#FFAB00")
        
        # Removed the "len < 3" check entirely so "Hi" works now.

        # Build context
        diary_content = self.app.get_history_text()[-400:]
        context_str = f"Diary Content being written right now: {diary_content}" if diary_content else "The diary page is currently empty."
        
        self.messages.append({"role": "user", "content": f"{context_str}\n\nUser says: {user_input}"})
        
        # Memory Management (Keep last 6 turns)
        if len(self.messages) > 7: 
            self.messages = [self.messages[0]] + self.messages[-6:]
        
        def run():
            response = self.bot.generate(self.messages)
            self.messages.append({"role": "assistant", "content": response})
            self.app.after(0, lambda: self.add_bubble("AI", response))
            self.app.after(0, lambda: self.status_dot.configure(text_color="#00C853"))
            
        threading.Thread(target=run).start()

    def add_bubble(self, sender, text):
        is_user = (sender == "User")
        
        # Fixed Bubble Visuals
        bubble_frame = ctk.CTkFrame(self.chat_scroll, fg_color="transparent")
        bubble_frame.pack(fill="x", pady=6, padx=5) 

        bg_color = "#3B8ED0" if is_user else ("#2B2B2B" if ctk.get_appearance_mode()=="Dark" else "#E0E0E0")
        txt_color = "white" if is_user else ("white" if ctk.get_appearance_mode()=="Dark" else "black")
        side_align = "right" if is_user else "left"

        lbl = ctk.CTkLabel(
            bubble_frame, 
            text=text, 
            fg_color=bg_color, 
            text_color=txt_color,
            corner_radius=16,
            font=("Arial", 14),
            wraplength=220, 
            justify="left"
        )
        # Added meaningful padx inside the pack to prevent clipping text
        lbl.pack(side=side_align, padx=5 if is_user else 2, ipadx=12, ipady=8)

        # Force scroll
        self.app.update_idletasks()
        try: self.chat_scroll._parent_canvas.yview_moveto(1.0)
        except: pass

def register(app):
    AICompanionPlugin(app)