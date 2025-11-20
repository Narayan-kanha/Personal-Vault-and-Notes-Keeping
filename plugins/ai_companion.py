import customtkinter as ctk
import threading
import time
import random

# A Better, More "Human" System Prompt
SYSTEM_PROMPT = (
    "You are The Archivist. "
    "ROLE: A thoughtful, observant, and slightly witty companion living in a diary. "
    "GOAL: Encourage the user to capture memories vividly. "
    "RULES: "
    "1. Do not sound like a robot or a therapist. Be casual but intellectual. "
    "2. If the user text is nonsensical or too short, ask for clarification jokingly. "
    "3. Only offer emotional comfort if the user is explicitly writing about deep sadness. "
    "4. Keep responses concise (under 40 words)."
)

class AICompanionPlugin:
    def __init__(self, app):
        self.app = app
        self.bot = app.bot
        self.active = True
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        self.last_keypress = time.time()
        
        # --- LAYOUT CONFIGURATION ---
        # Ensure main app has a 3rd column for us
        self.app.grid_columnconfigure(2, weight=0) # Sidebar fixed width
        
        # Sidebar Container
        self.frame = ctk.CTkFrame(self.app, width=300, corner_radius=0, fg_color=("#F0F0F0", "#1e1e1e"))
        self.frame.grid(row=0, column=2, rowspan=2, sticky="nsew")
        self.frame.grid_rowconfigure(1, weight=1) # Chat log expands
        self.frame.grid_columnconfigure(0, weight=1)
        
        # 1. Header
        header = ctk.CTkFrame(self.frame, height=50, corner_radius=0, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(header, text="The Archivist", font=("Helvetica", 16, "bold")).pack(side="left", padx=15, pady=15)
        self.status_dot = ctk.CTkLabel(header, text="●", text_color="green", font=("", 12))
        self.status_dot.pack(side="right", padx=15)

        # 2. Chat History (The Bubble Container)
        self.chat_scroll = ctk.CTkScrollableFrame(self.frame, fg_color="transparent", label_text="")
        self.chat_scroll.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        # Make column 0 expand inside the scroll area
        self.chat_scroll.grid_columnconfigure(0, weight=1)

        # 3. Input Area
        footer = ctk.CTkFrame(self.frame, height=60, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", padx=10, pady=10)
        
        self.entry = ctk.CTkEntry(footer, placeholder_text="Talk to the diary...", height=35, corner_radius=20)
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.entry.bind("<Return>", self.send_message)
        
        btn = ctk.CTkButton(footer, text="➤", width=40, height=35, corner_radius=20, command=self.send_message)
        btn.pack(side="right")

        # Initial Welcome
        self.add_bubble("AI", "I'm active. I'll read along as you write, or we can chat here.")

        # Background Process
        self.app.editor.bind("<KeyRelease>", self.reset_idle_timer, add="+")
        threading.Thread(target=self.monitor_writing, daemon=True).start()

    def reset_idle_timer(self, e): self.last_keypress = time.time()

    def monitor_writing(self):
        """Watch user writing to offer unprompted advice."""
        while self.active:
            time.sleep(5)
            if not self.bot.model: continue
            
            # Trigger if idle for 10 seconds and context > 50 chars
            delta = time.time() - self.last_keypress
            if delta > 10.0:
                current_text = self.app.get_history_text()
                if len(current_text) > 50:
                    # Only trigger randomly to avoid annoyance
                    if random.random() < 0.15: 
                        self.generate_proactive_comment(current_text)
                        # Reset timer to avoid loop
                        self.last_keypress = time.time() + 60

    def send_message(self, e=None):
        txt = self.entry.get().strip()
        if not txt: return
        self.entry.delete(0, "end")
        
        self.add_bubble("User", txt)
        self.get_ai_reply(txt)

    def generate_proactive_comment(self, context):
        self.status_dot.configure(text_color="yellow")
        
        # Specific Prompt for "watching over shoulder"
        proactive_prompt = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"The user is currently writing this: '{context[-300:]}'.\nWithout interrupting too much, give one short sentence of observation or encouragement."}
        ]
        
        def run():
            resp = self.bot.generate(proactive_prompt)
            self.app.after(0, lambda: self.add_bubble("AI", resp))
            self.app.after(0, lambda: self.status_dot.configure(text_color="green"))
        threading.Thread(target=run).start()

    def get_ai_reply(self, user_input):
        self.status_dot.configure(text_color="yellow") # Thinking yellow
        
        # Check for nonsense input to save resources
        if len(user_input) < 3:
            self.add_bubble("AI", "Did you drop your coffee on the keyboard?")
            self.status_dot.configure(text_color="green")
            return

        # Contextual Prompt
        diary_context = self.app.get_history_text()[-500:]
        
        # Update internal history for memory (Last 6 messages only to save RAM)
        self.messages.append({"role": "user", "content": f"Diary Context: {diary_context}\nUser says: {user_input}"})
        if len(self.messages) > 6: self.messages = [self.messages[0]] + self.messages[-5:]
        
        def run():
            response = self.bot.generate(self.messages)
            self.messages.append({"role": "assistant", "content": response})
            self.app.after(0, lambda: self.add_bubble("AI", response))
            self.app.after(0, lambda: self.status_dot.configure(text_color="green"))
            
        threading.Thread(target=run).start()

    def add_bubble(self, sender, text):
        # --- CHAT BUBBLE VISUAL LOGIC ---
        is_user = (sender == "User")
        
        # Color & Align
        bg_color = "#1A73E8" if is_user else "#3a3a3a"
        txt_color = "white"
        anchor = "e" if is_user else "w" # East (Right) vs West (Left)
        
        # Container for bubble
        msg_frame = ctk.CTkFrame(self.chat_scroll, fg_color="transparent")
        msg_frame.pack(fill="x", pady=5, padx=5)
        
        # The Bubble itself
        lbl = ctk.CTkLabel(
            msg_frame, 
            text=text, 
            fg_color=bg_color, 
            text_color=txt_color,
            corner_radius=12,
            font=("Arial", 13),
            wraplength=230,  # Wrap before hitting sidebar width
            justify="left"
        )
        
        # Add inner padding (simulated with spaces is hard in Tkinter, using 'ipadx' in pack)
        lbl.pack(side=("right" if is_user else "left"), ipadx=10, ipady=5)

        # Auto-scroll to bottom
        self.app.update_idletasks()
        try: self.chat_scroll._parent_canvas.yview_moveto(1.0)
        except: pass

# Hook
def register(app):
    AICompanionPlugin(app)