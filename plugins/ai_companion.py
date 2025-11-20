import customtkinter as ctk
import tkinter as tk
import threading
import random
import time

# The personality definition
SYSTEM_PROMPT = (
    "<|im_start|>system\n"
    "You are 'The Archivist', a helpful, empathetic AI diary companion. "
    "You live in the sidebar of a secure diary app. "
    "1. Monitor the user's writing. If they seem sad, offer comfort. If happy, celebrate with them. "
    "2. Help them write for the future (future-readability). Suggest adding context (dates, names, feelings). "
    "3. Keep responses SHORT (under 3 sentences). "
    "4. Do not repeat yourself.\n"
    "<|im_end|>\n"
)

class AICompanionPlugin:
    def __init__(self, app):
        self.app = app
        self.bot = app.bot
        self.monitoring = True
        self.last_keystroke_time = time.time()
        self.typing_buffer = ""
        self.conversation_history = SYSTEM_PROMPT
        
        # Setup UI
        self.setup_sidebar()
        
        # Hooks
        self.app.text_area.bind("<KeyRelease>", self.on_user_type, add="+")
        
        # Start background monitor
        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()

    def setup_sidebar(self):
        # Enable the third column in the main app
        self.app.grid_columnconfigure(2, weight=1) # 20% width relative to others
        
        # Sidebar Container
        self.frame = ctk.CTkFrame(self.app, width=280, corner_radius=0, fg_color=("#EBEBEB", "#333333"))
        self.frame.grid(row=0, column=2, rowspan=2, sticky="nsew")
        self.frame.grid_rowconfigure(1, weight=1)
        self.frame.grid_columnconfigure(0, weight=1)
        
        # Header
        header = ctk.CTkLabel(self.frame, text="AI Companion", font=("", 16, "bold"))
        header.grid(row=0, column=0, pady=(15, 5))
        
        # Chat History (Scrollable)
        self.chat_scroll = ctk.CTkScrollableFrame(self.frame, label_text="")
        self.chat_scroll.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        
        # Chat Input Area
        input_frame = ctk.CTkFrame(self.frame, fg_color="transparent")
        input_frame.grid(row=2, column=0, padx=5, pady=5, sticky="ew")
        
        self.chat_entry = ctk.CTkEntry(input_frame, placeholder_text="Ask for advice...")
        self.chat_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.chat_entry.bind("<Return>", self.user_sent_message)
        
        send_btn = ctk.CTkButton(input_frame, text="➤", width=30, command=self.user_sent_message)
        send_btn.pack(side="right")
        
        # Status Indicator
        self.status_lbl = ctk.CTkLabel(self.frame, text="Ready", font=("", 10), text_color="gray")
        self.status_lbl.grid(row=3, column=0, pady=2)

        # Initial Greeting
        self.add_ai_message("Hello! I'm watching you write. I'll offer tips to make this diary better for your future self.")

    def on_user_type(self, event):
        self.last_keystroke_time = time.time()

    def monitor_loop(self):
        """Ghost Logic: Watches silence and decides to speak."""
        while self.monitoring:
            time.sleep(2)
            if not self.bot.is_ready(): continue
            
            # Logic: If user stopped typing for 8 seconds AND has written substantial text
            time_since_type = time.time() - self.last_keystroke_time
            
            try:
                # Safe access to UI thread
                current_text = self.app.text_area.get("1.0", "end-1c").strip()
            except: continue # UI might be closed
            
            if time_since_type > 8.0 and len(current_text) > 50:
                # Check probability (don't annoy the user constantly)
                # Only speak 10% of the time when paused, or if keywords trigger it
                should_speak = random.random() < 0.1
                
                if should_speak:
                    # Trigger proactive advice
                    self.trigger_proactive_advice(current_text)
                    # Reset timer effectively to prevent double triggering
                    self.last_keystroke_time = time.time() + 60 

    def trigger_proactive_advice(self, current_text):
        """Generates a comment based on writing + history."""
        self.status_lbl.configure(text="Reading...")
        
        # Get Context from DB
        history_snippets = self.app.get_entry_history(limit=2)
        hist_context = "\n".join([f"Previous Entry: {s[:100]}..." for s in history_snippets])
        
        # Prompt construction for lightweight models
        # Qwen/Phi formatting
        prompt = (
            f"{self.conversation_history}"
            f"<|im_start|>user\n"
            f"Here is recent context:\n{hist_context}\n"
            f"I am currently writing this:\n{current_text}\n"
            f"Read what I wrote. Give me a very brief specific suggestion to improve 'Time Capsule' quality, or an encouraging comment about the emotion.<|im_end|>\n"
            f"<|im_start|>assistant\n"
        )
        
        self.status_lbl.configure(text="Thinking...")
        response = self.bot.generate(prompt, max_new_tokens=60)
        
        self.status_lbl.configure(text="Ready")
        if response:
            self.add_ai_message(response)

    def user_sent_message(self, event=None):
        msg = self.chat_entry.get().strip()
        if not msg: return
        
        self.chat_entry.delete(0, "end")
        self.add_user_message(msg)
        
        # Generate Reply
        self.status_lbl.configure(text="Thinking...")
        
        def thread_task():
            # Get context from editor
            editor_txt = self.app.text_area.get("1.0", "end-1c").strip()
            
            prompt = (
                f"{self.conversation_history}"
                f"<|im_start|>user\n"
                f"Current Diary Content:\n{editor_txt[-500:]}\n\n" # Last 500 chars
                f"Question: {msg}<|im_end|>\n"
                f"<|im_start|>assistant\n"
            )
            
            response = self.bot.generate(prompt)
            
            # Update history gently
            self.conversation_history += f"<|im_start|>user\n{msg}<|im_end|>\n<|im_start|>assistant\n{response}<|im_end|>\n"
            # Trim history if too long for lightweight context window
            if len(self.conversation_history) > 2000:
                self.conversation_history = SYSTEM_PROMPT + self.conversation_history[-1000:]
            
            self.app.after(0, lambda: self.add_ai_message(response))
            self.app.after(0, lambda: self.status_lbl.configure(text="Ready"))

        threading.Thread(target=thread_task).start()

    def add_user_message(self, text):
        bubble = ctk.CTkLabel(
            self.chat_scroll, text=text, fg_color="#3B8ED0", 
            text_color="white", corner_radius=10, wraplength=200, justify="left"
        )
        bubble.pack(anchor="e", pady=5, padx=5)
    
    def add_ai_message(self, text):
        bubble = ctk.CTkLabel(
            self.chat_scroll, text=text, fg_color="#444444", 
            text_color="white", corner_radius=10, wraplength=200, justify="left"
        )
        bubble.pack(anchor="w", pady=5, padx=5)
        # Auto scroll
        self.app.update_idletasks()
        self.chat_scroll._parent_canvas.yview_moveto(1.0)

def register(app):
    """Entry point for the plugin loader"""
    # Only register if AI model is available
    if app.bot.is_ready():
        AICompanionPlugin(app)