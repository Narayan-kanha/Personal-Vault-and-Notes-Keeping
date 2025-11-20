import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk

# All plugins must have a register function
def register(app_instance):
    """
    This function is called by the main application at startup.
    'app_instance' is a reference to the main SecureDiaryApp object.
    """
    
    # Create a "Plugins" menu in the main menubar if it doesn't exist
    # A bit of a hack to access the underlying Tk menubar
    if not hasattr(app_instance, 'plugins_menu'):
        app_instance.plugins_menu = tk.Menu(app_instance, tearoff=0)
        app_instance.configure(menu=app_instance.plugins_menu)
        
    # Add a command to the menu
    app_instance.plugins_menu.add_command(
        label="Word Count",
        command=lambda: show_word_count(app_instance)
    )

def show_word_count(app):
    """
    This function contains the plugin's logic.
    It accesses the main app's text_area to perform its function.
    """
    text_content = app.text_area.get("1.0", "end-1c")
    word_count = len(text_content.split())
    char_count = len(text_content)
    
    messagebox.showinfo(
        "Entry Statistics",
        f"Word Count: {word_count}\nCharacter Count: {char_count}",
        parent=app
    )