## ⭐ Secure Diary (Uncle-Proof Edition™)

Have you ever written something personal…
only to discover someone in the house reads faster than you encrypt?

Yeah. That happened.

This project began as a *simple plan*:
**“I’ll make a tiny encrypted diary in Python. 10 minutes. Easy.”**

But then, as all programmers know, 10-minute plans **evolve**.

And by “evolve,” I mean **explode into a full-blown software ecosystem.**

---

## 🧨 How a Normal Diary Became a Cyberpunk Vault

### Step 1 — The Betrayal

My uncle read my diary.

Privacy was breached. Trust was shattered.
Trauma was acquired.

I needed security.

---

### Step 2 — The Plan (a.k.a. The Lie)

“Let’s make a simple Caesar cipher. Done.”

Narrator: *It was not done.*

---

### Step 3 — Programmer Brain Activated

Because no sane developer ever stops at “simple.”

It escalated:

#### 🔥 **Level 1: Encryption**

* Caesar cipher → Substitution cipher → AES-GCM
  Because if it’s not government-grade encryption, is it even privacy?

#### 🔥 **Level 2: Password Security**

* PBKDF2? Too normal.
* **Argon2id**? Perfect.
  Now the diary password requires more compute than Bitcoin mining.

#### 🔥 **Level 3: Filesystem Chaos**

Encrypted text files? Ugly. Primitive. Barbaric.
→ Replaced with a **SQLite database** storing encrypted blobs.

Now my diary has indexing, journaling, commits, ACID compliance —
you know, everything a diary obviously needs.

#### 🔥 **Level 4: User Interface Enlightenment**

Tkinter default theme?
Looks like a Windows XP error.

Solution: **customtkinter + JSON theme engine.**
I can now be depressed in Ocean Blue or confident in Cyberpunk Neon.

#### 🔥 **Level 5: Plugin System**

Why write code once when you can architect a full plugin API?

My diary now has:

* Plugin loading
* Plugin menu
* Example plugin (word count)
* The possibility of a *Plugin Store*

Because yes, the diary needs an ecosystem.

#### 🔥 **Level 6: Local AI Companion**

“I feel lonely writing my secrets… what if my diary could respond?”

Boom. Offline HuggingFace model integrated.

Now my diary:

* Analyzes my feelings
* Summarizes my thoughts
* Gives emotional support
* Probably knows too much

It truly has become self-aware.

---

## 🚀 Final Result

What started as “protect my diary from my uncle”
turned into:

### ✔ Military-grade encryption

### ✔ A themeable UI

### ✔ A plugin-enabled architecture

### ✔ Encrypted SQLite storage

### ✔ Offline local AI companion

### ✔ Auto-lock system

### ✔ Backup import/export with encryption

### ✔ A loading splash screen

### ✔ A timeline UI

### ✔ A full software platform

I tried to build a diary.
I ended up building an operating system.

And honestly?

**It was totally worth it.**

---

## 🎯 Features Overview

* 🔐 **Argon2id password hashing**
* 🔑 **HKDF key derivation**
* 🧊 **AES-GCM encryption (double layer)**
* 📦 **Encrypted SQLite database storage**
* 🌈 **JSON theme system**
* 🧩 **Full plugin architecture**
* 🤖 **Local offline AI companion**
* 🕒 **Auto-lock after inactivity**
* 🗂 **Timeline view**
* 🧹 **Clean UI with customtkinter**
* 🔄 **Encrypted backups**

---

## 🧪 Example Plugin (word_count.py)

```python
def register(app_instance):
    app_instance.plugins_menu.add_command(
        label="Word Count",
        command=lambda: show_word_count(app_instance)
    )

def show_word_count(app):
    text = app.text_area.get("1.0", "end-1c")
    words = len(text.split())
    chars = len(text)
    messagebox.showinfo(
        "Entry Statistics",
        f"Words: {words}\nCharacters: {chars}",
        parent=app
    )
```

---

## 🎨 Example Theme (ocean_blue.json)

```json
{
    "appearance_mode": "dark",
    "color_theme": "dark-blue",
    "app_bg": "#0D202F"
}
```

---

## 🛡 Final Thoughts

This project is:

* Overbuilt
* Overengineered
* Overcomplicated
* **Perfectly necessary**

My uncle reads my diary.

He won’t read *this* one.
