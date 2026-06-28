"""
Gestionnaire de secrets local — interface graphique
Dépendances : pip install cryptography
Lancement    : python secrets_manager.py
"""

import json
import os
import base64
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

VAULT_FILE = Path.home() / ".secrets_vault.json"

# ─── Chiffrement ──────────────────────────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=500_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def load_vault(password: str) -> dict:
    if not VAULT_FILE.exists():
        return {}
    data = json.loads(VAULT_FILE.read_text())
    salt = base64.b64decode(data["salt"])
    key = derive_key(password, salt)
    try:
        plaintext = Fernet(key).decrypt(data["payload"].encode())
        return json.loads(plaintext)
    except InvalidToken:
        raise ValueError("Mot de passe incorrect.")

def save_vault(secrets: dict, password: str):
    if VAULT_FILE.exists():
        salt = base64.b64decode(json.loads(VAULT_FILE.read_text())["salt"])
    else:
        salt = os.urandom(16)
    key = derive_key(password, salt)
    payload = Fernet(key).encrypt(json.dumps(secrets).encode()).decode()
    VAULT_FILE.write_text(json.dumps({"salt": base64.b64encode(salt).decode(), "payload": payload}, indent=2))
    VAULT_FILE.chmod(0o600)

# ─── Fenêtre de connexion ─────────────────────────────────────────────────────

class LoginWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secrets Manager")
        self.resizable(False, False)
        self.configure(bg="#1e1e2e")
        self._center(360, 320)
        self.password = None
        self._build()
        self.bind("<Return>", lambda e: self._submit())

    def _center(self, w, h):
        self.geometry(f"{w}x{h}+{(self.winfo_screenwidth()-w)//2}+{(self.winfo_screenheight()-h)//2}")

    def _build(self):
        frame = tk.Frame(self, bg="#1e1e2e", padx=32, pady=28)
        frame.pack(fill="both", expand=True)

        tk.Label(frame, text="🔐", font=("", 36), bg="#1e1e2e", fg="#cdd6f4").pack()
        tk.Label(frame, text="Secrets Manager", font=("", 15, "bold"), bg="#1e1e2e", fg="#cdd6f4").pack(pady=(4, 16))

        is_new = not VAULT_FILE.exists()
        hint = "Créer un mot de passe maître" if is_new else "Mot de passe maître"
        tk.Label(frame, text=hint, font=("", 10), bg="#1e1e2e", fg="#a6adc8").pack(anchor="w")

        self.pwd_var = tk.StringVar()
        entry = tk.Entry(frame, textvariable=self.pwd_var, show="•", font=("", 12),
                         bg="#313244", fg="#cdd6f4", insertbackground="#cdd6f4",
                         relief="flat", bd=0, highlightthickness=1,
                         highlightcolor="#89b4fa", highlightbackground="#45475a")
        entry.pack(fill="x", ipady=7, pady=(4, 0))
        entry.focus_set()

        if is_new:
            tk.Label(frame, text="Confirmation", font=("", 10), bg="#1e1e2e", fg="#a6adc8").pack(anchor="w", pady=(10, 0))
            self.pwd2_var = tk.StringVar()
            tk.Entry(frame, textvariable=self.pwd2_var, show="•", font=("", 12),
                     bg="#313244", fg="#cdd6f4", insertbackground="#cdd6f4",
                     relief="flat", bd=0, highlightthickness=1,
                     highlightcolor="#89b4fa", highlightbackground="#45475a").pack(fill="x", ipady=7, pady=(4, 0))
        else:
            self.pwd2_var = None

        btn = tk.Button(frame, text="Déverrouiller" if not is_new else "Créer le vault",
                        font=("", 11, "bold"), bg="#89b4fa", fg="#1e1e2e",
                        relief="flat", bd=0, cursor="hand2",
                        activebackground="#b4befe", activeforeground="#1e1e2e",
                        command=self._submit)
        btn.pack(fill="x", ipady=8, pady=(16, 0))

    def _submit(self):
        pwd = self.pwd_var.get()
        if not pwd:
            return
        is_new = self.pwd2_var is not None
        if is_new:
            if pwd != self.pwd2_var.get():
                messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas.", parent=self)
                return
            # Nouveau vault : on sauvegarde un vault vide avec ce mot de passe
            try:
                save_vault({}, pwd)
                self.password = pwd
                self.destroy()
            except Exception as e:
                messagebox.showerror("Erreur", str(e), parent=self)
        else:
            try:
                load_vault(pwd)  # vérifie le mot de passe sur vault existant
                self.password = pwd
                self.destroy()
            except ValueError as e:
                messagebox.showerror("Erreur", str(e), parent=self)

# ─── Fenêtre principale ───────────────────────────────────────────────────────

class App(tk.Tk):
    BG      = "#1e1e2e"
    SURFACE = "#313244"
    TEXT    = "#cdd6f4"
    MUTED   = "#a6adc8"
    ACCENT  = "#89b4fa"
    RED     = "#f38ba8"
    GREEN   = "#a6e3a1"

    def __init__(self, password: str):
        super().__init__()
        self.password = password
        self.secrets: dict = {}
        self.show_values = False

        self.title("Secrets Manager")
        self.minsize(660, 460)
        self.configure(bg=self.BG)
        self._center(720, 520)
        self._build()
        self._load()

    def _center(self, w, h):
        self.geometry(f"{w}x{h}+{(self.winfo_screenwidth()-w)//2}+{(self.winfo_screenheight()-h)//2}")

    # ── Construction de l'UI ────────────────────────────────────────────────

    def _build(self):
        # Barre du haut
        top = tk.Frame(self, bg=self.BG, padx=16, pady=12)
        top.pack(fill="x")

        tk.Label(top, text="🔐 Secrets Manager", font=("", 14, "bold"),
                 bg=self.BG, fg=self.TEXT).pack(side="left")

        # Boutons à droite dans la barre du haut
        for text, cmd, color in [
            ("+ Ajouter",     self._dialog_add,    self.ACCENT),
            ("🔒 Verrouiller", self._lock,          self.MUTED),
        ]:
            tk.Button(top, text=text, font=("", 10, "bold"),
                      bg=color, fg=self.BG,
                      relief="flat", bd=0, cursor="hand2",
                      padx=12, pady=4,
                      activebackground=self.TEXT, activeforeground=self.BG,
                      command=cmd).pack(side="right", padx=(6, 0))

        # Barre de recherche + toggle
        search_bar = tk.Frame(self, bg=self.BG, padx=16, pady=0)
        search_bar.pack(fill="x")

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._refresh())
        search_entry = tk.Entry(search_bar, textvariable=self.search_var,
                                font=("", 11), bg=self.SURFACE, fg=self.TEXT,
                                insertbackground=self.TEXT, relief="flat", bd=0,
                                highlightthickness=1,
                                highlightcolor=self.ACCENT,
                                highlightbackground="#45475a")
        search_entry.pack(side="left", fill="x", expand=True, ipady=6)

        tk.Label(search_bar, text="  🔍", font=("", 12), bg=self.SURFACE, fg=self.MUTED).place(in_=search_entry, relx=0, rely=0.5, anchor="w", x=6)

        self.toggle_btn = tk.Button(search_bar, text="👁 Afficher",
                                    font=("", 10), bg=self.SURFACE, fg=self.MUTED,
                                    relief="flat", bd=0, cursor="hand2",
                                    padx=10, pady=4,
                                    activebackground="#45475a",
                                    command=self._toggle_show)
        self.toggle_btn.pack(side="right", padx=(8, 0))

        # Séparateur
        tk.Frame(self, bg="#45475a", height=1).pack(fill="x", pady=(10, 0))

        # En-tête du tableau
        header = tk.Frame(self, bg="#252535", padx=16, pady=8)
        header.pack(fill="x")
        tk.Label(header, text="NOM / CLÉ", font=("", 9, "bold"), bg="#252535",
                 fg=self.MUTED, width=24, anchor="w").pack(side="left")
        tk.Label(header, text="CATÉGORIE", font=("", 9, "bold"), bg="#252535",
                 fg=self.MUTED, width=14, anchor="w").pack(side="left")
        tk.Label(header, text="VALEUR", font=("", 9, "bold"), bg="#252535",
                 fg=self.MUTED).pack(side="left", expand=True, anchor="w")
        tk.Label(header, text="ACTIONS", font=("", 9, "bold"), bg="#252535",
                 fg=self.MUTED, width=16, anchor="e").pack(side="right")

        # Zone de liste scrollable
        canvas_frame = tk.Frame(self, bg=self.BG)
        canvas_frame.pack(fill="both", expand=True, padx=0)

        self.canvas = tk.Canvas(canvas_frame, bg=self.BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=self.canvas.yview)
        self.list_frame = tk.Frame(self.canvas, bg=self.BG)

        self.list_frame.bind("<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.list_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.canvas.bind_all("<MouseWheel>", lambda e: self.canvas.yview_scroll(-1*(e.delta//120), "units"))

        # Barre de statut
        self.status_var = tk.StringVar(value="")
        tk.Label(self, textvariable=self.status_var, font=("", 9),
                 bg=self.BG, fg=self.MUTED, anchor="w", padx=16, pady=6).pack(fill="x")

    # ── Données ─────────────────────────────────────────────────────────────

    def _load(self):
        try:
            self.secrets = load_vault(self.password)
            self._refresh()
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def _save(self):
        try:
            save_vault(self.secrets, self.password)
        except Exception as e:
            messagebox.showerror("Erreur de sauvegarde", str(e))

    # ── Affichage de la liste ────────────────────────────────────────────────

    def _refresh(self):
        for w in self.list_frame.winfo_children():
            w.destroy()

        query = self.search_var.get().lower()
        items = [(k, v) for k, v in self.secrets.items()
                 if query in k.lower() or query in v.get("category", "").lower()]

        if not items:
            tk.Label(self.list_frame, text="Aucun secret trouvé.",
                     font=("", 11), bg=self.BG, fg=self.MUTED,
                     pady=40).pack()
        else:
            for i, (key, val) in enumerate(sorted(items)):
                self._row(i, key, val)

        count = len(self.secrets)
        self.status_var.set(f"{count} secret{'s' if count > 1 else ''} • vault : {VAULT_FILE}")

    def _row(self, index: int, key: str, val: dict):
        bg = self.BG if index % 2 == 0 else "#252535"
        row = tk.Frame(self.list_frame, bg=bg, padx=16, pady=10)
        row.pack(fill="x")

        # Nom
        tk.Label(row, text=key, font=("", 11, "bold"), bg=bg,
                 fg=self.TEXT, width=24, anchor="w").pack(side="left")

        # Catégorie
        cat = val.get("category", "—")
        cat_color = {"perso": "#a6e3a1", "pro": "#89b4fa",
                     "dev": "#fab387", "autre": "#cba6f7"}.get(cat, self.MUTED)
        tk.Label(row, text=cat, font=("", 10), bg=bg,
                 fg=cat_color, width=14, anchor="w").pack(side="left")

        # Valeur
        secret_val = val.get("value", "")
        display = secret_val if self.show_values else "•" * min(len(secret_val), 16)
        value_lbl = tk.Label(row, text=display, font=("Courier", 10), bg=bg,
                              fg=self.MUTED if not self.show_values else self.GREEN,
                              anchor="w")
        value_lbl.pack(side="left", expand=True, fill="x")

        # Actions
        actions = tk.Frame(row, bg=bg)
        actions.pack(side="right")

        tk.Button(actions, text="📋", font=("", 11), bg=bg, fg=self.ACCENT,
                  relief="flat", bd=0, cursor="hand2",
                  command=lambda v=secret_val: self._copy(v)).pack(side="left", padx=2)

        tk.Button(actions, text="✏️", font=("", 11), bg=bg, fg=self.MUTED,
                  relief="flat", bd=0, cursor="hand2",
                  command=lambda k=key, v=val: self._dialog_edit(k, v)).pack(side="left", padx=2)

        tk.Button(actions, text="🗑", font=("", 11), bg=bg, fg=self.RED,
                  relief="flat", bd=0, cursor="hand2",
                  command=lambda k=key: self._delete(k)).pack(side="left", padx=2)

    # ── Actions ─────────────────────────────────────────────────────────────

    def _copy(self, value: str):
        self.clipboard_clear()
        self.clipboard_append(value)
        self.status_var.set("✓ Copié dans le presse-papier !")
        self.after(2500, lambda: self.status_var.set(
            f"{len(self.secrets)} secret(s) • vault : {VAULT_FILE}"))

    def _toggle_show(self):
        self.show_values = not self.show_values
        self.toggle_btn.config(text="🙈 Masquer" if self.show_values else "👁 Afficher")
        self._refresh()

    def _delete(self, key: str):
        if messagebox.askyesno("Confirmer", f"Supprimer « {key} » ?", parent=self):
            del self.secrets[key]
            self._save()
            self._refresh()

    def _lock(self):
        self.destroy()
        _run_login()

    # ── Dialogues ajouter / modifier ─────────────────────────────────────────

    def _dialog_add(self):
        self._open_form()

    def _dialog_edit(self, key: str, val: dict):
        self._open_form(key, val)

    def _open_form(self, existing_key=None, existing_val=None):
        win = tk.Toplevel(self)
        win.title("Modifier un secret" if existing_key else "Ajouter un secret")
        win.configure(bg=self.BG)
        win.resizable(False, False)
        win.grab_set()
        w, h = 400, 320
        win.geometry(f"{w}x{h}+{(self.winfo_screenwidth()-w)//2}+{(self.winfo_screenheight()-h)//2}")

        frame = tk.Frame(win, bg=self.BG, padx=24, pady=20)
        frame.pack(fill="both", expand=True)

        def field(label, default="", show=None):
            tk.Label(frame, text=label, font=("", 10), bg=self.BG, fg=self.MUTED,
                     anchor="w").pack(fill="x")
            var = tk.StringVar(value=default)
            kw = dict(textvariable=var, font=("", 11), bg=self.SURFACE, fg=self.TEXT,
                      insertbackground=self.TEXT, relief="flat", bd=0,
                      highlightthickness=1, highlightcolor=self.ACCENT,
                      highlightbackground="#45475a")
            if show:
                kw["show"] = show
            tk.Entry(frame, **kw).pack(fill="x", ipady=6, pady=(3, 12))
            return var

        name_var  = field("Nom / clé", existing_key or "")
        value_var = field("Valeur secrète", existing_val.get("value", "") if existing_val else "", show="•")

        # Catégorie
        tk.Label(frame, text="Catégorie", font=("", 10), bg=self.BG,
                 fg=self.MUTED, anchor="w").pack(fill="x")
        cat_var = tk.StringVar(value=existing_val.get("category", "autre") if existing_val else "autre")
        cat_frame = tk.Frame(frame, bg=self.BG)
        cat_frame.pack(fill="x", pady=(3, 16))
        for cat, color in [("perso", "#a6e3a1"), ("pro", "#89b4fa"),
                            ("dev", "#fab387"), ("autre", "#cba6f7")]:
            tk.Radiobutton(cat_frame, text=cat, variable=cat_var, value=cat,
                           font=("", 10), bg=self.BG, fg=color,
                           selectcolor=self.SURFACE, activebackground=self.BG,
                           relief="flat").pack(side="left", padx=(0, 10))

        def save():
            name = name_var.get().strip()
            value = value_var.get()
            if not name or not value:
                messagebox.showwarning("Champs manquants", "Nom et valeur requis.", parent=win)
                return
            if existing_key and existing_key != name and existing_key in self.secrets:
                del self.secrets[existing_key]
            self.secrets[name] = {"value": value, "category": cat_var.get()}
            self._save()
            self._refresh()
            win.destroy()

        tk.Button(frame, text="Enregistrer", font=("", 11, "bold"),
                  bg=self.ACCENT, fg=self.BG, relief="flat", bd=0,
                  cursor="hand2", padx=12, pady=6,
                  activebackground=self.TEXT, command=save).pack(fill="x")

        win.bind("<Return>", lambda e: save())


# ─── Point d'entrée ───────────────────────────────────────────────────────────

def _run_login():
    login = LoginWindow()
    login.mainloop()
    if login.password:
        app = App(login.password)
        app.mainloop()

if __name__ == "__main__":
    _run_login()
