import sqlite3
import sys
import bcrypt
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from groq import Groq

#------------------------------AES file encryption/decryption----------------------------------------------------------
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

#--------Helper functions---------------------------
# #pysqlcipher3 did not want to work, so this is my work around
#to maunaly encrypt/decrypt the database 
def _derive_key(password: str) -> bytes:
    """ Derive a 32‑byte AES key from the master password via SHA256. """
    return hashlib.sha256(password.encode('utf-8')).digest()

def encrypt_file(path: str, password: str):
    """ Encrypts the file at `path` in place using AES‑GCM. """
    key = _derive_key(password)
    with open(path, 'rb') as f:
        plaintext = f.read()
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    with open(path, 'wb') as f:
        f.write(nonce + tag + ciphertext)

def decrypt_file(path: str, password: str):
    """ Decrypts the file at `path` in place using AES‑GCM. """
    key = _derive_key(password)
    with open(path, 'rb') as f:
        data = f.read()
    nonce, tag, ciphertext = data[:12], data[12:28], data[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    with open(path, 'wb') as f:
        f.write(plaintext)
#----------------------------------------------------------------------------------------------------------------------


API_KEY = "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"    #has been disabled
MODEL_NAME = "compound-beta"

DB_NAME = "dataBase.db"

class PasswordManagerDB:
    """
    Encapsulates all database operations for the password manager.
    """

    def __init__(self, master_password, db_name=DB_NAME):
        self.master_password = master_password
        self.db_name = db_name
        self.connection = None
        self.cursor = None
        self._connect_and_initialize()
        

    def _connect_and_initialize(self):
        """
        - Decrypt (if exists), open the file
        - Ensure Master, Websites, and Instances tables all exist
        """
        try:
            self.connection = sqlite3.connect(self.db_name)
            self.cursor = self.connection.cursor()
            # Create Master table (id=1 reserved)
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS Master (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    password_hash TEXT NOT NULL
                )
            ''')
            # Create Websites
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS Websites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE
                )
            ''')
            # Create Instances
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS Instances (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    website_id INTEGER NOT NULL,
                    url TEXT NOT NULL,
                    username TEXT NOT NULL,
                    email TEXT NOT NULL,
                    password TEXT NOT NULL,
                    FOREIGN KEY (website_id) REFERENCES Websites(id) ON DELETE CASCADE
                )
            ''')
            self.connection.commit()
        except sqlite3.Error as e:
            raise RuntimeError(f"Database initialization error: {e}")


    def get_all_websites(self):
        """
        Return a list of (id, name) for all websites, ordered alphabetically.
        """
        try:
            self.cursor.execute("SELECT id, name FROM Websites ORDER BY name ASC")
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            raise RuntimeError(f"Could not fetch websites: {e}")

    def add_website(self, website_name):
        """
        Insert a new website into the Websites table.
        Raises:
          - sqlite3.IntegrityError if the name already exists
          - RuntimeError for other failures
        Returns the new website_id.
        """
        try:
            self.cursor.execute("INSERT INTO Websites (name) VALUES (?)", (website_name,))
            self.connection.commit()
            return self.cursor.lastrowid
        except sqlite3.IntegrityError:
            #needed so GUI can show “already exists”
            raise
        except sqlite3.Error as e:
            raise RuntimeError(f"Could not add website: {e}")

    def get_instances_for_website(self, website_id):
        """
        Return a list of (id, url, username, email, password) tuples
        for the given website_id.
        """
        try:
            self.cursor.execute(
                "SELECT id, url, username, email, password "
                "FROM Instances WHERE website_id = ?",
                (website_id,)
            )
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            raise RuntimeError(f"Could not fetch instances: {e}")

    def add_instance(self, website_id, url, username, email, raw_password):
        """
        Insert a new row into Instances. 
        Returns the new instance_id.
        Raises RuntimeError on failure.
        """

        try:
            self.cursor.execute(
                '''
                INSERT INTO Instances 
                (website_id, url, username, email, password)
                VALUES (?, ?, ?, ?, ?)
                ''',
                (
                    website_id,
                    url,
                    username,
                    email,
                    raw_password
                )
            )
            self.connection.commit()
            return self.cursor.lastrowid
        except sqlite3.Error as e:
            raise RuntimeError(f"Could not add instance: {e}")

    def delete_instance(self, instance_id):
        """
        Delete the row from Instances where id = instance_id.
        Raises RuntimeError on failure.
        """
        try:
            self.cursor.execute("DELETE FROM Instances WHERE id = ?", (instance_id,))
            self.connection.commit()
        except sqlite3.Error as e:
            raise RuntimeError(f"Could not delete instance: {e}")

    def close(self):
        """
        Close the SQLite connection cleanly.
        """
        if self.connection:
            self.connection.close()
            #encrypt the database
            encrypt_file(self.db_name, self.master_password)


    #--------------Master Password---------------------

    def has_master(self):
        """
        Return True if a master-password row exists in the Master table.
        """
        try:
            self.cursor.execute("SELECT COUNT(*) FROM Master")
            count = self.cursor.fetchone()[0]
            return count > 0
        except sqlite3.Error as e:
            raise RuntimeError(f"Could not check master existence: {e}")


    def set_master(self, raw_password):
        """
        Hash raw_password with bcrypt, then insert it into Master (id=1).
        Called only when no master exists yet.
        """
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(raw_password.encode("utf-8"), salt)
        try:
            #useses id=1, so we can easily find it when verifing the password
            self.cursor.execute(
                "INSERT INTO Master (id, password_hash) VALUES (1, ?)",
                (hashed.decode("utf-8"),)
            )
            self.connection.commit()
        except sqlite3.Error as e:
            raise RuntimeError(f"Could not set master password: {e}")


    def verify_master(self, raw_password):
        """
        Returns True if raw_password matches the stored hash in Master.
        """
        try:
            self.cursor.execute("SELECT password_hash FROM Master WHERE id = 1")
            row = self.cursor.fetchone()
            if not row:
                return False
            stored_hash = row[0].encode("utf-8")
            return bcrypt.checkpw(raw_password.encode("utf-8"), stored_hash)
        except sqlite3.Error as e:
            raise RuntimeError(f"Could not verify master password: {e}")
        

class PasswordSuggester:
    """
    Provides exactly 1 memorable password.
    """

    def __init__(self, model_name=MODEL_NAME, api_key=API_KEY):
        self.model_name = model_name

    def generate(self):
        prompt = (
            "You are a password‑making assistant. "
            "Generate **one** secure, memorable password by:  \n"
            "  1. Choosing three real English words that form a vivid mental image (e.g. 'SilverFoxMoon').  \n"
            "  2. Inserting 2–3 digits at the end (e.g. '123') for entropy.  \n"
            "Do **not** include symbols other than the capital letters and digits.  \n"
            "Return **exactly** the password, with no labels or extra text."
        )

        try:
            client = Groq(api_key=API_KEY)
            response = client.chat.completions.create(
                model=self.model_name,
                messages=[
                    # 1) System message tells the model who it *is*
                    {
                        "role": "system",
                        "content": "You are an assistant that creates secure and memorable passwords."
                    },
                    # 2) User message tells the model what we *want right now*
                    {
                        "role": "user",
                        "content": prompt
                    },
                ],
                max_tokens=8,
                temperature=0.8,
                top_p=1.0,
                # Stop at first newline so we only get a single line
                stop=["\n"]
            )

        except Exception as e:
            raise RuntimeError(f"AI API error: {e}")

        password = response.choices[0].message.content.strip()

        password = password.lstrip('"\' ').removeprefix("Password:").strip()

        return password


class PasswordManagerGUI:
    """
    All GUI logic lives here. This class holds a reference to both:
      - PasswordManagerDB   (database operations)
      - PasswordSuggester   (AI password suggestions)
    """

    def __init__(self, master, db_name="dataBase.db"):
        self.master = master
        self.master.title("Password Manager")
        self.master.geometry("900x650")  
        self.db_name = db_name


    #-------Master password--------------
        #hides main window until master password is verified/set
        self.master.withdraw()

        #Show the master password dialog
        self._show_master_dialog()


    def _show_master_dialog(self):
        """
        Create a modal Toplevel asking the user to set or enter the master password.
        If no master exists, prompt to create one (enter+confirm).
        If a master exists, prompt to enter.
        Upon success, destroy this Toplevel and reveal the main window/UI.
        """
        self.login_win = tk.Toplevel(self.master)
        self.login_win.title("Master Password")
        self.login_win.grab_set()  # Make it modal
        # Center the login window over the main (withdrawn) window
        self.login_win.geometry("350x200")
        self.login_win.resizable(False, False)
        # Check if a master password is already set
        if not os.path.exists(self.db_name):
            # No master yet: “Set a Master Password”
            ttk.Label(self.login_win, text="Set a Master Password", font=("Segoe UI", 12, "bold")).pack(pady=(10, 5))
            ttk.Label(self.login_win, text="Password:").pack(anchor="w", padx=20)
            self.new_pass_entry = ttk.Entry(self.login_win, show="*")
            self.new_pass_entry.pack(fill="x", padx=20, pady=(0,5))
            ttk.Label(self.login_win, text="Confirm Password:").pack(anchor="w", padx=20)
            self.confirm_pass_entry = ttk.Entry(self.login_win, show="*")
            self.confirm_pass_entry.pack(fill="x", padx=20, pady=(0,10))
            btn = ttk.Button(self.login_win, text="Set Password", command=self._set_master_password)
            btn.pack(pady=(5,10))
        else:
            # Master exists: “Enter Master Password”
            ttk.Label(self.login_win, text="Enter Master Password", font=("Segoe UI", 12, "bold")).pack(pady=(20, 5))
            ttk.Label(self.login_win, text="Password:").pack(anchor="w", padx=20)
            self.login_entry = ttk.Entry(self.login_win, show="*")
            self.login_entry.pack(fill="x", padx=20, pady=(0,10))
            btn = ttk.Button(self.login_win, text="Login", command=self._verify_master_password)
            btn.pack(pady=(5,10))
        # If the user clicks the “X” on the login_win, exit the entire app
        self.login_win.protocol("WM_DELETE_WINDOW", self._on_master_cancel)

    def _set_master_password(self):
        """
        Called when no master exists and the user clicks “Set Password.”
        Validates that both entries match and are non-empty, then stores the hash.
        """
        pw1 = self.new_pass_entry.get().strip()
        pw2 = self.confirm_pass_entry.get().strip()

        if not pw1 or not pw2:
            messagebox.showwarning("Validation Error", "Both fields must be filled.")
            return
        if pw1 != pw2:
            messagebox.showerror("Mismatch", "Passwords do not match.")
            return

        try:
            self.db = PasswordManagerDB(master_password=pw1, db_name=DB_NAME)
            self.db.set_master(pw1)
            self.db.close()
            decrypt_file(self.db_name, pw1)
            self.db = PasswordManagerDB(master_password=pw1, db_name=self.db_name)
        except RuntimeError as e:
            messagebox.showerror("Database Error", str(e))
            self.master.destroy()
            sys.exit(1)
 

        #When master password successfully set, we close the dialog and show main UI
        self.login_win.destroy()
        self._reveal_main_ui()

    def _verify_master_password(self):
        """
        Called when a master already exists and the user clicks “Login.”
        Verifies the typed password against the stored hash.
        """
        entered = self.login_entry.get().strip()
        if not entered:
            messagebox.showwarning("Validation Error", "Password cannot be empty.")
            return

        try:
            decrypt_file(self.db_name, entered)
            self.login_entry.delete(0, tk.END)
            
        except Exception:
            messagebox.showerror("Access Denied", "Incorrect master password.")
            return

        # Initialize the DB layer
        try:
            self.db = PasswordManagerDB(master_password=entered, db_name=DB_NAME)
            if not self.db.verify_master(entered):
                raise ValueError("Master‐hash mismatch")
        except RuntimeError as e:
            messagebox.showerror("Access Denied", str(e))
            self.master.destroy()
            sys.exit(1)

        #If master password is correct, we close the dialog and show main UI
        self.login_win.destroy()
        self._reveal_main_ui()


    def _on_master_cancel(self):
        """
        If the user closes the master password dialog before ever
        initializing the DB, just exit cleanly.
        """
        if hasattr(self, "db") and self.db:
            try:
                self.db.close()
            except Exception:
                pass
        self.master.destroy()
        sys.exit(0)


    def _reveal_main_ui(self):
       """
       After successful master‐password creation/verification, show the main window
       and build its UI.
       """
       self.master.deiconify()
       self._build_single_page_ui()
       self._refresh_website_list()
       self._refresh_website_dropdown()
       # Now the main window is fully functional
       self.master.protocol("WM_DELETE_WINDOW", self._on_close)
       # Initialize the AI Password Suggester (using GPT-3.5-turbo by default)
       self.suggester = PasswordSuggester(model_name=MODEL_NAME)
       # Build the single‐window UI layout
       self._build_single_page_ui()
       # Load initial data into Treeviews and Combobox
       self._refresh_website_list()
       self._refresh_website_dropdown()
       # Hook into window-close so we can shut down the DB
       self.master.protocol("WM_DELETE_WINDOW", self._on_close)


    def _build_single_page_ui(self):
        """
        Constructs a single window with four regions:
          ┌───────────────────────────────────────────────────┐
          │ Top (row=0)                                       │
          │  ╔═══════════════╗ ╔════════════════════════════╗ │
          │  ║  Websites     ║ ║      Instances             ║ │
          │  ║  (Treeview)   ║ ║  (Treeview + Delete btn)   ║ │
          │  ╚═══════════════╝ ╚════════════════════════════╝ │
          │                                                   │
          │                                                   │
          │                                                   │
          │                                                   │
          │─────────────────────────────────────────────────  │
          │ Bottom (row=1)                                    │
          │  ╔═══════════════╗ ╔════════════════════════════╗ │
          │  ║ Add Website   ║ ║  Add Instance (w/ Generate)║ │
          │  ║ (Entry + Btn) ║ ║  (Dropdown + fields + Btn) ║ │
          │  ╚═══════════════╝ ╚════════════════════════════╝ │
          └───────────────────────────────────────────────────┘
        """

        # Configure main grid: two rows, two columns
        self.master.rowconfigure(0, weight=3)   # Top: Treeviews
        self.master.rowconfigure(1, weight=2)   # Bottom: Forms
        self.master.columnconfigure(0, weight=1)
        self.master.columnconfigure(1, weight=1)

        # ─────────── Top Left: Websites List ─────────────
        top_left_frame = ttk.Frame(self.master, padding=10, relief="groove")
        top_left_frame.grid(row=0, column=0, sticky="nsew", padx=(10, 5), pady=10)
        top_left_frame.columnconfigure(0, weight=1)
        top_left_frame.rowconfigure(1, weight=1)

        lbl_sites = ttk.Label(top_left_frame, text="Websites", font=("Segoe UI", 12, "bold"))
        lbl_sites.grid(row=0, column=0, sticky="w", pady=(0, 5))

        self.tree_websites = ttk.Treeview(
            top_left_frame,
            columns=("ID", "Name"),
            show="headings",
            selectmode="browse"
        )
        self.tree_websites.heading("ID", text="ID")
        self.tree_websites.heading("Name", text="Website Name")
        self.tree_websites.column("ID", width=40, anchor="center")
        self.tree_websites.column("Name", width=200, anchor="w")
        self.tree_websites.grid(row=1, column=0, sticky="nsew")

        visible_sites = ttk.Scrollbar(top_left_frame, orient="vertical", command=self.tree_websites.yview)
        self.tree_websites.configure(yscrollcommand=visible_sites.set)
        visible_sites.grid(row=1, column=1, sticky="ns")

        # Whenever a website is selected, show its instances
        self.tree_websites.bind("<<TreeviewSelect>>", self._on_website_select)

        # ─────────── Top Right: Instances List + Delete Button ─────────────
        top_right_frame = ttk.Frame(self.master, padding=10, relief="groove")
        top_right_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 10), pady=10)
        top_right_frame.columnconfigure(0, weight=1)
        top_right_frame.rowconfigure(1, weight=1)

        lbl_instances = ttk.Label(top_right_frame, text="Instances", font=("Segoe UI", 12, "bold"))
        lbl_instances.grid(row=0, column=0, sticky="w", pady=(0, 5))

        self.tree_instances = ttk.Treeview(
            top_right_frame,
            columns=("ID", "URL", "Username", "Email", "Password"),
            show="headings",
            selectmode="browse"
        )
        for col in ("ID", "URL", "Username", "Email", "Password"):
            self.tree_instances.heading(col, text=col)
            anchor = "center" if col == "ID" else "w"
            width = 40 if col == "ID" else 120
            self.tree_instances.column(col, width=width, anchor=anchor)
        self.tree_instances.grid(row=1, column=0, sticky="nsew")

        visible_instances = ttk.Scrollbar(top_right_frame, orient="vertical", command=self.tree_instances.yview)
        self.tree_instances.configure(yscrollcommand=visible_instances.set)
        visible_instances.grid(row=1, column=1, sticky="ns")

        delete_instance_btn = ttk.Button(
            top_right_frame,
            text="Delete Selected Instance",
            command=self._delete_selected_instance
        )
        delete_instance_btn.grid(row=2, column=0, columnspan=2, pady=(10, 0), sticky="ew")

        # ─────────── Bottom Left: Add Website Form ─────────────
        bottom_left_frame = ttk.Frame(self.master, padding=10, relief="groove")
        bottom_left_frame.grid(row=1, column=0, sticky="nsew", padx=(10, 5), pady=(0, 10))
        bottom_left_frame.columnconfigure(1, weight=1)

        lbl_add_site = ttk.Label(bottom_left_frame, text="Add New Website", font=("Segoe UI", 11, "bold"))
        lbl_add_site.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 5))

        ttk.Label(bottom_left_frame, text="Website Name:").grid(
            row=1, column=0, sticky="w", pady=5, padx=(0, 5)
        )
        self.entry_new_site = ttk.Entry(bottom_left_frame)
        self.entry_new_site.grid(row=1, column=1, sticky="ew", pady=5)

        add_site_btn = ttk.Button(
            bottom_left_frame,
            text="Add Website",
            command=self._add_website_from_form
        )
        add_site_btn.grid(row=2, column=0, columnspan=2, pady=(10, 0), sticky="ew")

        # ─────────── Bottom Right: Add Instance Form + AI sugguestion─────────────
        bottom_right_frame = ttk.Frame(self.master, padding=10, relief="groove")
        bottom_right_frame.grid(row=1, column=1, sticky="nsew", padx=(5, 10), pady=(0, 10))
        bottom_right_frame.columnconfigure(0, weight=1)
        bottom_right_frame.columnconfigure(1, weight=1)

        lbl_add_inst = ttk.Label(bottom_right_frame, text="Add New Instance", font=("Segoe UI", 11, "bold"))
        lbl_add_inst.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 5))

        #Website dropdown (Combobox)
        ttk.Label(bottom_right_frame, text="Select Website:").grid(
            row=1, column=0, sticky="w", pady=5, padx=(0, 5)
        )
        self.var_site_dropdown = tk.StringVar()
        self.cmb_sites = ttk.Combobox(
            bottom_right_frame,
            textvariable=self.var_site_dropdown,
            state="readonly"
        )
        self.cmb_sites.grid(row=1, column=1, sticky="ew", pady=5)

        #URL
        ttk.Label(bottom_right_frame, text="URL:").grid(
            row=2, column=0, sticky="w", pady=5, padx=(0, 5)
        )
        self.entry_url = ttk.Entry(bottom_right_frame)
        self.entry_url.grid(row=2, column=1, sticky="ew", pady=5)

        #Username
        ttk.Label(bottom_right_frame, text="Username:").grid(
            row=3, column=0, sticky="w", pady=5, padx=(0, 5)
        )
        self.entry_username = ttk.Entry(bottom_right_frame)
        self.entry_username.grid(row=3, column=1, sticky="ew", pady=5)

        #Email
        ttk.Label(bottom_right_frame, text="Email:").grid(
            row=4, column=0, sticky="w", pady=5, padx=(0, 5)
        )
        self.entry_email = ttk.Entry(bottom_right_frame)
        self.entry_email.grid(row=4, column=1, sticky="ew", pady=5)

        #Password + Generate button
        ttk.Label(bottom_right_frame, text="Password:").grid(
            row=5, column=0, sticky="w", pady=5, padx=(0, 5)
        )
        self.entry_password = ttk.Entry(bottom_right_frame)
        self.entry_password.grid(row=5, column=1, sticky="ew", pady=5)

        # “Generate Password” sits below the password entry
        gen_btn = ttk.Button(
            bottom_right_frame,
            text="Generate Password",
            command=self._generate_password
        )
        gen_btn.grid(row=6, column=0, columnspan=2, pady=(10, 0), sticky="ew")

        #Finally, the “Add Instance” button sits under that
        add_inst_btn = ttk.Button(
            bottom_right_frame,
            text="Add Instance",
            command=self._add_instance_from_form
        )
        add_inst_btn.grid(row=7, column=0, columnspan=2, pady=(10, 0), sticky="ew")

    # ─────────── Data Refresh / Event Callbacks ────────────

    def _refresh_website_list(self):
        """
        Clear and repopulate the Websites Treeview from the DB.
        """
        for row in self.tree_websites.get_children():
            self.tree_websites.delete(row)

        try:
            websites = self.db.get_all_websites()
            for wid, name in websites:
                self.tree_websites.insert("", "end", values=(wid, name))
        except RuntimeError as e:
            messagebox.showerror("Error", str(e))


    def _refresh_website_dropdown(self):
        """
        Populate the “Select Website” Combobox with “id - name” strings.
        """
        try:
            websites = self.db.get_all_websites()
            display_values = [f"{wid} - {wname}" for (wid, wname) in websites]
            self.cmb_sites['values'] = display_values
            if display_values:
                self.cmb_sites.current(0)
            else:
                self.cmb_sites.set("")  # no selection if empty
        except RuntimeError as e:
            messagebox.showerror("Error", str(e))


    def _on_website_select(self, event):
        """
        Called when the user selects a website in the top-left Treeview.
        Fetch and display its instances in the top-right Treeview.
        """
        selected = self.tree_websites.focus()
        if not selected:
            return

        wid = int(self.tree_websites.item(selected, "values")[0])
        self._refresh_instances_list(website_id=wid)


    def _refresh_instances_list(self, website_id):
        """
        Clear and repopulate the Instances Treeview for the given website_id.
        """
        for row in self.tree_instances.get_children():
            self.tree_instances.delete(row)

        try:
            instances = self.db.get_instances_for_website(website_id)
            for inst in instances:
                # inst = (id, url, username, email, password)
                self.tree_instances.insert("", "end", values=inst)
        except RuntimeError as e:
            messagebox.showerror("Error", str(e))


    def _delete_selected_instance(self):
        """
        Delete whichever instance is highlighted in the top-right Treeview,
        then refresh that list for the same website (if still selected).
        """
        selected = self.tree_instances.focus()
        if not selected:
            messagebox.showwarning("Selection Error", "Please select an instance to delete.")
            return

        inst_id = int(self.tree_instances.item(selected, "values")[0])
        confirm = messagebox.askyesno("Confirm Deletion", "Are you sure you want to delete this instance?")
        if not confirm:
            return

        try:
            self.db.delete_instance(inst_id)
        except RuntimeError as e:
            messagebox.showerror("Error", str(e))
            return

        # Refresh instances for currently selected website, if any
        selected_site = self.tree_websites.focus()
        if selected_site:
            wid = int(self.tree_websites.item(selected_site, "values")[0])
            self._refresh_instances_list(wid)
        else:
            # Otherwise just clear the instances Treeview
            for row in self.tree_instances.get_children():
                self.tree_instances.delete(row)


    def _add_website_from_form(self):
        """
        Take the text from entry_new_site, insert it into the DB, then refresh
        both the top-left Treeview and the bottom-right Combobox.
        """
        name = self.entry_new_site.get().strip()
        if not name:
            messagebox.showwarning("Validation Error", "Website name cannot be empty.")
            return

        try:
            self.db.add_website(name)
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "This website already exists.")
            return
        except RuntimeError as e:
            messagebox.showerror("Database Error", str(e))
            return

        # Clear entry, then refresh
        self.entry_new_site.delete(0, tk.END)
        self._refresh_website_list()
        self._refresh_website_dropdown()


    def _add_instance_from_form(self):
        """
        Collect fields from the “Add Instance” form, insert a new row, then 
        clear the form and refresh instances if needed.
        """
        selection = self.var_site_dropdown.get().strip()
        if "-" not in selection:
            messagebox.showerror("Error", "Please select a valid website from the dropdown.")
            return

        website_id = int(selection.split(" - ")[0])
        url = self.entry_url.get().strip()
        username = self.entry_username.get().strip()
        email = self.entry_email.get().strip()
        password = self.entry_password.get().strip()

        #basic validation
        if not (url and username and email and password):
            messagebox.showwarning("Validation Error", "All fields must be filled in.")
            return

        try:
            self.db.add_instance(website_id, url, username, email, password)
        except RuntimeError as e:
            messagebox.showerror("Database Error", str(e))
            return

        # Clear the form fields
        self.entry_url.delete(0, tk.END)
        self.entry_username.delete(0, tk.END)
        self.entry_email.delete(0, tk.END)
        self.entry_password.delete(0, tk.END)

        messagebox.showinfo("Success", "Instance added successfully!")

        # If the instance belongs to the currently displayed website, refresh
        sel_site = self.tree_websites.focus()
        if sel_site and int(self.tree_websites.item(sel_site, "values")[0]) == website_id:
            self._refresh_instances_list(website_id)


    def _generate_password(self):
        """
        Query the AI model (via PasswordSuggester) to obtain a single, memorable password,
        then insert it into the password Entry widget.
        """
        # Disable the Generate button temporarily by finding it
        # We'll change the text to indicate “loading…”
        # (Simplest approach: search all children of the bottom‐right frame)
        brf = self.entry_password.master  # bottom_right_frame
        for child in brf.winfo_children():
            if isinstance(child, ttk.Button) and child.cget("text") == "Generate Password":
                child.config(state="disabled", text="Generating...")
                brf.update_idletasks()
                break

        try:
            new_pass = self.suggester.generate()
        except RuntimeError as e:
            messagebox.showerror("AI Error", f"Could not generate password:\n{e}")
            # Re-enable button
            child.config(state="normal", text="Generate Password")
            return

        # Insert the suggested password into the password field (overwriting whatever was there)
        self.entry_password.delete(0, tk.END)
        self.entry_password.insert(0, new_pass)

        # Re-enable the button
        child.config(state="normal", text="Generate Password")


    def _on_close(self):
        """
        Cleanly close the DB connection before quitting.
        """
        self.db.close()
        self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()
