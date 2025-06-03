import sqlite3
import sys
import bcrypt
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

class PasswordManagerGUI:
    def __init__(self, master, db_name="dataBase.db"):
        self.master = master
        self.master.title("Password Manager")
        self.db_name = db_name

        # Initialize database
        self.connection = None
        self.cursor = None
        self._initialize_database()

        # Build a single‐window layout
        self._build_single_page_ui()

        # Load websites at startup
        self._refresh_website_list()
        self._refresh_website_dropdown()

        # Ensure clean exit
        self.master.protocol("WM_DELETE_WINDOW", self._on_close)

    def _initialize_database(self):
        """
        Connect to SQLite database and create tables if they don't exist.
        """
        try:
            self.connection = sqlite3.connect(self.db_name)
            self.cursor = self.connection.cursor()

            # Create Websites table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS Websites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE
                )
            ''')

            # Create Instances table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS Instances (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    website_id INTEGER NOT NULL,
                    url TEXT NOT NULL,
                    username TEXT NOT NULL,
                    email TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    FOREIGN KEY (website_id) REFERENCES Websites(id) ON DELETE CASCADE
                )
            ''')

            self.connection.commit()
            print("Database initialized successfully!")
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Could not initialize database:\n{e}")
            self.master.destroy()
            sys.exit(1)

    def _build_single_page_ui(self):
        """
        Construct a single‐window UI:
          - Top left: Websites Treeview
          - Top right: Instances Treeview + Delete button
          - Bottom left: Add Website form
          - Bottom right: Add Instance form
        """
        # Configure main grid
        self.master.rowconfigure(0, weight=3)   # Top half (Treeviews)
        self.master.rowconfigure(1, weight=2)   # Bottom half (Forms)
        self.master.columnconfigure(0, weight=1)
        self.master.columnconfigure(1, weight=1)

        # ─── Top Left ─── Websites List ─────
        top_left_frame = ttk.Frame(self.master, padding=10, relief="groove")
        top_left_frame.grid(row=0, column=0, sticky="nsew", padx=(10,5), pady=10)
        top_left_frame.columnconfigure(0, weight=1)
        top_left_frame.rowconfigure(1, weight=1)

        lbl_sites = ttk.Label(top_left_frame, text="Websites", font=("Segoe UI", 12, "bold"))
        lbl_sites.grid(row=0, column=0, sticky="w", pady=(0,5))

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

        vsb_sites = ttk.Scrollbar(top_left_frame, orient="vertical", command=self.tree_websites.yview)
        self.tree_websites.configure(yscrollcommand=vsb_sites.set)
        vsb_sites.grid(row=1, column=1, sticky="ns")

        # When a website is selected, refresh instances list
        self.tree_websites.bind("<<TreeviewSelect>>", self._on_website_select)

        # ─── Top Right ─── Instances List + Delete Button ─────
        top_right_frame = ttk.Frame(self.master, padding=10, relief="groove")
        top_right_frame.grid(row=0, column=1, sticky="nsew", padx=(5,10), pady=10)
        top_right_frame.columnconfigure(0, weight=1)
        top_right_frame.rowconfigure(1, weight=1)

        lbl_instances = ttk.Label(top_right_frame, text="Instances", font=("Segoe UI", 12, "bold"))
        lbl_instances.grid(row=0, column=0, sticky="w", pady=(0,5))

        self.tree_instances = ttk.Treeview(
            top_right_frame,
            columns=("ID", "URL", "Username", "Email", "Password Hash"),
            show="headings",
            selectmode="browse"
        )
        for col in ("ID", "URL", "Username", "Email", "Password Hash"):
            self.tree_instances.heading(col, text=col)
            anchor = "center" if col == "ID" else "w"
            width = 40 if col == "ID" else 120
            self.tree_instances.column(col, width=width, anchor=anchor)
        self.tree_instances.grid(row=1, column=0, sticky="nsew")

        vsb_instances = ttk.Scrollbar(top_right_frame, orient="vertical", command=self.tree_instances.yview)
        self.tree_instances.configure(yscrollcommand=vsb_instances.set)
        vsb_instances.grid(row=1, column=1, sticky="ns")

        # Delete Selected Instance button
        delete_inst_btn = ttk.Button(
            top_right_frame,
            text="Delete Selected Instance",
            command=self._delete_selected_instance
        )
        delete_inst_btn.grid(row=2, column=0, columnspan=2, pady=(10,0), sticky="ew")

        # ─── Bottom Left ─── Add Website Form ─────
        bottom_left_frame = ttk.Frame(self.master, padding=10, relief="groove")
        bottom_left_frame.grid(row=1, column=0, sticky="nsew", padx=(10,5), pady=(0,10))
        bottom_left_frame.columnconfigure(1, weight=1)

        lbl_add_site = ttk.Label(bottom_left_frame, text="Add New Website", font=("Segoe UI", 11, "bold"))
        lbl_add_site.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0,5))

        ttk.Label(bottom_left_frame, text="Website Name:").grid(row=1, column=0, sticky="w", pady=5, padx=(0,5))
        self.entry_new_site = ttk.Entry(bottom_left_frame)
        self.entry_new_site.grid(row=1, column=1, sticky="ew", pady=5)

        add_site_btn = ttk.Button(
            bottom_left_frame,
            text="Add Website",
            command=self._add_website_from_form
        )
        add_site_btn.grid(row=2, column=0, columnspan=2, pady=(10,0), sticky="ew")

        # ─── Bottom Right ─── Add Instance Form ─────
        bottom_right_frame = ttk.Frame(self.master, padding=10, relief="groove")
        bottom_right_frame.grid(row=1, column=1, sticky="nsew", padx=(5,10), pady=(0,10))
        for i in range(2):
            bottom_right_frame.columnconfigure(i, weight=1)

        lbl_add_inst = ttk.Label(bottom_right_frame, text="Add New Instance", font=("Segoe UI", 11, "bold"))
        lbl_add_inst.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0,5))

        # Website dropdown (Combobox)
        ttk.Label(bottom_right_frame, text="Select Website:").grid(row=1, column=0, sticky="w", pady=5, padx=(0,5))
        self.var_site_dropdown = tk.StringVar()
        self.cmb_sites = ttk.Combobox(
            bottom_right_frame,
            textvariable=self.var_site_dropdown,
            state="readonly"
        )
        self.cmb_sites.grid(row=1, column=1, sticky="ew", pady=5)

        # URL
        ttk.Label(bottom_right_frame, text="URL:").grid(row=2, column=0, sticky="w", pady=5, padx=(0,5))
        self.entry_url = ttk.Entry(bottom_right_frame)
        self.entry_url.grid(row=2, column=1, sticky="ew", pady=5)

        # Username
        ttk.Label(bottom_right_frame, text="Username:").grid(row=3, column=0, sticky="w", pady=5, padx=(0,5))
        self.entry_username = ttk.Entry(bottom_right_frame)
        self.entry_username.grid(row=3, column=1, sticky="ew", pady=5)

        # Email
        ttk.Label(bottom_right_frame, text="Email:").grid(row=4, column=0, sticky="w", pady=5, padx=(0,5))
        self.entry_email = ttk.Entry(bottom_right_frame)
        self.entry_email.grid(row=4, column=1, sticky="ew", pady=5)

        # Password (masked)
        ttk.Label(bottom_right_frame, text="Password:").grid(row=5, column=0, sticky="w", pady=5, padx=(0,5))
        self.entry_password = ttk.Entry(bottom_right_frame, show="*")
        self.entry_password.grid(row=5, column=1, sticky="ew", pady=5)

        add_inst_btn = ttk.Button(
            bottom_right_frame,
            text="Add Instance",
            command=self._add_instance_from_form
        )
        add_inst_btn.grid(row=6, column=0, columnspan=2, pady=(10,0), sticky="ew")

    def _refresh_website_list(self):
        """
        Fetch all websites from DB and populate the top‐left Treeview.
        """
        for row in self.tree_websites.get_children():
            self.tree_websites.delete(row)

        try:
            self.cursor.execute("SELECT id, name FROM Websites ORDER BY name ASC")
            rows = self.cursor.fetchall()
            for wid, name in rows:
                self.tree_websites.insert("", "end", values=(wid, name))
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"Could not retrieve websites:\n{e}")

    def _refresh_website_dropdown(self):
        """
        Populate the Combobox in the "Add Instance" form with "id – name" entries.
        """
        try:
            self.cursor.execute("SELECT id, name FROM Websites ORDER BY name ASC")
            rows = self.cursor.fetchall()
            display_values = [f"{wid} - {wname}" for (wid, wname) in rows]
            self.cmb_sites['values'] = display_values
            if display_values:
                self.cmb_sites.current(0)
            else:
                self.cmb_sites.set("")  # no selection if empty
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"Could not load websites for dropdown:\n{e}")

    def _on_website_select(self, event):
        """
        Called when a website is selected in the left Treeview.
        Refresh the right Treeview to show its instances.
        """
        selected = self.tree_websites.focus()
        if not selected:
            return

        wid, wname = self.tree_websites.item(selected, "values")
        self._refresh_instances_list(website_id=int(wid))

    def _refresh_instances_list(self, website_id):
        """
        Given a website_id, fetch its instances and populate the top‐right Treeview.
        """
        for row in self.tree_instances.get_children():
            self.tree_instances.delete(row)

        try:
            self.cursor.execute(
                "SELECT id, url, username, email, password_hash FROM Instances WHERE website_id = ?",
                (website_id,)
            )
            rows = self.cursor.fetchall()
            for inst in rows:
                self.tree_instances.insert("", "end", values=inst)
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"Could not retrieve instances:\n{e}")

    def _delete_selected_instance(self):
        """
        Delete whatever instance is currently highlighted in the instances Treeview.
        """
        selected = self.tree_instances.focus()
        if not selected:
            messagebox.showwarning("Selection Error", "Please select an instance to delete.")
            return

        inst_id = self.tree_instances.item(selected, "values")[0]
        confirm = messagebox.askyesno("Confirm Deletion", "Are you sure you want to delete this instance?")
        if not confirm:
            return

        try:
            self.cursor.execute("DELETE FROM Instances WHERE id = ?", (inst_id,))
            self.connection.commit()
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"Could not delete instance:\n{e}")
            return

        # After deletion, refresh the instances list for the currently selected website (if any)
        sel_site = self.tree_websites.focus()
        if sel_site:
            wid = int(self.tree_websites.item(sel_site, "values")[0])
            self._refresh_instances_list(wid)
        else:
            # If no website is selected, just clear the instances list
            for row in self.tree_instances.get_children():
                self.tree_instances.delete(row)

    def _add_website_from_form(self):
        """
        Read the "New Website" entry, insert into DB, and refresh.
        """
        name = self.entry_new_site.get().strip()
        if not name:
            messagebox.showwarning("Validation Error", "Website name cannot be empty.")
            return

        try:
            self.cursor.execute("INSERT INTO Websites (name) VALUES (?)", (name,))
            self.connection.commit()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "This website already exists.")
            return
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Could not add website:\n{e}")
            return

        # Clear the entry, then refresh both website list and dropdown
        self.entry_new_site.delete(0, tk.END)
        self._refresh_website_list()
        self._refresh_website_dropdown()

    def _add_instance_from_form(self):
        """
        Read all fields in the "Add Instance" form, hash the password, insert into DB, and refresh.
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

        # Basic validation
        if not (url and username and email and password):
            messagebox.showwarning("Validation Error", "All fields must be filled in.")
            return

        # Generate salt & hash
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode("utf-8"), salt)

        try:
            self.cursor.execute(
                '''
                INSERT INTO Instances 
                (website_id, url, username, email, password_hash, salt)
                VALUES (?, ?, ?, ?, ?, ?)
                ''',
                (
                    website_id,
                    url,
                    username,
                    email,
                    password_hash.decode("utf-8"),
                    salt.decode("utf-8")
                )
            )
            self.connection.commit()
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Could not add instance:\n{e}")
            return

        # Clear the form fields
        self.entry_url.delete(0, tk.END)
        self.entry_username.delete(0, tk.END)
        self.entry_email.delete(0, tk.END)
        self.entry_password.delete(0, tk.END)

        messagebox.showinfo("Success", "Instance added successfully!")

        # If the newly added instance belongs to the currently selected website, refresh
        sel_site = self.tree_websites.focus()
        if sel_site and int(self.tree_websites.item(sel_site, "values")[0]) == website_id:
            self._refresh_instances_list(website_id)

    def _on_close(self):
        """
        Clean up DB connection before quitting.
        """
        if self.connection:
            self.connection.close()
        self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()
