import sqlite3
import sys
import bcrypt
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox


class PasswordManagerDB:
    """
    Encapsulates all database operations for the password manager.
    Responsibilities:
      - Connect to SQLite (or create it)
      - Create tables if they do not exist
      - Provide CRUD methods for Websites and Instances
      - Cleanly close the connection
    """

    def __init__(self, db_name="dataBase.db"):
        self.db_name = db_name
        self.connection = None
        self.cursor = None
        self._connect_and_initialize()

    def _connect_and_initialize(self):
        """
        Connect to the SQLite database file and create required tables if absent.
        """
        try:
            self.connection = sqlite3.connect(self.db_name)
            self.cursor = self.connection.cursor()

            # Create Websites table (id, name)
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS Websites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE
                )
            ''')

            # Create Instances table (id, website_id, url, username, email, password_hash, salt)
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
        except sqlite3.Error as e:
            # If initialization fails, we cannot proceed
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
          - sqlite3.IntegrityError if name already exists
          - sqlite3.Error for other failures
        Returns:
          - The newly generated website_id (int)
        """
        try:
            self.cursor.execute("INSERT INTO Websites (name) VALUES (?)", (website_name,))
            self.connection.commit()
            return self.cursor.lastrowid
        except sqlite3.IntegrityError:
            raise  # propagate so GUI can catch and display “already exists”
        except sqlite3.Error as e:
            raise RuntimeError(f"Could not add website: {e}")

    def get_instances_for_website(self, website_id):
        """
        Return a list of rows (id, url, username, email, password_hash) for a given website_id.
        """
        try:
            self.cursor.execute(
                "SELECT id, url, username, email, password_hash "
                "FROM Instances WHERE website_id = ?", (website_id,)
            )
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            raise RuntimeError(f"Could not fetch instances: {e}")

    def add_instance(self, website_id, url, username, email, raw_password):
        """
        Hash the raw_password with bcrypt, then insert a new Instance row.
        Returns:
          - The newly generated instance_id (int)
        Raises:
          - sqlite3.Error if insertion fails
        """
        # Generate salt & hash
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(raw_password.encode("utf-8"), salt)
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
            return self.cursor.lastrowid
        except sqlite3.Error as e:
            raise RuntimeError(f"Could not add instance: {e}")

    def delete_instance(self, instance_id):
        """
        Delete the row from Instances where id = instance_id.
        Raises:
          - sqlite3.Error if deletion fails
        """
        try:
            self.cursor.execute("DELETE FROM Instances WHERE id = ?", (instance_id,))
            self.connection.commit()
        except sqlite3.Error as e:
            raise RuntimeError(f"Could not delete instance: {e}")

    def close(self):
        """
        Close the SQLite connection.
        """
        if self.connection:
            self.connection.close()


class PasswordManagerGUI:
    """
    All GUI logic lives here. This class holds a reference to PasswordManagerDB
    and delegates every data operation to that DB instance.
    The layout is unchanged: a single window divided into four areas:
      - Top‐left: Websites List
      - Top‐right: Instances List + Delete button
      - Bottom‐left: Add Website form
      - Bottom‐right: Add Instance form
    """

    def __init__(self, master, db_name="dataBase.db"):
        self.master = master
        self.master.title("Password Manager")
        self.master.geometry("800x600")  # A reasonable default window size

        # Instantiate the database layer
        try:
            self.db = PasswordManagerDB(db_name=db_name)
        except RuntimeError as e:
            messagebox.showerror("Database Error", str(e))
            self.master.destroy()
            sys.exit(1)

        # Build UI elements (frames, Treeviews, forms)
        self._build_single_page_ui()

        # Initial population of data
        self._refresh_website_list()
        self._refresh_website_dropdown()

        # Ensure DB connection is closed when window is closed
        self.master.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_single_page_ui(self):
        # Configure main grid (two rows, two columns)
        self.master.rowconfigure(0, weight=3)   # Top: Treeviews
        self.master.rowconfigure(1, weight=2)   # Bottom: Forms
        self.master.columnconfigure(0, weight=1)
        self.master.columnconfigure(1, weight=1)

        # ─── Top Left: Websites List ───────────────────────────────
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

        vsb_sites = ttk.Scrollbar(top_left_frame, orient="vertical", command=self.tree_websites.yview)
        self.tree_websites.configure(yscrollcommand=vsb_sites.set)
        vsb_sites.grid(row=1, column=1, sticky="ns")

        # When a website is selected, refresh instances list
        self.tree_websites.bind("<<TreeviewSelect>>", self._on_website_select)

        # ─── Top Right: Instances List + Delete Button ─────────────
        top_right_frame = ttk.Frame(self.master, padding=10, relief="groove")
        top_right_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 10), pady=10)
        top_right_frame.columnconfigure(0, weight=1)
        top_right_frame.rowconfigure(1, weight=1)

        lbl_instances = ttk.Label(top_right_frame, text="Instances", font=("Segoe UI", 12, "bold"))
        lbl_instances.grid(row=0, column=0, sticky="w", pady=(0, 5))

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

        delete_inst_btn = ttk.Button(
            top_right_frame,
            text="Delete Selected Instance",
            command=self._delete_selected_instance
        )
        delete_inst_btn.grid(row=2, column=0, columnspan=2, pady=(10, 0), sticky="ew")

        # ─── Bottom Left: Add Website Form ─────────────────────────
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

        # ─── Bottom Right: Add Instance Form ───────────────────────
        bottom_right_frame = ttk.Frame(self.master, padding=10, relief="groove")
        bottom_right_frame.grid(row=1, column=1, sticky="nsew", padx=(5, 10), pady=(0, 10))
        bottom_right_frame.columnconfigure(0, weight=1)
        bottom_right_frame.columnconfigure(1, weight=1)

        lbl_add_inst = ttk.Label(bottom_right_frame, text="Add New Instance", font=("Segoe UI", 11, "bold"))
        lbl_add_inst.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 5))

        # Website dropdown (Combobox)
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

        # URL
        ttk.Label(bottom_right_frame, text="URL:").grid(
            row=2, column=0, sticky="w", pady=5, padx=(0, 5)
        )
        self.entry_url = ttk.Entry(bottom_right_frame)
        self.entry_url.grid(row=2, column=1, sticky="ew", pady=5)

        # Username
        ttk.Label(bottom_right_frame, text="Username:").grid(
            row=3, column=0, sticky="w", pady=5, padx=(0, 5)
        )
        self.entry_username = ttk.Entry(bottom_right_frame)
        self.entry_username.grid(row=3, column=1, sticky="ew", pady=5)

        # Email
        ttk.Label(bottom_right_frame, text="Email:").grid(
            row=4, column=0, sticky="w", pady=5, padx=(0, 5)
        )
        self.entry_email = ttk.Entry(bottom_right_frame)
        self.entry_email.grid(row=4, column=1, sticky="ew", pady=5)

        # Password (masked)
        ttk.Label(bottom_right_frame, text="Password:").grid(
            row=5, column=0, sticky="w", pady=5, padx=(0, 5)
        )
        self.entry_password = ttk.Entry(bottom_right_frame, show="*")
        self.entry_password.grid(row=5, column=1, sticky="ew", pady=5)

        add_inst_btn = ttk.Button(
            bottom_right_frame,
            text="Add Instance",
            command=self._add_instance_from_form
        )
        add_inst_btn.grid(row=6, column=0, columnspan=2, pady=(10, 0), sticky="ew")

    def _refresh_website_list(self):
        """
        Clear and repopulate the top‐left Treeview from the database.
        """
        # Clear existing rows
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
        Populate the bottom‐right Combobox with "id - name" for each website.
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
        Called whenever the user selects a website in the top‐left Treeview.
        Fetch and display its instances in the top‐right Treeview.
        """
        selected = self.tree_websites.focus()
        if not selected:
            return

        wid = int(self.tree_websites.item(selected, "values")[0])
        self._refresh_instances_list(website_id=wid)

    def _refresh_instances_list(self, website_id):
        """
        Clear and repopulate the top‐right Treeview with instances for website_id.
        """
        for row in self.tree_instances.get_children():
            self.tree_instances.delete(row)

        try:
            instances = self.db.get_instances_for_website(website_id)
            for inst in instances:
                # inst is a tuple: (id, url, username, email, password_hash)
                self.tree_instances.insert("", "end", values=inst)
        except RuntimeError as e:
            messagebox.showerror("Error", str(e))

    def _delete_selected_instance(self):
        """
        Delete whichever instance is highlighted in the top‐right Treeview,
        then refresh that list.
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

        # If a website is still selected, refresh its instances
        sel_site = self.tree_websites.focus()
        if sel_site:
            wid = int(self.tree_websites.item(sel_site, "values")[0])
            self._refresh_instances_list(wid)
        else:
            # Otherwise just clear the instances Treeview
            for row in self.tree_instances.get_children():
                self.tree_instances.delete(row)

    def _add_website_from_form(self):
        """
        Take the text from entry_new_site, insert into DB, and refresh both list + dropdown.
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

        # Clear the entry, then refresh both the Treeview and the dropdown
        self.entry_new_site.delete(0, tk.END)
        self._refresh_website_list()
        self._refresh_website_dropdown()

    def _add_instance_from_form(self):
        """
        Collect all fields for a new instance, hash the password, insert into DB,
        then clear the form and refresh instances if needed.
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

        # If the instance belongs to the currently selected website, refresh its instances
        sel_site = self.tree_websites.focus()
        if sel_site and int(self.tree_websites.item(sel_site, "values")[0]) == website_id:
            self._refresh_instances_list(website_id)

    def _on_close(self):
        """
        Cleanly close the DB connection before quitting the application.
        """
        self.db.close()
        self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()
