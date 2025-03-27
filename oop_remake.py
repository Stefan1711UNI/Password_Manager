import sqlite3
import sys
import bcrypt

class PasswordManager:
    def __init__(self, db_name="dataBase.db"):
        self.db_name = db_name
        self.connection = None
        self.cursor = None
        self.initialize_database()

    def initialize_database(self):
        global connect, db
        try:
            connect = sqlite3.connect('dataBase.db')
            db = connect.cursor()
            db.execute('''CREATE TABLE IF NOT EXISTS instances (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL,
                            email TEXT NOT NULL,
                            password TEXT NOT NULL)''')
            connect.commit()
            print('Database connected')
        except sqlite3.Error as e:
            print(f'Error: Could not connect to database. {e}')
            sys.exit(1)


    def add_instance(self):
        try:
            username = input("Enter username: ")
            email = input(print("Enter email: "))
            password = input("Enter password: ")
            db.execute('''INSERT INTO instances (username, email, password) VALUES (?, ?, ?)''', (username, email, password))
            connect.commit()
            print("Instance added successfully!!!")
        except sqlite3.Error as e:
            print(f"Error: Could not add instance. {e}")

        self.navigate_menu()
    

    def view_instances(self):
        try:
            db.execute('''SELECT * FROM instances''')
            instances = db.fetchall()
            for instance in instances:
                print("")
                print("-" * 50)
                print(f"ID: {instance[0]}")
                print(f"Username: {instance[1]}")
                print(f"Email: {instance[2]}")
                print(f"Password: {instance[3]}")
                print("-" * 50)
                print("")
            while True:
                if input("Enter 'q' to quit: ").lower() == "q":
                    self.navigate_menu()
        except sqlite3.Error as e:
            print(f"Error: Could not view instances. {e}")

        


    #check if master password is correct
    def check_masterPassword(self, masterPassword):
        pass


    def navigate_menu(self):
        print("1. Add new instance")
        print("2. View all instances")
        print("3. Delete instance")
        print("4. Update instance")
        print("5. Exit")
        print("")
        choice = input("Enter your choice: ")
        if choice == '1':
            self.add_instance()
        elif choice == '2':
            self.view_instances()
        # elif choice == '3':
        #     delete_instance()
        # elif choice == '4':
        #     update_instance()
        elif choice == '5':
            exit()
        else:
            print("Invalid choice")
            self.navigate_menu()


if __name__ == "__main__":
    manager = PasswordManager()
    manager.navigate_menu()