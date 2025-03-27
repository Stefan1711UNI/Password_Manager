import sqlite3
import sys
import bcrypt

def main():
    if initialize_database():
        print("Database initialized")
        #get master password
        masterPassword = input("Enter the master password: ")
        #check if master password is correct
        #if so navigate to menu
        navigate_menu()
    else:
        sys.exit(1)


def initialize_database():
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
        return True
    except sqlite3.Error as e:
        print(f'Error: Could not connect to database. {e}')
        return False


#check if master password is correct
def check_masterPassword(masterPassword):
    pass


def navigate_menu():
    print("1. Add new instance")
    print("2. View all instances")
    print("3. Delete instance")
    print("4. Update instance")
    print("5. Exit")
    choice = input("Enter your choice: ")
    if choice == '1':
        add_instance()
    elif choice == '2':
        view_instances()
    # elif choice == '3':
    #     delete_instance()
    # elif choice == '4':
    #     update_instance()
    elif choice == '5':
        exit()
    else:
        print("Invalid choice")
        navigate_menu()


def add_instance():
    try:
        username = input("Enter username: ")
        email = input(print("Enter email: "))
        password = input("Enter password: ")
        db.execute('''INSERT INTO instances (username, email, password) VALUES (?, ?, ?)''', (username, email, password))
        connect.commit()
        print("Instance added successfully!!!")
    except sqlite3.Error as e:
        print(f"Error: Could not add instance. {e}")
    
    navigate_menu()
    

def view_instances():
    try:
        db.execute('''SELECT * FROM instances''')
        instances = db.fetchall()
        for instance in instances:
            print(f"ID: {instance[0]}")
            print(f"Username: {instance[1]}")
            print(f"Email: {instance[2]}")
            print(f"Password: {instance[3]}")
            print("-" * 50)
            print()
    except sqlite3.Error as e:
        print(f"Error: Could not view instances. {e}")
    
    navigate_menu()

main()