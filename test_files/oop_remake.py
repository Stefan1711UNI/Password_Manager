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
            #Websites table
            db.execute('''CREATE TABLE IF NOT EXISTS Websites (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT NOT NULL UNIQUE
                        )''')

            #Instances table, foreign key referes to Websites id
            db.execute('''CREATE TABLE IF NOT EXISTS Instances (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            website_id INTEGER NOT NULL,
                            url TEXT NOT NULL,
                            username TEXT NOT NULL,
                            email TEXT NOT NULL,
                            password_hash TEXT NOT NULL,
                            salt TEXT NOT NULL,
                            FOREIGN KEY (website_id) REFERENCES Websites(id) ON DELETE CASCADE
                        )''')
            connect.commit()
            print('Database intialized succesfully!')

        except sqlite3.Error as e:
            print(f'Error: Could not initialize database. {e}')
            sys.exit(1)


    def add_instance(self):
        try:
            #website id gotten from function
            website_id = self.find_websiteid_from_str(input("Enter website name: "))
            username = input("Enter username: ")
            email = input("Enter email: ")
            password = input("Enter password: ")    #then gets hashed and that gets stored
            url = input("Enter URL: ")
            #get salt 
            #check if website exits and add if not
            db.execute('''INSERT INTO Instances (website_id, url, username, email, password_hash, salt) VALUES (?, ?, ?, ?, ?, ?)''', 
                       (website_id, url, username, email, password, "salt"))
            connect.commit()
            print("Instance added successfully!!!")
        except sqlite3.Error as e:
            print(f"Error: Could not add instance. {e}")

        self.navigate_menu()


    def find_websiteid_from_str(self, user_input):
        str_website = user_input.strip()
        websites = self.get_websites()
        for website in websites:
            website_id, website_name = website
            if str_website.lower() == website_name.lower():
                return website_id
    
        #add website since none exist
        return self.add_website(str_website)
            
        
    

    def add_website(self, website_name):
        try:
            db.execute('''INSERT INTO Websites (name) VALUES (?)''', (website_name,))
            connect.commit()
            db.execute('''SELECT id FROM Websites WHERE name = (?) ''', (website_name,))
            website_id = db.fetchone()
            if website_id:
                return website_id[0]
            else:
                print("Error: Failed to retrieve new website ID.")
                return None
        except sqlite3.Error as e:
            self.navigate_menu()
            print(f"Error: Could not add website. {e}")
            


    def view_websites(self):
        try:
            websites = self.get_websites()
            for website in websites:
                print("-" * 50)
                print(f"{website[0]}: Name: {website[1]}")
                print("-" * 50)
                print("")
            #change
            print("Enter website ID to see it's instances.")
            while True:
                user_input = int(input("Enter website ID: "))
                if user_input < 1 or user_input > len(websites):
                    print("Invalid website ID!")
                else:
                    self.view_instances(user_input)
        except sqlite3.Error as e:
            print(f"Error: Could not view websites. {e}")
        

    def get_websites(self):
        db.execute('''Select * FROM Websites ORDER BY name ASC''')
        websites = db.fetchall()
        lst = []
        for website in websites:
            lst.append(website)
        return lst

    def view_instances(self, website_id):
        try:
            db.execute('''SELECT * FROM Instances WHERE website_id = (?)''', (website_id,))
            instances = db.fetchall()
            for instance in instances:
                print("-" * 50)
                print(f"ID: {instance[0]}")
                print(f"Username: {instance[3]}")
                print(f"Email: {instance[4]}")
                print(f"Password: {instance[5]}")
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
        print("")
        print("1. Add new instance")
        print("2. View all instances")
        print("3. Update instance")
        print("4. Delete instance")
        print("5. Exit")
        print("")
        choice = input("Enter your choice: ")
        if choice == '1':
            self.add_instance()
        elif choice == '2':
            self.view_websites()
        # elif choice == '3':
        #     update_instance()
        # elif choice == '4':
        #     delete_instance()
        elif choice == '5':
            exit()
        else:
            print("Invalid choice")
            self.navigate_menu()


if __name__ == "__main__":
    manager = PasswordManager()
    manager.navigate_menu()