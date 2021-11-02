import csv
import random
import bcrypt
import re
import linecache
import itertools

#Initializing variables
usernameList = []
userIDList = []

#This method is the default screen a user will see, in which they will choose to log into an existing profile or create a new one.
def welcomeScreen():
    while True:
        print("Welcome to Medview Imaging\nMedical Information Management System\n----------------------------------------\nDo you have an existing profile?\nEnter 'y' for yes or 'n' for no\n\n")
        whatNext()
        break;

#This method is the default login page for a user
def profileLogin():
    print("\n\nMedview Imaging\nMedical Information Management System\n----------------------------------------")
    while True:
        username = input("Enter username: ")
        if(isUsernameInFile(username) or (username in usernameList)): #If username is found in file passwd.txt file database or usernameList then ask for password
            setUsername(username) #store username in global variable
            pw = input('Enter password: ')
            if(isLoginPasswordValid(pw) and (not isPasswordWeak(pw))):
                print("ACCESS GRANTED")
                displayUserInfo()
                break;
            else:
                print("Password invalid.\nEnter 'y' to try again\n----\nEnter 'n' to create a new profile\n----\nEnter 'q' to exit back to the main menu\n")
                whatNext()
            break;
        else:
            print("That username doesn't exist, perhaps you misspelt it?\n----\nEnter 'y' to try again\n----\nEnter 'n' to create a new profile\n----\nEnter 'q' to exit back to the main menu\n")
            whatNext()
            break;

#This method is a setter to set the username of an existing user who is logging in.
def setUsername(name):
    global profileUsername
    profileUsername = name

#This method is a getter which gets the username of the existing user.
def getUsername():
    return profileUsername

#This method creates a random ID for a new user. If the generated ID already exists, it will look for another.
def generateUserID():
    while True:
        newID = random.getrandbits(64)
        if newID not in userIDList:
            userIDList.append(newID)
            return newID
            break;
    
#This method walks the user through creating a new password
def newPassword():
    password = input("\nHi " + firstName + ", please create a new password for your account.\nPlease note that:\nPasswords must be least 8-12 characters in length\nPassword must include at least:\n\t– one upper-case letter;\n\t– one lower-case letter;\n\t– one numerical digit, and\n\t– one special character from the set: {!, @, #, $, %, ?, ∗}\n\n")
    uppercase, lowercase , digit, special = False, False, False, False
    #Used https://www.geeksforgeeks.org/python-program-check-string-contains-special-character/ for help when learning how to check for special characters
    regex = re.compile('[!@#$%?∗]')

    for elem in password:
        if elem.isupper():
            uppercase = True
        elif elem.islower():
            lowercase = True
        elif elem.isdigit():
            digit = True
        elif(not (regex.search(password) == None)):
            special = True

    while True:
        if((len(password) >= 8 and len(password) <= 12) and uppercase and lowercase and digit and special and (not isPasswordWeak(password))): #If all password conditions/requirements are True, then confirm password
            confirmPassword = input("\nPlease confirm the password you entered:\n\n")
            if(password == confirmPassword):
                print('\nPassword accepted.\n')
                assignRole() #assign role before hashing/saving password becasue role is required to save password
                hashPassword(confirmPassword)
                break;
            else:
                whatNext = input("The password you entered does not match the original, please try again. Enter 'exit' if you'd like to start over and create a different password\n")
                if(whatNext == "exit"): newPassword() #if user enters 'exit' they will create a new password
                break;
        else:
            print("Sorry, the password you entered does not meet the requiremnts. Please try again.\n")
            newPassword() #if user enters a weak password, they will have to create a new password
            break;

#This method looks for specific user input and executes a specific method depending on the input. These lines of code were present across different methods so I cleaned it up by making them a method.
def whatNext():
    while True:
        answer = input()
        if(answer == 'y'):
            profileLogin()
            break;
        elif(answer == 'n'):
            newUser()
            break;
        elif(answer == 'q'):
            print("\n")
            welcomeScreen()
            break;
        else:
            print("\nThat input is invalid.\nRedirecting you to the home screen...\n")
            welcomeScreen()
            break;

#This method is taken from my Problem1d.py with some minor changes: entering a role now appends that role to a user.
def assignRole():
    global userRole
    while True:
        roleName = input("\nWhat is the name of the role which you will be taking on here at Medview Imaging?\nThe valid roles are:\n'Radiologist', 'Physician', 'Nurse', 'Patient', 'Administrator', and 'Technical Support'\n\n")
        if(roleName.lower() == 'radiologist'):
            userRole = 'radiologist'
            break;
        elif(roleName.lower() == 'physician'):
            userRole = 'physician'
            break;
        elif(roleName.lower() == 'nurse'):
            userRole = 'nurse'
            break;
        elif(roleName.lower() == 'patient'):
            userRole = 'patient'
            break;
        elif(roleName.lower() == 'administrator'):
            userRole = 'administrator'
            break;
        elif(roleName.lower() == 'technical support'):
            userRole = 'technical support'
            break;
        else:
            print("\nThat input is not recognized, maybe you misspelled a word? Please try again.\n")

#This method adds a new record to the end of passwd.txt
def addNewRecord():
    newRecord = str(generateUserID()) + ":" + username + ":" + userRole + "\n"
    try:
        f = open("passwd.txt", "a") #Prepares file for data to be appended to the end of file
        f.write(newRecord) #Adds data to end of file
        f.close #Closes file

        hash = open("hashedPasswdOnly.txt", "ab") #Prepares second file for data to be appended to the end of file
        hash.write(pwHashed) #write binary hashed pw to second file
        hash.close #close file
        
        hash = open("hashedPasswdOnly.txt", "a") #Reopen second file in str mode to enter new line since I was unable to input new line in binary mode
        hash.write("\n") #Wrtie new line so records are properly formated
        hash.close #close file

        print("New user creation is complete, and records have been updated.\n")
    except Exception:
        print('There was an error adding the record to passwd.txt\n')

#This method checks the 2nd column of the passwd.txt file, delimited by :, and returns True if the inputted username is found in the file
def isUsernameInFile(username):
    global userIDList #make this list global since we will be using it in isLoginPasswordValid()
    with open ('passwd.txt', 'r') as f:
        first_column = [row[1] for row in csv.reader(f,delimiter=':')]
        userIDList = (first_column[0:]) #Stores all userIDs in this list
        if username in userIDList:
            return True
        else:
            return False

#This method is passed a password string as a parameter. It checks if the inputted password corresponding to the username is the same as the hashed password in the passwd.txt file database (aka checks if it is correct).
def isLoginPasswordValid(pw):
    usernameIndex = userIDList.index(getUsername()) #Find the index of the current user's username inside the passwd.txt file
    fullLine = linecache.getline(r"passwd.txt", usernameIndex+1) #Gets the full line from passwd.txt file specified by usernameIndex
    lineSplit = fullLine.split(':') #Splits the line contents delimited by ':' which is now stored in a list
    
    hashedPwLine = getHashedPassword(usernameIndex+1) #Gets the full line from hashedPasswdOnly.txt file specified by usernameIndex
    
    hashedPw = lineSplit[2] #Gets the hashed password from the usernameLine string above which is the 2nd index in the passwd.txt file. Since we are reading it from a file, it is in string form and we have to convert it to byte form later.
    
    try:
        if bcrypt.checkpw(bytes(pw, encoding = 'utf-8'), hashedPwLine):
            return True
        else:
            return False
    except Exception:
        print("There was an error verifying the password")

#This method hashes a password string passed as a parameter
def hashPassword(pw):
    global pwHashed #made gloabal since it will be used outside this method
    pwBytes = bytes(pw, encoding = 'utf-8') #Password in bytes
    userSalt = bcrypt.gensalt() #auto generated 32 byte salt
    pwHashed = bcrypt.hashpw(pwBytes, userSalt) #Hashed password
    addNewRecord()
    
def getHashedPassword(index):
    with open("hashedPasswdOnly.txt", "rb") as binary_file:
        content = binary_file.readlines()
        couple_bytes = content[index-1]
        couple_bytes = bytes(couple_bytes.decode('UTF-8').strip('\r\n'), encoding = 'UTF-8') #encode the decoded pw to compare later with original hashedPwLine
        
        return couple_bytes

def roleInfo(name):
    if(name.lower() == 'radiologist'):
        return(" You can radiologist can view a patient's profile, view and modify a patient's history, and view a patient's medical images.\n")
    elif(name.lower() == 'physician'):
        return(" You can view a patient's profile, view and modify a patient's history, and view a patient's medical images.\n")
    elif(name == "nurse"):
        return(" You can view a patient's profile, view a patient's history, and view a patient's medical images.\n")
    elif(name.lower() == 'patient'):
        return(" You can view their profile, view their history, and view their contact details.\n")
    elif(name.lower() == 'administrator'):
        return(" You can view and modify a patient's profile with access only from 9:00AM to 5:00PM\n")
    elif(name.lower() == 'technical support'):
        return(" You can view/run diagnostic tests on imaging units\n")
    else:
        return("\nThat role is not recognized. Please report this error to the developer.\n")

def displayUserInfo():
    usernameIndex = userIDList.index(getUsername()) #Find the index of the current user's username inside the passwd.txt file
    fullLine = linecache.getline(r"passwd.txt", usernameIndex+1) #Gets the full line from passwd.txt file specified by usernameIndex
    lineSplit = fullLine.split(':') #Splits the line contents delimited by ':' which is now stored in a list
    userID = lineSplit[0] #Gets user ID from passwd.txt file
    userRole = lineSplit[2] #Gets user role from passwd.txt file
    print("\nWelcome, below are your profile details.\n\nUser ID: " + userID + "\nRole: " + userRole + "\nRole Permission(s): " + roleInfo(str(userRole.strip("\n"))))

#This method enrolls users into the databse
def newUser():
    storeUsernames() #Stores usernames from file in list to see if the user inputted username is taken or not
    print("\n\nMedview Imaging\nNew User Profile:\n----------------------------------------\n")
    global firstName, username #Although global, these variables are solely used for the purpose of recording a new user. There are setters and getters to get the info of an existing user who is logging in.
    firstName = input("Please enter your first name:\n\n")
    while True:
        username = input("\nPlease enter the profile username of your preference:\n\n")
        if username not in usernameList:
            usernameList.append(username)
            break;
        else:
            ("This username is already taken, please enter a different username")
    newPassword()
    welcomeScreen()

#This method checks if the new user's password is amongst the top 200 most used password according to 2020 statistics, discovered from (https://github.com/danielmiessler/SecLists/blob/master/Passwords/2020-200_most_used_passwords.txt)
def isPasswordWeak(pw):
    weakPasswordList = ["123456", "123456789", "picture1", "password", "12345678", "111111", "123123", "12345", "1234567890", "senha", "1234567", "qwerty", "abc123", "Million2", "000000", "1234", "iloveyou", "aaron431", "password1", "qqww1122", "123", "omgpop", "123321", "654321", "qwertyuiop", "qwer123456", "123456a", "a123456", "666666", "asdfghjkl", "ashley", "987654321", "unknown", "zxcvbnm", "112233", "chatbooks", "20100728", "123123123", "princess", "jacket025", "evite", "123abc", "123qwe", "sunshine", "121212", "dragon", "1q2w3e4r", "5201314", "159753", "123456789", "pokemon", "qwerty123", "Bangbang123", "jobandtalent", "monkey", "1qaz2wsx", "abcd1234", "default", "aaaaaa", "soccer", "123654", "ohmnamah23", "12345678910", "zing", "shadow", "102030", "11111111", "asdfgh", "147258369", "qazwsx", "qwe123", "michael", "football", "baseball", "1q2w3e4r5t", "party", "daniel", "asdasd", "222222", "myspace1", "asd123", "555555", "a123456789", "888888", "7777777", "fuckyou", "1234qwer", "superman", "147258", "999999", "159357", "love123", "tigger", "purple", "samantha", "charlie", "babygirl", "88888888", "jordan23", "789456123", "jordan", "anhyeuem", "killer", "basketball", "michelle", "1q2w3e", "lol123", "qwerty1", "789456", "6655321", "nicole", "naruto", "master", "chocolate", "maggieown", "computer", "hannah", "jessica", "123456789a", "password123", "hunter", "686584", "iloveyou1", "987654321", "justin", "cookie", "hello", "blink182", "andrew", "25251325", "love", "987654", "bailey", "princess1", "123456", "101010", "12341234", "a801016", "1111", "1111111", "anthony", "yugioh", "fuckyou1", "amanda", "asdf1234", "trustno1", "butterfly", "x4ivygA51F", "iloveu", "batman", "starwars", "summer", "michael1", "00000000", "lovely", "jakcgt333", "buster", "jennifer", "babygirl1", "family", "456789", "azerty", "andrea", "q1w2e3r4", "qwer1234", "hello123", "10203", "matthew", "pepper", "12345a", "letmein", "joshua", "131313", "123456b", "madison", "Sample123", "777777", "football1", "jesus1", "taylor", "b123456", "whatever", "welcome", "ginger", "flower", "333333", "1111111111", "robert", "samsung", "a12345", "loveme", "gabriel", "alexander", "cheese", "passw0rd", "142536", "peanut", "11223344", "thomas", "angel1", "Password1", "Qwerty123", "Qaz123wsx"]

    for words in weakPasswordList:
        if pw == words or pw == getUserID:
            return True
        else:
            return False

def getUserID():
    usernameIndex = userIDList.index(getUsername()) #Find the index of the current user's username inside the passwd.txt file
    fullLine = linecache.getline(r"passwd.txt", usernameIndex+1) #Gets the full line from passwd.txt file specified by usernameIndex
    lineSplit = fullLine.split(':') #Splits the line contents delimited by ':' which is now stored in a list
    userID = lineSplit[0] #Gets user ID from passwd.txt file
    return userID

#This method stores usernames from passwd.txt file into usernameList
def storeUsernames():
    try:
        with open ('passwd.txt', 'r') as f:
            first_column = [row[1] for row in csv.reader(f,delimiter=':')]
            names = (first_column[0:]) #Stores all usernames in this list
            if names not in usernameList:
                usernameList.extend(names)
    except Exception:
        print("")

if __name__ == "__main__":
    welcomeScreen()