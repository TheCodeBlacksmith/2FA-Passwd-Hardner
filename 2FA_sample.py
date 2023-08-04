import os, subprocess
import sys
import crypt
import signal
from base64 import b64encode



def create_user(username:str, password:str, cnf_password:str, salt:str, intial_token:str):
    '''
    user requests an account
    '''    
    if not passwords_match(password, cnf_password):
        print("FALIURE: either passwd or token is incorrect")
        return

    hash = generate_password_hash(password, salt, intial_token)
    user_directory_interaction(username, 1, hash)
    password_directory_interaction(username, 1)
    print(f"SUCCESS: {username} created")   
#--------------------------------------------------------------------------------------------

def user_login(username:str, password:str, current_token:str, next_token:str):
    '''
    user requests to login
    '''
    salt = get_username_salt(username, password)
    current_pwd_hash = generate_password_hash(password, salt, current_token)
    user_authed = user_authenticated(username, current_pwd_hash)
    
    if user_authed:
        new_pwd_hash = generate_password_hash(password, salt, next_token)
        user_directory_interaction(username, 2, new_pwd_hash)
        print("SUCCESS: Login Successful")
#--------------------------------------------------------------------------------------------

def user_password_update(username:str, password:str, new_password:str, cnf_password:str, new_salt:str, current_token:str, next_token:str):
    '''
    user requests to update password
    '''
    if not passwords_match(new_password, cnf_password):
        print("FALIURE: either passwd or token is incorrect")
        return

    salt = get_username_salt(username, password)
    current_pwd_hash = generate_password_hash(password, salt, current_token)
    user_authed = user_authenticated(username, current_pwd_hash)

    if user_authed:
        new_pwd_hash = generate_password_hash(new_password, new_salt, next_token)
        user_directory_interaction(username, 2, new_pwd_hash)
        print(f"SUCCESS: user {username} updated")
#--------------------------------------------------------------------------------------------

def delete_user(username:str, password:str, current_token:str):
    '''
    user requests to be deleted
    '''
    salt = get_username_salt(username, password)
    current_pwd_hash = generate_password_hash(password, salt, current_token)
    user_authed = user_authenticated(username, current_pwd_hash)
    
    if user_authed:
        user_directory_interaction(username, 3, None)
        password_directory_interaction(username, 2)
        print(f"SUCCESS: user {username} Deleted")

#--------------------------------------------------------------------------------------------
def action_prompt() -> str:
    '''prompt for an action'''
    action = None
    while True:
        try:
            action = int(input("Select an action:\
            \n1) Create a user\
            \n2) Login\
            \n3) Update password\
            \n4) Delete user account\n"))

            if not (action >= 1 and action <= 4):
                #invalid input given
                continue
            else:
                #valid input given
                break
        except ValueError:
            #invalid input given
            continue
    return str(action)

def username_exists(username:str) -> bool:
    '''check if user already exists'''
    with open('/etc/shadow','r') as fp:         # Opening shadow file in read mode
        arr=[]
        for line in fp:                         # Enumerating through all the enteries in shadow file
            temp=line.split(':')
            if temp[0]==username:                  # checking whether entered username exist or not
                return True
    return False

def passwords_match(password:str, cnf_password:str) -> bool:
    '''check if password and cnf_password match'''
    return password == cnf_password

def user_authenticated(username:str, password_hash:str) -> bool:
    '''check if password and username match'''
    user_exists = False

    with open('/etc/shadow','r') as fp:	
        arr=[]
        for line in fp:                                 #Enumerating through all the enteries in shadow file
            temp=line.split(':')
            if temp[0] == username:                          #checking whether entered username exist or not
                user_exists = True
                if password_hash==temp[1]:                     #comparing generated salt with existing salt entery
                    return True
                else:
                    print("FALIURE: either passwd or token is incorrect")
                    return False
        
    if not user_exists:
        print(f"FALIURE: user {username} does not exist")    #if no user exist (technically this should not be hit since username validation is done earlier)
        return False
    return True

def get_username_salt(username:str, password:str) -> str:
    '''return salt of username's password or None'''
    user_exists = False

    with open('/etc/shadow','r') as fp:	
        arr=[]
        for line in fp:                                 #Enumerating through all the enteries in shadow file
            temp=line.split(':')
            if temp[0] == username:                          #checking whether entered username exist or not
                user_exists = True
                salt_and_pass=(temp[1].split('$'))      #retrieving salt against the user
                salt=salt_and_pass[2]
                return salt 
        
    if not user_exists:
        print(f"FALIURE: user {username} does not exist")    #if no user exist (technically this should not be hit since username validation is done earlier)
        return None
    return None

def generate_password_hash(password:str, salt:str, token:str):
    '''construct hash of password with whichever token and salt is provided
        for action #1: token is initial_token so hardened_password = (password + initial_token)
        for action #2 & #3: token is current_token so hardened_password = (password + current_token)
            or token could then be next_token so hardened_password = (password + next_token)
    '''
    password = password + salt # "salting" the password
    hardened_password = password + token
    hash=crypt.crypt(hardened_password,'$6$'+salt)         # generating hash | NOTE: 6 is SHA-512
    return hash

def user_directory_interaction(username:str, process_id:int, hash=None):
    '''interact with user directory (/etc/shadow) based on specified process_id:
    process_id = 1 : create user password directory
    process_id = 2 : update user password directory
    process_id = 3 : delete user password directory'''
    if process_id == 1: #create user password directory
        line = username + ':' + hash + ":17710:0:99999:7:::"
        shadow_file=open("/etc/shadow","a+")        # Opening shadow file in append+ mode
        shadow_file.write(line+'\n')			    # Making hash entry in the shadow file
        try:
            os.mkdir("/home/"+username)	            # Making home file for the user
        except:
            print("Directory: /home/"+username+" already exist")
        shadow_file.close()

    elif process_id == 2: #update user password directory
        new_line = username + ':' + hash + ":17710:0:99999:7:::" # create updated line for user in shadow file
        with open('/etc/shadow','r') as fp:
            idx = 0	
            for line in fp:                                 #Enumerating through all the enteries in shadow file
                temp=line.split(':')
                if temp[0] == username:                          #checking whether entered username exists on this line
                    break
                idx += 1

        data = None
        with open('/etc/shadow','r') as fp:                 # get all lines in shadow file
            data = fp.readlines()

        data[idx] = new_line+'\n'                               #update shadow file on this specific line

        with open('/etc/shadow', 'w') as fp:                #overwrite shadow file with updated lines
            fp.writelines(data)


    elif process_id == 3: #delete user password directory
        with open('/etc/shadow','r') as fp:
            idx = 0	
            for line in fp:                                 #Enumerating through all the enteries in shadow file
                temp=line.split(':')
                if temp[0] == username:                          #checking whether entered username exists on this line
                    break
                idx += 1

        data = None
        with open('/etc/shadow','r') as fp:                 # get all lines in shadow file
            data = fp.readlines()

        data.pop(idx)
        with open('/etc/shadow', 'w') as fp:                #overwrite shadow file with updated lines without the user line
            for line in data:
                fp.write(line)


def password_directory_interaction(username:str, process_id:int):
    '''interact with password directory (/etc/passwd) based on specified process_id:
    process_id = 1 : create user entry
    process_id = 2 : delete user entry'''
    if process_id == 1: #create user entry
        passwd_file=open("/etc/passwd","a+")		    # Opening passwd file in append+ mode
        
        count = 1000
        with open('/etc/passwd','r') as f:          # Opening passwd file in read mode
            arr1=[]
            for line in f:
                temp1=line.split(':')
                # checking number of existing UID
                while (int(temp1[3])>=count and int(temp1[3])<65534):
                    count=int(temp1[3])+1           # assigning new uid = 1000+number of UIDs +1

        count=str(count)	
        entry=username+':x:'+count+':'+count+':,,,:/home/'+username+':/bin/bash' 
        passwd_file.write(entry+'\n')                           # creating entry in passwd file for new user
        passwd_file.close()

    elif process_id == 2: #delete user entry
        with open('/etc/passwd','r') as fp:
            idx = 0	
            for line in fp:                                 #Enumerating through all the enteries in passwd file
                temp=line.split(':')
                if temp[0] == username:                          #checking whether entered username exists on this line
                    break
                idx += 1

        data = None
        with open('/etc/passwd','r') as fp:                 # get all lines in passwd file
            data = fp.readlines()

        data.pop(idx)
        with open('/etc/passwd', 'w') as fp:                #overwrite passwd file with updated lines without the user line
            for line in data:
                fp.write(line)

 #--------------------------------------------------------------------------------------------   

# Defining main function
if __name__=="__main__":
    #checking whether program is running as a root or not.
    if os.getuid()!=0:
        print("Please, run as root.")
        sys.exit()

    action = None
    action_success = False

    # list of potentiol values to be inputted
    username = None
    password = None
    new_password = None
    cnf_password = None
    salt = None
    new_salt = None
    intial_token = None
    current_token = None
    next_token = None

    action = action_prompt()
    if action == "1": #Create a user
        username = input("Username: ")
        password = input("Password: ")
        cnf_password = input("Confirm Password: ")
        salt = input("Salt: ")
        intial_token = input("Initial Token: ")

        #validate username does NOT exist:
        if username_exists(username):
            print(f"FAILURE: user {username} already exists")
            sys.exit()

        create_user(username, password, cnf_password, salt, intial_token) 
        
    elif action == "2": #Login
        username = input("Username: ")
        password = input("Password: ")
        current_token = input("Current Token: ")
        next_token = input("Next Token: ")
        
        #validate username does exist: 
        if not username_exists(username):
            print(f"FAILURE: user {username} does not exist")
            sys.exit()
            
        user_login(username, password, current_token, next_token)

    elif action == "3": #Update password
        username = input("Username: ")
        password = input("Password: ")
        new_password = input("New Password: ")
        cnf_password = input("Confirm New Password: ")
        new_salt = input("New Salt: ")
        current_token = input("Current Token: ")
        next_token = input("Next Token: ")

        #validate username does exist:
        if not username_exists(username):
            print(f"FAILURE: user {username} does not exist")
            sys.exit()

        user_password_update(username, password, new_password, cnf_password, new_salt, current_token, next_token)

    elif action == "4": # Delete user account
        username = input("Username: ")
        password = input("Password: ")
        current_token = input("Current Token: ") 

        #validate username does exist:
        if not username_exists(username):
            print(f"FAILURE: user {username} does not exist")
            sys.exit()

        delete_user(username, password, current_token)
    else:
        print("FAILURE: unknown error!")
        sys.exit()


    
