import sqlite3
from sqlite3 import Error
import bcrypt

def create_connection():
    db_file = "user_database/freshspace_messaging.db"
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Error as e:
        print(e)

    return conn

"""Take a password and return the hashed password"""
def hash_password(password):
    hashed = bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
    return hashed

''' Check if the password given matches the one in the database'''
def check_password(password, hashed):
    if bcrypt.checkpw(password, hashed):
        return True
    else:
        return False

''' Create a new user by adding their username and 
 password to the database'''
def create_user(username, password):

    conn = create_connection()
    cursor = conn.cursor()
    ## Check if the username exists in the database
    # query = "SELECT username FROM users WHERE username LIKE ?;", (username)
    cursor.execute("SELECT username FROM users WHERE username LIKE ?;", (username,))
    if len(cursor.fetchall()) != 0:
        ## Username exists in the database
        cursor.close()
        conn.close()
        return False
    else:
        password = hash_password(password).decode()
        # query = "INSERT INTO users VALUES (?,?);", (username, password)
        cursor.execute("INSERT INTO users VALUES (?,?)", (username, password))
        conn.commit()
        cursor.close()
        conn.close()
        return True

''' Check if a user exists in the database '''
def check_user(username, password):

    conn = create_connection()
    cursor = conn.cursor()
    ## Check if the username is in the db
    # query = "SELECT password FROM users WHERE username LIKE ?", (username)
    cursor.execute("SELECT password FROM users WHERE username LIKE ?", (username,))

    results = cursor.fetchall()
    ## Username not in the db
    if len(results) == 0:
        return 0
    
    ## Check if the passwords match
    db_passwd = results[0][0]
    if check_password(password.encode('utf-8'), db_passwd.encode('utf-8')):
        return 1
    else:
        return 2

''' Delete a user's accouont '''
def delete_user(username):
  conn = create_connection()
  cursor = conn.cursor()

  try:
    cursor.execute("DELETE FROM users WHERE username LIKE ?", (username,))
    conn.commit()
  except sqlite3.Error as e:
    print('SQL Deletion error: %s' % (' '.join(e.args)))
    cursor.close()
    conn.close()
    return False
  cursor.close()
  conn.close()
  return True
'''
add message in the database
return True if succeed; if fails, return False
'''
def add_history(user1, user2, msg):
  conn = create_connection()
  cursor = conn.cursor()

  ## Insert the message history into the db
  # query = "INSERT INTO history (user1, user2, msg) VALUES (?, ?, ?);", (user1, user2, msg)
  try:
    cursor.execute("INSERT INTO history (user1, user2, msg) VALUES (?, ?, ?);", (user1, user2, msg))
    conn.commit()
  except sqlite3.Error as e:
    print('SQL insertion error: %s' % (' '.join(e.args)))
    cursor.close()
    conn.close()
    return False
  else:
    cursor.close()
    conn.close()
    return True

'''
return all history row between user1 and user2
Return: list of tuples (m_id:int, user1:text, user2:text, msg:text, ts:text)
Return value example: [(1, 'Alice' , 'Bob', 'msg','2021-12-06 06:07:28' )] 
'''
def show_history(user1, user2):
  conn = create_connection()
  cursor = conn.cursor()
  
  ## Check if the username is in the db
  # query = "SELECT * FROM history WHERE (user1=? AND user2=?) OR (user1=? AND user2=?);", (user1, user2, user1, user2)
  
  try:
    cursor.execute("SELECT * FROM history WHERE (user1=? AND user2=?) OR (user1=? AND user2=?);", (user1, user2, user2, user1))
    results = cursor.fetchall()

    #     cursor.execute("SELECT * FROM history WHERE (user1=? AND user2=?);", (user1, user2))
    # results = cursor.fetchall()
    # cursor.execute("SELECT * FROM history WHERE (user1=? AND user2=?);", (user2, user1))
    # results = results + cursor.fetchall()
  except sqlite3.Error as e:
    print('SQL insertion error: %s' % (' '.join(e.args)))
  
  cursor.close()
  conn.close()
  return results

'''
delete chat log in db
return True if succeed; if fail, return False
'''
def delete_history(user1, user2):
  conn = create_connection()
  cursor = conn.cursor()

  try:
    cursor.execute("DELETE FROM history WHERE (user1=? AND user2=?) OR (user1=? AND user2=?);", (user1, user2, user2, user1))
    conn.commit()
  
  except sqlite3.Error as e:
    print('SQL insertion error: %s' % (' '.join(e.args)))
    cursor.close()
    conn.close()
    return False
  else:
    cursor.close()
    conn.close()
    return True
    



