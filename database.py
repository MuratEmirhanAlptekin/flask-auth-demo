import bcrypt
import re
import os
from dotenv import load_dotenv
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import uuid

load_dotenv()
user = os.getenv('db_user')
password = os.getenv('db_passw')
hostname = os.getenv('db_hostname')
database_name = os.getenv('db_name')
sql_engine = create_engine(f'postgresql+psycopg2://{user}:{password}@{hostname}/{database_name}')
Base = declarative_base()
Session = sessionmaker(bind=sql_engine)
session = Session()
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    public_id = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)

Base.metadata.create_all(sql_engine)
#dont do this in prod


def check_passw_regex(passw):
    regex_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$"
    return bool(re.match(regex_pattern, passw))

def check_mail_regex(email):
    regex_pattern = r"^\S+@\S+\.\S+$"
    return bool(re.match(regex_pattern, email))

def authenticate_user(email, password):
    # Query the user based on the email
    user = session.query(User).filter_by(email=email).first()
    hashed_pw_from_db = user.hashed_password
    pw_bytes = bytes.fromhex(hashed_pw_from_db[2:])


    if user:

        if bcrypt.checkpw(password.encode('utf-8'), pw_bytes):
            return user  # Authentication successful
        else:
            return None  # Password mismatch
    else:
        return None  # User not found

def register_user(email, password):
    #check if password or email is valid
    if not (check_passw_regex(password) and check_mail_regex(email)):
        return "invalid password or email"
    # Check if the user already exists
    existing_mail = session.query(User).filter_by(email=email).first()
    # todo check the mail pattern if it is a valid mail do this also for password
    
    if existing_mail:
        return "email already exists bozo"
    
    salt = bcrypt.gensalt()
    encoded_pw = password.encode('utf-8')
    hashed_password = bcrypt.hashpw(encoded_pw, salt)

    # Create a new user
    new_user = User(public_id=str(uuid.uuid4()),email=email, hashed_password=hashed_password)
    session.add(new_user)
    session.commit()
    
    return "Registration successful"


