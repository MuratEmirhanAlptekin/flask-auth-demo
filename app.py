import jwt
import datetime
from flask import Flask, render_template_string, request, session, redirect,jsonify,make_response
from database import authenticate_user,register_user,session, User
from functools import wraps

# Create the Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'very-secret-key'

def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
           token = request.headers['x-access-tokens']
 
        if not token:
           return jsonify({'message': 'a valid token is missing'})
        try:
           data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
           current_user = session.query(User).filter_by(public_id=data['public_id']).first()
           # if exp is smaller than current timestamp token is invalid
        except:
            return jsonify({'message': 'token is invalid'})
 
        return f(current_user, *args, **kwargs)
   return decorator


@app.route('/register', methods=['GET', 'POST'])
def signup_user():
    if request.method == 'POST':
        data = request.get_json() 
        email = data['email_address']
        passw = data['password']
        message = register_user(email,passw)
        return message
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() 
        email = data['email_address']
        passw = data['password']
        user = authenticate_user(email,passw)  
        if user is not None:
            token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
            return jsonify({'token' : token})
 
        return make_response('could not verify',  401, {'Authentication': '"login required"'})

@app.route('/home')
@token_required
def homepage(current_user):
    return str(current_user.email)

if __name__ == '__main__':
    app.run()
