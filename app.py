from flask import Flask, jsonify, request
from flask_migrate import Migrate
from datetime import datetime, timedelta
from models.user import User
from models.passwordresettoken import PasswordResetToken
from models.dbconfig import db
from werkzeug.security import generate_password_hash, check_password_hash
from flasgger import Swagger
import random
import string
import cloudinary
import cloudinary.uploader
import jwt
import os 
import base64

app = Flask(__name__)
app.config['SWAGGER'] = {
    'title': 'Auth and Cloudinary API docs',
    'uiversion': 3
}
swagger = Swagger(app)
# api = Api(app)
# swagger = Swagger(api, title='Auth and Authorization', description='My Flask API Documentation for Auth using JWT and cloudinary upload.')
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://authorizationapis_tidn_user:2ojSPuvRhLLJvWhK78HLxVQITPqGhZWE@dpg-coegmp0l5elc73883lk0-a/authorizationapis_tidn'
# postgresql format 
# postgresql://username:password@hostname/database_name


# cloudinary 
# Configure Cloudinary
# raw credentials are too exposed. 
from utlis import cloudconfig
cloudconfig

# generating jwt secret key 
secret_key = base64.b64encode(os.urandom(24)).decode('utf-8')
print(secret_key)


# Bind the SQLAlchemy instance to the Flask app
# silence the initialization below for postgresql use it for sqlite. 
db.init_app(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Routes
@app.route('/register', methods=['POST'])
def register():
    """
    Register a new users.
    ---
    tags:
      - Authentication
    parameters:
      - name: username
        in: body
        type: string
        required: true
        description: User's username
      - name: password
        in: body
        type: string
        required: true
        description: User's password
    responses:
      201:
        description: User registered successfully
        schema:
          type: object
          properties:
            message:
              type: string
              description: Registration success message
      400:
        description: Bad request, invalid input data
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, password=hashed_password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        # generate token with no expiry 
        # token = jwt.encode({'user_id': user.id}, secret_key, algorithm='HS256')

        # to generate a token with an expiration period 
        # Set the expiration time to 1 hour from now // to set as minutes , use minutes , to set as seconds add as seconds.
        expiration_time = datetime.utcnow() + timedelta(hours=1)
        # Generate the JWT token with the 'exp' claim
        token = jwt.encode({'user_id': user.id, 'exp': expiration_time}, secret_key, algorithm='HS256')
        print(token)
        return jsonify({'message': 'Login successful', 'token': token})
    else:
        return jsonify({'message': 'Invalid username or password'}), 401
    
# Helper function to decode the token
def decode_token(token):
    try:
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return 'Token has expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'


# Protected route example
@app.route('/protected', methods=['GET'])
def protected_route():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'message': 'Token is missing'}), 401

    token = token.split(' ')[1]  # Extract the token from the 'Authorization' header

    # Decode the token
    payload = decode_token(token)

    if isinstance(payload, str):
        return jsonify({'message': payload}), 401

    user_id = payload.get('user_id')
    
    # Now you have the user ID, and you can perform further authorization logic
    # Check if the user has the necessary permissions, etc.
    # the process 
    return jsonify({'message': 'Access granted'}), 200



@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    username = data.get('username')

    user = User.query.filter_by(username=username).first()

    if user:
        # Generate a random token
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=20))

        # Set token expiration time (e.g., 1 hour)
        expiration = datetime.now() + timedelta(hours=1)
        print(token)
        print(expiration)
        # Create a new reset token
        reset_token = PasswordResetToken(user_id=user.id, token=token, expiration=expiration)
        db.session.add(reset_token)
        db.session.commit()

        # In a real application, you would send an email with the reset link containing the token

        return jsonify({'message': 'Password reset token generated successfully'})

    return jsonify({'message': 'User not found'}), 404

@app.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    data = request.get_json()
    new_password = data.get('new_password')

    reset_token = PasswordResetToken.query.filter_by(token=token).first()

    if reset_token and reset_token.expiration > datetime.now():
        user = User.query.filter_by(id=reset_token.user_id).first()
        hashed_password = generate_password_hash(new_password, method='sha256')
        user.password = hashed_password

        db.session.delete(reset_token)
        db.session.commit()

        return jsonify({'message': 'Password reset successful'})

    return jsonify({'message': 'Invalid or expired reset token'}), 400


@app.route('/upload-profile-picture/<int:user_id>', methods=['POST'])
def upload_profile_picture(user_id):
    # Check if the 'file' key exists in the request.files
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400

    file = request.files['file']

    # Check if a file was uploaded
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    # Upload the image to Cloudinary
    try:
        result = cloudinary.uploader.upload(file)
        image_url = result['secure_url']

        # Retrieve the user
        user = User.query.get(user_id)

        # Update the user's profile picture URL
        user.profile_picture = image_url

        db.session.commit()

        return jsonify({'message': 'Profile picture uploaded and updated successfully', 'url': image_url}), 200
    except Exception as e:
        return jsonify({'message': f'Error uploading image: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=True)

