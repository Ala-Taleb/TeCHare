from flask_sqlalchemy import SQLAlchemy
import uuid 
from datetime import datetime, timedelta
from functools import wraps
from flask_mail import Mail, Message
from flask import Flask
from flask import jsonify
from flask import request
from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

from  werkzeug.security import generate_password_hash, check_password_hash
from passlib.hash import pbkdf2_sha256
from flask_migrate import Migrate

app = Flask(__name__)
mail = Mail(app)
app.config.from_pyfile('config.py')
db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app) 
jwt = JWTManager(app)

class User(db.Model):
	id = db.Column(db.Integer, primary_key = True)
	public_id = db.Column(db.String(50), unique = True)
	name = db.Column(db.String(100))
	email = db.Column(db.String(70), unique = True)
	password = db.Column(db.String(80))
	role = db.Column(db.String(10))
	date = db.Column(db.DateTime, default = datetime.utcnow)

@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
	identity = get_jwt_identity()
	access_token = create_access_token(identity=identity, fresh=False)
	return jsonify(access_token=access_token)

# get all users only for admin role
@app.route("/user", methods =['GET'])
@jwt_required()
def get_all_users():
	current_user = get_jwt_identity()
	user = User.query.filter_by(email = current_user).first()
	if user.role == 'admin':
		users = User.query.all()
		output = []
		for user in users:
			user_data = {}
			user_data['public_id'] = user.public_id
			user_data['name'] = user.name
			user_data['email'] = user.email
			user_data['role'] = user.role
			output.append(user_data)
		return jsonify({'users': output})
	else:
		return jsonify({'message': 'Only admin can perform that function!'}), 401

#delete user only for admin role
@app.route("/user/<public_id>", methods =['DELETE'])
@jwt_required()
def delete_user(public_id):
	current_user = get_jwt_identity()
	user = User.query.filter_by(email = current_user).first()
	if user.role == 'admin':
		compte = User.query.filter_by(public_id = public_id).first()
		if not compte:
			return jsonify({'message': 'No user found!'})
		db.session.delete(compte)
		db.session.commit()
		return jsonify({'message': 'The user has deleted!'})
	return jsonify({'message': 'Only admin can perform that function!'}), 401


def send_mail(receiver, objet, body):
	msg = Message(objet, sender = 'alaataleb677@gmail.com', recipients = [receiver])
	msg.body = body
	try:
		mail.send(msg)
		return 'Flase'
	except:
		return 'Link sent successfully'
	
@app.route('/login', methods =['POST'])
def login():
	auth = request.form
	email, password = auth.get('email'), auth.get('password')
	if not auth or not email or not password:
		return jsonify({"msg": "Bad username or password"}), 401
	user = User.query.filter_by(email = email).first()
	if user:
		if pbkdf2_sha256.verify(password, user.password):
			access_token = create_access_token(identity=email, fresh=True)
			refresh_token = create_refresh_token(identity=email)
			return jsonify(access_token=access_token, refresh_token=refresh_token)
		return jsonify({"msg": "Bad username or password"}), 401
	else:
		return jsonify({"msg": "Bad username or password"}), 401	



@app.route('/signup', methods =['POST'])
def signup():
	data = request.form
	name, email = data.get('name'), data.get('email')
	password = data.get('password')
	role = data.get('role')

	user = User.query\
		.filter_by(email = email)\
		.first()
	if not user:
		user = User(
			public_id = str(uuid.uuid4()),
			name = name,
			email = email,
			role = role,
			password = pbkdf2_sha256.hash(password)
		)
		db.session.add(user)
		db.session.commit()

		return jsonify({'message' : 'Successfully registered.'}), 201
	else:
		return jsonify({'message': 'User already exists. Please Log in.'}), 202

# edit user details except password and email and role
@app.route('/user/<public_id>', methods =['PUT'])
@jwt_required()
def edit_user( public_id):
	data = request.form
	name = data.get('name')
	user = User.query.filter_by(public_id = public_id).first()
	if not user:
		return jsonify({'message': 'No user found!'}), 401
	user.name = name
	db.session.commit()
	return jsonify({'message': 'The user has been updated!'}), 201
	
		
#forgot password and send email to user with reset password link
@app.route('/forgot_password', methods =['POST'])
def forgot_password():
	data = request.form
	email = data.get('email')
	user = User.query\
		.filter_by(email = email)\
		.first()
	if not user:
		return make_response('User does not exist.', 404)
	else:
		link = "http://127.0.0.1:5000/reset_password/" + str(user.id) 
		res = send_mail(email, 'Reset Password', link)
		return (res, 201) 

#send email to user with reset password link
@app.route('/reset_password/<id>', methods =['PUT'])
def reset_password(id):
	data = request.form
	password = data.get('password')
	user = User.query\
		.filter_by(id = id)\
		.first()
	if not user:
		return jsonify({'msg': 'User does not exist.'}), 404
	else:
		user.password = pbkdf2_sha256.hash(password)
		db.session.commit()
		return ({'msg' :'Password changed with success'}), 201

#home route protected by token
@app.route("/home", methods=["GET"])
@jwt_required()
def home():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

if __name__ == "__main__":
	app.run()

