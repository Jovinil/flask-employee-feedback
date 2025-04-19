from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from flask_restful import Api, Resource
from neomodel import StructuredNode, StringProperty, UniqueIdProperty, RelationshipTo,db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import requests

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'supersecretkey'
app.config['SECRET_KEY'] = 'anothersecretkey'
api = Api(app)
jwt = JWTManager(app)

# Initialize a set to store blacklisted tokens
blacklist = set()

# db.set_connection('neo4j://neo4j:password@:localhost:7687/')

class User(StructuredNode):
    uid = UniqueIdProperty()
    username = StringProperty(unique=True, required=True)
    password = StringProperty(required=True)
    gave_feedback = RelationshipTo('Feedback', 'GAVE_FEEDBACK')

class Feedback(StructuredNode):
    uid = UniqueIdProperty()
    surname = StringProperty(required=True)
    first_name = StringProperty(required=True)
    middle_name = StringProperty(required=True)
    unit = StringProperty(required=True)
    quarter = StringProperty(required=True)
    gist = StringProperty(required=True)
    date = StringProperty(required=True)
    recommended = StringProperty(required=True)
    target_date = StringProperty(required=True)
    date_created = StringProperty(required=True)


class Register(Resource):
    def post(self):
        data = request.get_json()
        hushed_password = generate_password_hash(data['password'])
        try:
            user = User(username=data['username'], password=hushed_password).save()
            return {'message': 'User Registered Successfully'}, 201
        except Exception as e:
            return {'error': str(e)}, 400
        
class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.nodes.first_or_none(username=data['username'])
        if user and check_password_hash(user.password, data['password']):
            access_token = create_access_token(identity=user.username)
            return {'access_token': access_token}, 200
        return {'message': 'Invalid credentials'}, 401
    
class Logout(Resource):
    @jwt_required()
    def get(self):
        jti = get_jwt()['jti']  # Get the unique identifier of the JWT
        blacklist.add(jti)  # Add the token to the blacklist
        return {'message': 'Successfully logged out'}, 200

class Dashboard(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        return {'username': current_user}, 200
    
class FeedbackForm(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        return {'username': current_user}, 200

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return jti in blacklist

api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')  # Add the logout resource
api.add_resource(Dashboard, '/dashboard')
api.add_resource(FeedbackForm, '/feedback-form')

if __name__ == '__main__':
    app.run(port=4000, debug=True)