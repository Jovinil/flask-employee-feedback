from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from neomodel import StructuredNode, StringProperty, UniqueIdProperty, RelationshipTo, db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

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
    division = StringProperty(required=True)
    quarter = StringProperty(required=True)
    gist = StringProperty(required=True)
    incident_date = StringProperty(required=True)
    recommended = StringProperty(required=True)
    target_date = StringProperty(required=True)
    date_created = StringProperty(required=True)

class Register(Resource):
    def post(self):
        data = request.get_json()
        hushed_password = generate_password_hash(data['password'])
        try:
            user = User(username=data['username'], password=hushed_password).save()
            return {'message': 'User  Registered Successfully'}, 201
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
        user = User.nodes.first_or_none(username=current_user)

        if user:
            feedback_list = user.gave_feedback.all()
            feedback_data = []
            for feedback in feedback_list:
                feedback_data.append({
                    'uid': feedback.uid,
                    'surname': feedback.surname,
                    'first_name': feedback.first_name,
                    'middle_name': feedback.middle_name,
                    'division': feedback.division,
                    'quarter': feedback.quarter,
                    'gist': feedback.gist,
                    'incident_date': feedback.incident_date,
                    'recommended': feedback.recommended,
                    'target_date': feedback.target_date,
                    'date_created': feedback.date_created
                })
            json = jsonify('feedback_data')
            response = {'username': current_user, 'data': feedback_data}
            # response.status_code = 200
            return response
        
        return {'message': 'User  not found'}, 404

    
class FeedbackForm(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        return {'username': current_user}, 200

class AddFeedback(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()
        current_user = get_jwt_identity()
        user = User.nodes.first_or_none(username=current_user)

        if user:
            feedback = Feedback(
                surname=data['surname'],
                first_name=data['first_name'],
                middle_name=data['middle_name'],
                division=data['division'],
                quarter=data['quarter'],
                gist=data['gist'],
                incident_date=data['incident_date'],
                recommended=data['recommended'],
                target_date=data['target_date'],
                date_created=data['date_created']
            ).save()
            user.gave_feedback.connect(feedback)
            return {'message': 'Feedback added successfully'}, 201
        return {'message': 'User  not found'}, 404

class GetFeedback(Resource):
    @jwt_required()
    def get(self, feedback_id):
        current_user = get_jwt_identity()
        user = User.nodes.first_or_none(username=current_user)

        if user:
            feedback = Feedback.nodes.get_or_none(uid=feedback_id)

            if feedback and feedback in user.gave_feedback.all():
                data = {
                    'uid': feedback.uid,
                    'surname': feedback.surname,
                    'first_name': feedback.first_name,
                    'middle_name': feedback.middle_name,
                    'division': feedback.division,
                    'quarter': feedback.quarter,
                    'gist': feedback.gist,
                    'incident_date': feedback.incident_date,
                    'recommended': feedback.recommended,
                    'target_date': feedback.target_date,
                    'date_created': feedback.date_created}
                return {'username': current_user, 'data': data}, 200
            
            return {'message': 'Feedback not found or does not belong to the user'}, 404
        
        return {'message': 'User  not found'}, 404
    
class UpdateFeedback(Resource):
    @jwt_required()
    def post(self, feedback_id):
        data = request.get_json()
        current_user = get_jwt_identity()
        user = User.nodes.first_or_none(username=current_user)

        if user:
            feedback = Feedback.nodes.get_or_none(uid=feedback_id)

            if feedback and feedback in user.gave_feedback.all():
                feedback.surname = data.get('surname', feedback.surname)
                feedback.first_name = data.get('first_name', feedback.first_name)
                feedback.middle_name = data.get('middle_name', feedback.middle_name)
                feedback.division = data.get('division', feedback.division)
                feedback.quarter = data.get('quarter', feedback.quarter)
                feedback.gist = data.get('gist', feedback.gist)
                feedback.incident_date = data.get('incident_date', feedback.incident_date)
                feedback.recommended = data.get('recommended', feedback.recommended)
                feedback.target_date = data.get('target_date', feedback.target_date)
                feedback.date_created = data.get('date_created', feedback.date_created)
                feedback.save() 

                return {'message': 'Feedback updated successfully'}, 200
            
            return {'message': 'Feedback not found or does not belong to the user'}, 404
        
        return {'message': 'User  not found'}, 404


@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return jti in blacklist

api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(Dashboard, '/dashboard')
api.add_resource(FeedbackForm, '/feedback-form')
api.add_resource(AddFeedback, '/add-feedback')
api.add_resource(GetFeedback, '/get-feedback/<feedback_id>')
api.add_resource(UpdateFeedback, '/update-feedback/<feedback_id>')


if __name__ == '__main__':
    app.run(port=4000, debug=True)