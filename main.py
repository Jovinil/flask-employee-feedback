from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from flask_restful import Api, Resource
from neomodel import StructuredNode, StringProperty, UniqueIdProperty, db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime
import requests

app = Flask(__name__)

client_app = Flask(__name__)
client_app.config['SECRET_KEY'] = 'clientsecretkey'
AUTH_SERVER = 'http://127.0.0.1:4000'

@client_app.route('/')
def home():
    return render_template('login.html')

@client_app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = {'username': request.form['username'], 'password': request.form['password']}
        response = requests.post(f'{AUTH_SERVER}/register', json=data)
        if response.status_code == 201:
            return redirect(url_for('login'))
        return jsonify(response.json()), response.status_code
    return render_template('register.html')

@client_app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = {'username': request.form['username'], 'password': request.form['password']}
        response = requests.post(f'{AUTH_SERVER}/login', json=data)
        if response.status_code == 200:
            session['token'] = response.json().get('access_token')
            return redirect(url_for('dashboard'))
        return jsonify(response.json()), response.status_code
    return render_template('login.html')

@client_app.route('/logout')
def logout():
    token = session.get('token')
    headers = {'Authorization': f'Bearer {token}'}
    reponse = requests.get(f'{AUTH_SERVER}/logout', headers=headers)

    session.pop('token', None)
    return redirect(url_for('login'))

@client_app.route('/dashboard')
def dashboard():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(f'{AUTH_SERVER}/dashboard', headers=headers)
    if response.status_code == 200:
        return render_template('dashboard.html', username=response.json().get('username'), feedbacks=response.json().get('data'))
    return redirect(url_for('login'))

@client_app.route('/feedback-form')
def feedbackForm():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(f'{AUTH_SERVER}/feedback-form', headers=headers)
    if response.status_code == 200:
        return render_template('feedback-form.html', username=response.json().get('username'))
    return redirect(url_for('dashboard'))

@client_app.route('/add-feedback', methods = ['POST', 'GET'])
def addFeedback():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    if request.method == 'POST':
        headers = {'Authorization': f'Bearer {token}'}
        now = datetime.now()
        data = {'surname': request.form['surname'], 
                'first_name': request.form['first_name'],
                'middle_name': request.form['middle_name'],
                'division': request.form['division'],
                'quarter': request.form['quarter'],
                'gist': request.form['gist'],
                'incident_date': request.form['incident_date'],
                'recommended': request.form['recommended'],
                'target_date': request.form['target_date'],
                'date_created': now.strftime('%m/%d/%Y')}
        response = requests.post(f'{AUTH_SERVER}/add-feedback', headers=headers, json=data)
        if response.status_code == 201:
            return redirect(url_for('dashboard'))
        return redirect(url_for('feedbackForm'))

@client_app.route('/get-feedback/<feedback_id>', methods=['POST', 'GET'])
def getFeedback(feedback_id):
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    headers = {'Authorization': f'Bearer {token}'}
    if request.method == 'GET':
        response = requests.get(f'{AUTH_SERVER}/get-feedback/{feedback_id}', headers=headers)
        if response.status_code == 200:
            return render_template('view-form.html', username=response.json().get('username'), data=response.json().get('data'))
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    client_app.run(port=4001, debug=True)