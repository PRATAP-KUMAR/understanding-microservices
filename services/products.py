import requests
from flask import Flask, jsonify, request, make_response
from flask_cors import CORS, cross_origin
import jwt
from functools import wraps
import json
import os
from jwt.exceptions import InvalidTokenError  # Use the correct exception

app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['SECRET_KEY'] = os.urandom(24)

# Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return jsonify({'error': 'Authorization token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_id = data['user_id']
        except InvalidTokenError:
            return jsonify({'error': 'Authorization token is invalid'}), 401
        return f(current_user_id, *args, **kwargs)
    return decorated

# Load users
with open('users.json', 'r') as f:
    users = json.load(f)

# Authentication route
@app.route('/auth', methods=['POST'])
@cross_origin()
def authenticate_user():
    if request.headers['Content-Type'] != 'application/json':
        return jsonify({'error': 'Unsupported Media Type'}), 415
    username = request.json.get('username')
    password = request.json.get('password')
    for user in users:
        if user['username'] == username and user['password'] == password:
            token = jwt.encode({'user_id': user['id']}, app.config['SECRET_KEY'], algorithm="HS256")
            response = make_response(jsonify({'message': 'Authentication successful'}))
            response.set_cookie('token', token)
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response, 200
    return jsonify({'error': 'Invalid username or password'}), 401

# Home route
@app.route("/")
def home():
    return "Hello, this is a Flask Microservice"

# Products route
BASE_URL = "https://dummyjson.com"
@app.route('/products', methods=['GET'])
@cross_origin()
@token_required
def get_products(current_user_id):
    response = requests.get(f"{BASE_URL}/products")
    if response.status_code != 200:
        return jsonify({'error': response.json()['message']}), response.status_code
    products = []
    for product in response.json()['products']:
        product_data = {
            'id': product['id'],
            'title': product['title'],
            'price': product['price'],
            'description': product['description']
        }
        products.append(product_data)
    return jsonify({'data': products}), 200 if products else 204

# Run the app
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)