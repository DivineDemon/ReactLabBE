import os
import jwt  # type: ignore
import json
import base64
import stripe  # type: ignore
import requests  # type: ignore
from . import db, bcrypt
from functools import wraps
from .models import Item, User
from flask import Blueprint, request, jsonify  # type: ignore
from flask_jwt_extended import create_access_token  # type: ignore
from cryptography.hazmat.primitives import serialization  # type: ignore
from cryptography.hazmat.backends import default_backend  # type: ignore
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers  # type: ignore

main_bp = Blueprint('main', __name__)
FrontEnd_DOMAIN = os.getenv("FRONTEND_DOMAIN")
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
KINDE_DOMAIN = os.getenv("KINDE_DOMAIN")
KINDE_CLIENT_ID = os.getenv("KINDE_CLIENT_ID")
KIND_PUBLIC_KEY_URL = f"{KINDE_DOMAIN}/.well-known/jwks.json"


def get_jwk():
    response = requests.get(KIND_PUBLIC_KEY_URL)
    if response.status_code == 200:
        return response.json()
    raise Exception("Unable to fetch JWKS")


def base64url_decode(base64url_str):
    padding = '=' * (4 - len(base64url_str) % 4)
    base64_str = base64url_str.replace('-', '+').replace('_', '/') + padding
    return base64.b64decode(base64_str)


def extract_audience_from_token(token):
    """Extract audience claim from the token payload."""
    _, payload, _ = token.split(".")
    decoded_payload = base64url_decode(payload)
    payload_json = json.loads(decoded_payload.decode('utf-8'))
    audience = payload_json.get('aud')
    if not audience:
        raise Exception("Audience (aud) claim missing in the token payload")
    return audience


def convert_jwk_to_pem(jwk):
    n = base64url_decode(jwk['n'])
    e = base64url_decode(jwk['e'])
    public_numbers = RSAPublicNumbers(
        int.from_bytes(e, byteorder='big'),
        int.from_bytes(n, byteorder='big')
    )
    public_key = public_numbers.public_key(backend=default_backend())
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem


def kinde_token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization", None)
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401

        token = auth_header.split(" ")[1]
        try:
            payload = verify_jwt(token)
        except Exception as e:
            return jsonify({"error": str(e)}), 401

        return f(payload, *args, **kwargs)
    return decorated_function


def verify_jwt(token):
    jwks = get_jwk()
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = key
            break

    if not rsa_key:
        return Exception("No matching RSA key found in JWKS")

    if rsa_key:
        try:
            pem_key = convert_jwk_to_pem(rsa_key)
            audience = extract_audience_from_token(token)
            payload = jwt.decode(
                token,
                pem_key,
                algorithms=["RS256"],
                audience=audience,
                issuer=KINDE_DOMAIN
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise Exception("Token is expired")
        except jwt.InvalidTokenError as e:
            raise Exception(f"Invalid token: {str(e)}")

    raise Exception("Unable to find appropriate key for token")


def kinde_auth_required(f):
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401

        token = auth_header.split(" ")[1]
        try:
            payload = verify_jwt(token)
            request.user = payload
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({"error": str(e)}), 401
    wrapper.__name__ = f.__name__
    return wrapper


@main_bp.route('/', methods=['GET'])
def root():
    return {'response': 'API Running'}


@main_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'User already exists'}), 400

    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201


@main_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        token = create_access_token(identity=str(user.id))
        return jsonify({'token': token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401


@main_bp.route('/items', methods=['GET', 'POST'])
@kinde_auth_required
def handle_items():
    if request.method == 'GET':
        items = Item.query.all()
        return jsonify([{'id': item.id, 'name': item.name, 'description': item.description} for item in items])

    if request.method == 'POST':
        data = request.get_json()
        new_item = Item(name=data['name'], description=data.get('description'))
        db.session.add(new_item)
        db.session.commit()
        return jsonify({'id': new_item.id, 'name': new_item.name, 'description': new_item.description}), 201


@main_bp.route('/items/<int:item_id>', methods=['GET', 'PUT', 'DELETE', 'PATCH'])
@kinde_auth_required
def handle_item(item_id):
    item = Item.query.get_or_404(item_id)

    if request.method == 'GET':
        return jsonify({'id': item.id, 'name': item.name, 'description': item.description})

    if request.method == 'PUT':
        data = request.get_json()
        item.name = data['name']
        item.description = data.get('description')
        db.session.commit()
        return jsonify({'id': item.id, 'name': item.name, 'description': item.description})

    if request.method == 'DELETE':
        db.session.delete(item)
        db.session.commit()
        return jsonify({'message': 'Item deleted'}), 204

    if request.method == 'PATCH':
        data = request.get_json()
        if 'name' in data:
            item.name = data['name']
        if 'description' in data:
            item.description = data['description']
        db.session.commit()
        return jsonify({'id': item.id, 'name': item.name, 'description': item.description})


@main_bp.route('/pay', methods=['POST'])
@kinde_auth_required
def pay():
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            billing_address_collection="required",
            customer_email="customer_email@gmail.com",
            line_items=[
                {
                    'price_data': {
                        'currency': 'USD',
                        'product_data': {
                            'name': "card_title",
                            'description': "Unlimited AI Generations",
                        },
                        'unit_amount': 7800,
                        'recurring': {'interval': "month"}
                    },
                    'quantity': 1,
                }
            ],
            success_url=FrontEnd_DOMAIN + "/success",
            cancel_url=FrontEnd_DOMAIN + "/cancel",
        )

        return jsonify({'id': checkout_session.id})
    except Exception as e:
        return jsonify(error=str(e)), 500


@main_bp.route('/protected-endpoint', methods=['GET'])
@kinde_auth_required
def protected():
    """Protected endpoint to validate token."""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error": "Authorization header missing"}), 401
    return jsonify({"message": "Token is valid and successful"}), 200
