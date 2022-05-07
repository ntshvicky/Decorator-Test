from flask import Flask, json, jsonify, request
import datetime
from functools import wraps
import jwt


########################################################################
# Flask Setup
########################################################################
app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]ddMngrty$$/'


# #============= Decorators =================================

#use to validate access token generated on login
def token_required(f):
    @wraps(f)
    def token_decorator(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({"message" : "Token is missing!"}), 401
        try: 
            jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({"message" : "Token is invalid!"}), 401
        return f(*args, **kwargs)
    return token_decorator

#use to validate input passed as json 
def validate_request(keys, files = None):
    def validate_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if request.json is None:
                return jsonify({'status': False, 'message': 'No data in requests'}), 400

            if keys is not None:
                if not all(key in request.json for key in keys):
                    response = {'status': False, 'message': 'Input Validation: {} are required'.format(",".join(keys))}
                    return jsonify(response), 400

            if files is not None:
                if not all(key in request.files for key in files):
                    response = {'status': False, 'message': 'File Validation: {} are required'.format(",".join(files))}
                    return jsonify(response), 400

            return f(*args, **kwargs)
        return wrapper
    return validate_decorator

#A flask default validator to execute after every request
#in flask setting after_request decorator in our custom decorator to run decorator
@app.after_request # you can use @app.before_request to execute anything before any request as we have done previously
def after_request(response):
    log = {"username": request.json['username'], "timestamp": datetime.datetime.now(), "request": str(request.headers)}
    print(log)
    with open("log.txt", "a") as file:
        file.write(json.dumps(log)+"\n")
    return response

# #============= Integrate Decorator in api =================================

# An example to validate request data and create login log
@app.route('/api/login/', methods=['POST'])
@app.route('/api/login', methods=['POST'])
@validate_request(keys = ['username', 'password'])
def login():
    requestData = request.json
    email = requestData['username']
    password = requestData['password']
    if email == "admin" and password == "1234":
        token = jwt.encode({'public_id' : "admin", 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=1440)}, app.secret_key)
        return jsonify({'authentication': True, 'token': token.decode("utf-8")}), 200
    else:
        return jsonify({'authentication': False}), 400


#to access dashboard api validate x-access-token
@app.route('/api/dashboard/', methods=['POST'])
@app.route('/api/dashboard', methods=['POST'])
@token_required
def dashboard():
    return jsonify({'status': True, 'message': 'Logged In'}), 200

# Execute flask api in port 5000
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)