from flask import Flask, redirect, url_for, render_template, make_response, request, flash,session,jsonify
from constant import LANDINGPAGE, LOGIN, SERVER, USER_SERVER, PASSWORD_SERVER, DATABASE,column_names,DASHBOARD,JADWAL,JALAN
import os
from mysql import insert_auth,delete_auth,update_auth,upload_fisio_auth,updatepassword_auth
from models import db,User,Sidebar
from forms import LoginForm,RegistrationForm,insertupdate_user,UploadFileForm,UpdatePasswordForm
from flask_wtf.csrf import CSRFProtect,generate_csrf
import logging
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import Session as SQLAlchemySession
from flask_socketio import SocketIO, Namespace
from flask_cors import CORS


app = Flask(__name__)
messages = []
CORS(app)
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")
engine = create_engine(f'mysql://{USER_SERVER}:{PASSWORD_SERVER}@{SERVER}/{DATABASE}')

app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql://{USER_SERVER}:{PASSWORD_SERVER}@{SERVER}/{DATABASE}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

app.permanent_session_lifetime = timedelta(days=30)  # Adjust the lifetime as needed
app.register_blueprint(insert_auth)
app.register_blueprint(update_auth)
app.register_blueprint(delete_auth)

app.secret_key = 'many random bytes'

csrf = CSRFProtect(app)  # Inisialisasi CSRF protection
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # in seconds


class JalanNamespace(Namespace):
    def on_connect(self):
        print('Client connected to the /jalan namespace')

    def on_disconnect(self):
        print('Client disconnected from the /jalan namespace')

    def on_message_from_arduino(self, message):
        print(f'Received message from Arduino: {message}')
        self.emit('message_from_api', message) 

    def on_request_disconnect(self):
        self.disconnect()

socketio.on_namespace(JalanNamespace('/jalan'))


@socketio.on('disconnect', namespace='/jalan')
def handle_disconnect():
    print('Client disconnected from the /jalan namespace')


@app.route('/')
def index():
    
    html_content = render_template(LANDINGPAGE)
    response = make_response(html_content)

        # Set the Cache-Control header to prevent caching
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, no-store'

    return response
    
         
@app.route('/login', methods=['GET', 'POST'])
def login():
    full_name = request.cookies.get('full_name')
    if full_name:
            return redirect(url_for('dashboard'))
    else:
           
        login_form = LoginForm()
        regis_form = RegistrationForm()
        
    if request.method == 'POST':
        if 'submit_login' in request.form and login_form.validate_on_submit():
            email = login_form.email.data
            password = login_form.password.data
            user = User.query.filter_by(email=email).first()

            if user and user.password == password:
                csrf_token = generate_csrf()
                session['full_name'] = user.full_name
                session['csrf_token'] = csrf_token
                session['status'] = user.status
                
                resp = make_response(redirect(url_for('dashboard')))
                expiration_date = datetime.now() + timedelta(days=30)
                resp.set_cookie('full_name', user.full_name, expires=expiration_date)
                
                return resp
            else:
                message = 'Password atau Username Salah!!'
                flash(message, 'error')  # Flash the error message
                return redirect(url_for('login'))

        elif 'submit_register' in request.form and regis_form.validate_on_submit():
            # Process registration form
            full_name = regis_form.full_name.data
            email = regis_form.email.data
            password = regis_form.password.data
            
            # Check if any of the registration fields are empty
            if not full_name or not email or not password:
                flash('Semua kolom registrasi harus diisi.', 'danger')
            else:
                # Check if the email already exists in the database
                existing_user = User.query.filter_by(email=email).first()
                if existing_user:
                    flash('Email sudah terdaftar. Silakan gunakan email lain.', 'danger')    
                else:
                    # Save a notification in the Flask session
                    flash('Registrasi berhasil! Anda dapat masuk sekarang.', 'success')
                    new_user = User(full_name=full_name, email=email, password=password)
                    db.session.add(new_user)
                    db.session.commit()
                    
                    # Clear the form after successful registration
                    regis_form.full_name.data = ''
                    regis_form.email.data = ''
                    regis_form.password.data = ''

            # Redirect to login with updated forms
            return redirect(url_for('login'))

    # Handle GET request or form validation errors
    html_content = render_template(LOGIN, login_form=login_form, regis_form=regis_form)

    response = make_response(html_content)

    # Set the Cache-Control header to prevent caching
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, no-store'
    
    return response


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    session.permanent = True
    if 'full_name' not in session:
        return redirect(url_for('login'))  # Redirect to the login page if not logged in

    form = insertupdate_user()
    users = User.query.all()

    full_name = session['full_name']
    csrf_token = session['csrf_token']

    # Query the database to retrieve the user's data
    user_data = User.query.filter_by(full_name=full_name).first()

    modified_data = []

    for user in users:
        modified_user = [user.id, user.email, "*******", user.status]  # Assuming 'password' is the third column
        modified_data.append(modified_user)

    count_result = User.query.count()

    sidebar_items = []  # Define it at the beginning
    sidebar_data = Sidebar.query.all()  # Fetch all sidebar items (replace 'Sidebar' with your actual model name)

    # Modify the sidebar data as needed
    for item in sidebar_data:
        sidebar_item = {
            'name': item.name_side,
            'icon': item.icon_side,
            'url': item.url_side
        }
        sidebar_items.append(sidebar_item)

    # Disconnect clients from the '/jalan' namespace
    

    data_list = [
        {"label": "Email", "input_type": "email", "name": "email", "value": "email"},
        {"label": "Password", "input_type": "password", "name": "password", "value": "password"},
        {"label": "Status", "input_type": "select", "name": "status", "options": [("Admin", "1"), ("Pasien", "2")]}
    ]

    data_list1 = [
        {"label": "Email", "input_type": "email", "name": "email", "required": "1"},
        {"label": "Full Name", "input_type": "text", "name": "full_name", "required": "1"},
        {"label": "Password", "input_type": "password", "name": "password", "required": "1"},
        {"label": "Status", "input_type": "select", "name": "status", "required": "1", "options": [("Admin", "1"), ("Pasien", "2")]}
    ]

    # Assuming you have a 'DASHBOARD' template defined
    html_content = render_template(
        DASHBOARD,
        users=modified_data,
        column_names=column_names,
        sidebar_items=sidebar_items,
        data_hitung=count_result,
        data_list=data_list,
        data_list1=data_list1,
        form=form,
        user=user_data,
        csrf_token=csrf_token
    )

    response = make_response(html_content)

    # Set the Cache-Control header to prevent caching
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, no-store'

    return response
    
  
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    session.permanent = True

    if 'full_name' not in session:
        return redirect(url_for('login'))  # Redirect to the login page if not logged in

    # Get the currently logged-in user's username from the session
    
    form = insertupdate_user() 
    form1 = UploadFileForm()
    form2 = UpdatePasswordForm()
    full_name = session['full_name']
    csrf_token = session['csrf_token']   
    # Query the database to retrieve the user's data
    user = User.query.filter_by(full_name=full_name).first()



    data_hitung = 1  # Set the count_user value as needed

    sidebar_items = []  # Define it at the beginning
    sidebar_data = Sidebar.query.all()  # Fetch all sidebar items (replace 'Sidebar' with your actual model name)

    # Modify the sidebar data as needed
    for item in sidebar_data:
        sidebar_item = {
            'name': item.name_side,
            'icon': item.icon_side,
            'url': item.url_side
        }
        sidebar_items.append(sidebar_item)



        
    html_content = render_template('profile.html',sidebar_items=sidebar_items, data_hitung=data_hitung, user=user,form=form,form1=form1,form2=form2,csrf_token=csrf_token)

    response = make_response(html_content)

    # Set the Cache-Control header to prevent caching
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, no-store'

    return response

        
@app.route('/jadwal')
def jadwal():
    session.permanent = True

    if 'full_name' not in session:
        return redirect(url_for('login'))

    users = User.query.all()

    full_name = session['full_name']

    # Query the database to retrieve the user's data
    user_data = User.query.filter_by(full_name=full_name).first()

    modified_data = []

    for user in users:
        modified_user = [user.id, user.email, "*******", user.status]  # Assuming 'password' is the third column
        modified_data.append(modified_user)

    count_result = User.query.count()

    sidebar_items = []  # Define it at the beginning
    sidebar_data = Sidebar.query.all()  # Fetch all sidebar items (replace 'Sidebar' with your actual model name)

    # Modify the sidebar data as needed
    for item in sidebar_data:
        sidebar_item = {
            'name': item.name_side,
            'icon': item.icon_side,
            'url': item.url_side
        }
        sidebar_items.append(sidebar_item)

    # Disconnect clients from the '/jalan' namespace


    # Assuming you have a 'JADWAL' template defined
    html_content = render_template(
        JADWAL,
        users=modified_data,
        column_names=column_names,
        sidebar_items=sidebar_items,
        data_hitung=count_result,
        user=user_data
    )

    response = make_response(html_content)

    # Set the Cache-Control header to prevent caching
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, no-store'

    return response
    
@app.route('/api/get_csrf_token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf()  # You may need to import generate_csrf from Flask-WTF
    return jsonify({'csrf_token': token})


@app.route('/api/send_message', methods=['POST'])
def send_message():
    try:
        if request.method == 'POST':
            data = request.get_json()
            if data and 'message' in data:
                message = data['message']
                # Append the message to the messages list
                messages.append(message)
                # Print the messages list for debugging
                print("Messages List:", messages)
                socketio.emit('message_from_api', message, namespace='/jalan')
                return jsonify({'success': True, 'message': 'Message sent successfully'})
            else:
                return jsonify({'success': False, 'message': 'Invalid JSON data or missing "message" field'}), 400
    except Exception as e:
        # Log the exception for debugging purposes
        print(f"Error in send_message API: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred'}), 500


@app.route('/api/get_messages', methods=['GET'])
def get_messages():
    try:
        # Print the request object for debugging
        print("Request Object:", request)
        # Return the list of messages as JSON response
        return jsonify({'success': True, 'messages': messages})
    except Exception as e:
        # Log the exception for debugging purposes
        print(f"Error in get_messages API: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred'}), 500


@app.route('/jalan', methods=['GET', 'POST'])
def jalan():
    session.permanent = True

    if 'full_name' not in session:
        return redirect(url_for('login'))

    users = User.query.all()

    full_name = session['full_name']

    # Ensure that you're using the correct key to retrieve the CSRF token from the session

    # Query the database to retrieve the user's data
    user_data = User.query.filter_by(full_name=full_name).first()

    modified_data = []

    for user in users:
        modified_user = [user.id, user.email, "*******", user.status]  # Assuming 'password' is the third column
        modified_data.append(modified_user)

    count_result = User.query.count()

    sidebar_items = []  # Define it at the beginning
    sidebar_data = Sidebar.query.all()  # Fetch all sidebar items (replace 'Sidebar' with your actual model name)

    # Modify the sidebar data as needed
    for item in sidebar_data:
        sidebar_item = {
            'name': item.name_side,
            'icon': item.icon_side,
            'url': item.url_side
        }
        sidebar_items.append(sidebar_item)

    # Assuming you have a 'DASHBOARD' template defined
    html_content = render_template(
        JALAN,
        users=modified_data,
        column_names=column_names,
        sidebar_items=sidebar_items,
        data_hitung=count_result,
        user=user_data,
    )

    response = make_response(html_content)

    # Set the Cache-Control header to prevent caching
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, no-store'

    return response


@app.route('/logout')
def logout():
    # Clear the Flask session
    session.pop('full_name', None)

    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie('full_name')  # Clear the 'full_name' cookie
    return resp
        

                
if __name__ == "__main__":    
     app.register_blueprint(upload_fisio_auth, url_prefix='/upload_fisio_auth')          
     app.register_blueprint(updatepassword_auth, url_prefix='/updatepassword_auth')       
     socketio.run(app, debug=True, port=5005)
