from flask import Blueprint, request, Flask, redirect, url_for, flash, request, current_app, session
from forms import insertupdate_user, UploadFileForm
from models import db, User
from flask_wtf.csrf import CSRFError
from werkzeug.utils import secure_filename
import os
from PIL import Image

insert_auth = Blueprint('insert_data', __name__)
update_auth = Blueprint('update_data', __name__)
delete_auth = Blueprint('delete_data', __name__)
upload_fisio_auth = Blueprint('upload_fisio_auth', __name__)
updatepassword_auth = Blueprint('updatepassword_auth', __name__)

UPLOAD_FOLDER = 'Data_Foto/Foto_User'
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS




@insert_auth.route('/insert', methods=['POST'])
def insert():
    form = insertupdate_user()

    if form.validate_on_submit():
        # Use form data as needed in your logic
        email = form.email.data
        password = form.password.data
        full_name = form.full_name.data
        status = form.status.data

        # Create a new user with the required fields
        user = User(email=email, password=password, full_name=full_name, status=status)

        # Add the user to the session and commit the transaction
        db.session.add(user)
        db.session.commit()

        return redirect(url_for('login'))


@delete_auth.route('/delete/<int:id>', methods=['GET'])
def delete(id):
    user_to_delete = User.query.get(id)

    if user_to_delete:
        db.session.delete(user_to_delete)
        db.session.commit()
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('dashboard'))


@update_auth.route('/update/<id>', methods=['GET', 'POST'], endpoint='update')
def update(id):
    user = None

    if id.isdigit():
        # If the identifier is a digit, assume it's an ID
        user = User.query.get(int(id))
    else:
        # If it's not a digit, assume it's a username
        user = User.query.filter_by(full_name=id).first()

    if user is None:
        return redirect(url_for('dashboard'))

    form = insertupdate_user(obj=user)

    if form.validate_on_submit():
        if request.method == 'POST':
            if form.full_name.data:
                user.full_name = form.full_name.data
            if form.password.data:
                user.password = form.password.data
            if form.status.data:
                user.status = form.status.data
            if form.email.data:
                user.email = form.email.data
            
    if id.isdigit():
        db.session.commit()
        return redirect(url_for('dashboard'))

    else:
        db.session.commit()
        return redirect(url_for('profile'))

@upload_fisio_auth.route('/upload_fisio/<id>', methods=['GET', 'POST'])
def upload_fisio(id):
    form = UploadFileForm()

    if form.validate_on_submit():
        try:
            file = form.foto_fisio.data
            username = form.full_name.data
            status = form.status.data

            if file and allowed_file(file.filename):
                upload_folder = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static', UPLOAD_FOLDER,status, username)
                if not os.path.exists(upload_folder):
                    os.makedirs(upload_folder)

                # Change this to your desired new filename and extension
                new_filename = username + ".png"

                file_path = os.path.join(upload_folder, secure_filename(new_filename))
                file.save(file_path)

                if new_filename.lower().endswith('.jpg') or new_filename.lower().endswith('.jpeg'):
                    image = Image.open(file_path)
                    image.save(file_path, "PNG")


                if id.isdigit():
                    FotoUpload = os.path.join(UPLOAD_FOLDER,status ,username, new_filename)
                    user = User.query.get(int(id))
                    user.Foto_Profile =  FotoUpload  # Use capital "F" for Foto_Profile
                else:
                    FotoUpload = os.path.join(UPLOAD_FOLDER,status ,username, new_filename)
                    user = User.query.filter_by(full_name=id).first()
                    user.Foto_Profile =  FotoUpload  # Use capital "F" for Foto_Profile

                         
                    if id.isdigit() :
                        db.session.commit()
                        return redirect(url_for('profile'))
                    else :
                     db.session.commit()
                     return redirect(url_for('profile'))
               
        except Exception as e:
            db.session.rollback()  # Rollback changes in case of an error
            print(f"An error occurred while processing the file: {str(e)}")

    return redirect(url_for('profile'))



@updatepassword_auth.route('/change_password/<string:id>', methods=['POST'])
def change_password(id):
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    # Retrieve the user from the database (you should adapt this based on your authentication method)
    user = User.query.filter_by(email=id).first()

    if user:
        # Check if the current password matches the one stored in the database
        if user.password == current_password:
            if new_password == confirm_password:
                # Update the password in the database
                user.password = new_password  # Replace this line with your database update logic
                db.session.commit()
                flash('Password updated successfully', 'success')
                return redirect(url_for('profile'))
            else:
                flash('New password and confirmation password do not match', 'danger')
                return redirect(url_for('profile'))

        else:
            flash('Incorrect current password', 'danger')
            return redirect(url_for('profile'))
    else:
        flash('User not found', 'danger')
        return redirect(url_for('profile'))
