from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    Foto_Profile = db.Column(db.String(128), nullable=False)  # Capital "F" for Foto_Profile
    status = db.Column(db.Integer, default=2)

    def __init__(self, full_name, email, password,status):
        self.full_name = full_name
        self.email = email
        self.password = password
        self.status = status

     
class Sidebar(db.Model):
     __tablename__ = 'side_bar'
     id_side = db.Column(db.Integer, primary_key=True)
     name_side = db.Column(db.String(50))
     icon_side = db.Column(db.String(50))
     url_side = db.Column(db.String(50))
        

              