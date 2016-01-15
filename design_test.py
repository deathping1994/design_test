import datetime
from flask import Flask, jsonify,request
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.cors import CORS, cross_origin
from flask.ext.bcrypt import Bcrypt
import sqlalchemy
app = Flask("design_test")
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
cors = CORS(app, resources={r"*": {"origins": "*"}})
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://postgres:gaurav@localhost:5432/locaholic'

# models


class User(db.Model):
    email_id = db.Column(db.String(80), unique=True, primary_key=True, nullable=False)
    _password = db.Column(db.String(100), nullable=False)
    isAdmin = db.Column(db.Boolean)

    def __init__(self,email_id,_password,isadmin=False):
        self.email_id = email_id
        self._password=_password
        self.isAdmin=isadmin



class Session(db.Model):
    authkey = db.Column(db.String(100), unique=True, primary_key=True)
    isAdmin = db.Column(db.Boolean)

    def __init__(self,authtoken,user):
        self.isAdmin = user.isAdmin
        self.authkey=authtoken

def isAdmin(authkey):
    chkSession = Session.query.get(str(authkey))
    if chkSession is not None and chkSession.isAdmin:
        return True
    return False


def authenticate(email, passwd):
    user = User.query.get(str(email))
    if user is not None:
        if bcrypt.check_password_hash(user._password.encode(),str(passwd)):
            authtoken = bcrypt.generate_password_hash(user.email_id + str(datetime.datetime.now()))
            newSession = Session(authtoken,user)
            db.session.add(newSession)
            db.session.commit()
            return authtoken
    return "Invalid"


@app.route('/login', methods=["GET", "POST"])
@cross_origin(origin='*', headers=['Content- Type', 'Authorization'])
def login():
    data = request.get_json(force=True)
    res=authenticate(email=data['email_id'],passwd=data['passwd'])
    if res!="Invalid":
        return jsonify(success=res),200
    else:
        return jsonify(error="Invalid Details"),403

@app.route('/logout', methods=["GET", "POST"])
@cross_origin(origin='*', headers=['Content- Type', 'Authorization'])
def logout():
    data = request.get_json(force=True)
    chkSession = Session.query.get(str(data['authkey']))
    if chkSession is not None:
        db.session.delete(chkSession)
        db.session.commit()
        return jsonify(success="logged out successfully"),200
    else:
        return jsonify(error="You are not logged in"),500


@app.route('/regadmin',methods=["GET","POST"])
@cross_origin(origin='*', headers=['Content- Type', 'Authorization'])
def reg():
    data = request.get_json(force=True)
    user=User("pk@locaholic.co",bcrypt.generate_password_hash("admin"),True)
    db.session.add(user)
    try:
        db.session.commit()
    except Exception as e:
        print str(e)
        pass
    return jsonify(success="done"),201

@app.route('/invite', methods=["GET", "POST"])
@cross_origin(origin='*', headers=['Content- Type', 'Authorization'])
def invite():
    data = request.get_json(force=True)
    if not isAdmin(data['authkey']):
        return jsonify(error="You don't have access to invite users"), 403
    user = User(data['email_id'],
                bcrypt.generate_password_hash(data['passwd']))
    try:
        db.session.add(user)
        # db.session.add(guest)
        db.session.flush()
        db.session.commit()
        return jsonify(success="User successfully invited"), 200
    except Exception as e:
        print type(e)
        if isinstance(e, sqlalchemy.exc.IntegrityError):
            return jsonify(error="User already Exists"), 500
            print e
            return jsonify(error="Oops something went wrong. Contact administrator"), 500


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True,host="0.0.0.0", port=8080)
