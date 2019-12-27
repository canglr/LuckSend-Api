from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand

app = Flask(__name__)
POSTGRES = {
    'user': 'lucksend',
    'pw': 'XD9pLYDxaqZHlJaBVSum6uWIyC4Q1Dob',
    'db': 'Raffles',
    'host': '127.0.0.1',
    'port': '5432',
}
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:\
%(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES

db = SQLAlchemy(app)
migrate = Migrate(app, db)

manager = Manager(app)
manager.add_command('db', MigrateCommand)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mail_adress = db.Column(db.String, nullable=False)
    name = db.Column(db.String, nullable=False)
    profile_picture = db.Column(db.String, nullable=False)
    local = db.Column(db.String, nullable=False)
    provider_name = db.Column(db.String, nullable=False)
    provider_id = db.Column(db.String, nullable=False)
    id_share = db.Column(db.String, nullable=False,unique=True)
    is_active = db.Column(db.Boolean, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    last_update = db.Column(db.DateTime, nullable=False)
    raffleslerf = db.relationship('Raffles', backref='users', lazy=True)
    feedbacksf = db.relationship('Feedbacks', backref='users', lazy=True)
    participantsf = db.relationship('Participants', backref='users', lazy=True)
    keysf = db.relationship('Keys', backref='users', lazy=True)
    luckysf = db.relationship('Luckys', backref='users', lazy=True)
    qrcodesf = db.relationship('Qrcode', backref='users', lazy=True)
    socialstatisticssf = db.relationship('Socialstatistics', backref='users', lazy=True)
    socialsavedf = db.relationship('Socialsaved', backref='users', lazy=True)
    socialreportssf = db.relationship('Socialreports', backref='users', lazy=True)


class Raffles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_share = db.Column(db.String, nullable=False,unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'),nullable=False)
    title = db.Column(db.String, nullable=False)
    contact_information = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.Boolean, nullable=False)
    processing = db.Column(db.Boolean, nullable=False)
    completed = db.Column(db.Boolean, nullable=False)
    delete = db.Column(db.Boolean, nullable=False)
    disable = db.Column(db.Boolean, nullable=False)
    winners = db.Column(db.Integer, nullable=False)
    reserves = db.Column(db.Integer, nullable=False)
    raffle_date = db.Column(db.DateTime, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    last_update = db.Column(db.DateTime, nullable=False)
    luckysf = db.relationship('Luckys', backref='raffles', lazy=True)
    tagstargetf = db.relationship('Tagtargets', backref='raffles', lazy=True)
    countrytargetf = db.relationship('Countrytargets', backref='raffles', lazy=True)


class Feedbacks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'),nullable=False)
    description = db.Column(db.String, nullable=False)
    read = db.Column(db.Boolean, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    last_update = db.Column(db.DateTime, nullable=False)


class Participants(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'),nullable=False)
    raffle_id = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)


class Keys(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'),nullable=False)
    key = db.Column(db.String, nullable=False)
    device_key = db.Column(db.String, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)
    device_information_id = db.Column(db.Integer, db.ForeignKey('deviceinformation.id'),nullable=False)


class Luckys(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'),nullable=False)
    raffles_id = db.Column(db.Integer, db.ForeignKey('raffles.id'),nullable=False)
    secret_key = db.Column(db.String, nullable=False, unique=True)
    status = db.Column(db.Boolean, nullable=False)
    check_key = db.Column(db.Boolean, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)


class Deviceinformation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    brand = db.Column(db.String, nullable=False)
    model = db.Column(db.String, nullable=False)
    release = db.Column(db.String, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    keysf = db.relationship('Keys', backref='deviceinformation', lazy=True)


class Tags(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tag_name = db.Column(db.String, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    tagsf = db.relationship('Tagtargets', backref='tags', lazy=True)
    socialtagtargetsf = db.relationship('Socialtagtargets', backref='tags', lazy=True)


class Tagtargets(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tag_id = db.Column(db.Integer, db.ForeignKey('tags.id'),nullable=False)
    raffle_id = db.Column(db.Integer, db.ForeignKey('raffles.id'),nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)


class Countries(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    country_code = db.Column(db.String, nullable=False)
    countriesf = db.relationship('Countrytargets', backref='countries', lazy=True)
    socialcountrytargetsf = db.relationship('Socialcountrytargets', backref='countries', lazy=True)


class Countrytargets(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    country_id = db.Column(db.Integer, db.ForeignKey('countries.id'), nullable=False)
    raffle_id = db.Column(db.Integer, db.ForeignKey('raffles.id'), nullable=False)


class Countrymultilang(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    multi_code = db.Column(db.String, nullable=True)
    country_code = db.Column(db.String, nullable=False)
    country_name = db.Column(db.String, nullable=False)


class Versions(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    versions_name = db.Column(db.String, nullable=False)
    versions_description = db.Column(db.String, nullable=True)
    versions_code = db.Column(db.String, nullable=False)
    versions_secret_key = db.Column(db.String, nullable=False)
    contact_secret_key = db.Column(db.String,nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)


class Logs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ip_address = db.Column(db.String, nullable=False)
    action = db.Column(db.String, nullable=False)
    data = db.Column(db.JSON, nullable=True)
    creation_date = db.Column(db.DateTime, nullable=False)


class AdminUsers(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    user_name = db.Column(db.String, nullable=False,unique=True)
    mail_address = db.Column(db.String, nullable=False,unique=True)
    password_hash = db.Column(db.String, nullable=False)
    master = db.Column(db.Boolean, nullable=False)
    is_active = db.Column(db.Boolean, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    last_update = db.Column(db.DateTime, nullable=False)


class Qrcode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    key = db.Column(db.String, nullable=False)
    status = db.Column(db.Boolean, nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)


class Socialmedia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_share = db.Column(db.String, nullable=False, unique=True)
    author_name = db.Column(db.String, nullable=False)
    media_id = db.Column(db.String, nullable=False)
    media_description = db.Column(db.String, nullable=False)
    media_image = db.Column(db.String, nullable=False)
    media_url = db.Column(db.String, nullable=False)
    provider_name = db.Column(db.String,nullable=False)
    delete = db.Column(db.Boolean, nullable=False)
    disable = db.Column(db.Boolean, nullable=False)
    verification = db.Column(db.Boolean, nullable=False)
    sponsor = db.Column(db.Boolean,nullable=False)
    type = db.Column(db.Boolean,nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    last_update = db.Column(db.DateTime, nullable=False)
    socialtagtargetsf = db.relationship('Socialtagtargets', backref='socialmedia', lazy=True)
    socialsavedf = db.relationship('Socialsaved', backref='socialmedia', lazy=True)
    socialstatisticsf = db.relationship('Socialstatistics', backref='socialmedia', lazy=True)
    socialcountrytargetsf = db.relationship('Socialcountrytargets', backref='socialmedia', lazy=True)
    socialreportsf = db.relationship('Socialreports', backref='socialmedia', lazy=True)


class Socialtagtargets(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    tag_id = db.Column(db.Integer, db.ForeignKey('tags.id'), nullable=False)
    social_id = db.Column(db.Integer, db.ForeignKey('socialmedia.id'), nullable=False)


class Socialcountrytargets(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    country_id = db.Column(db.Integer, db.ForeignKey('countries.id'), nullable=False)
    social_id = db.Column(db.Integer, db.ForeignKey('socialmedia.id'), nullable=False)


class Socialstatistics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    social_id = db.Column(db.Integer, db.ForeignKey('socialmedia.id'), nullable=False)
    clicks = db.Column(db.Boolean, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)


class Socialsaved(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    social_id = db.Column(db.Integer, db.ForeignKey('socialmedia.id'), nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)


class Socialreports(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    social_id = db.Column(db.Integer, db.ForeignKey('socialmedia.id'), nullable=False)
    description = db.Column(db.String, nullable=False)
    read = db.Column(db.Boolean, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)


if __name__ == '__main__':
    manager.run()