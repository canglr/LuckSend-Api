import json
import urllib
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from bson import SON
from dateutil.relativedelta import relativedelta
from flask import Flask
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy
from flask import request
from flask import jsonify
from sqlalchemy import desc
import shortuuid
import datetime

from random import randint
import uuid
from datetime import datetime, timedelta
from google.oauth2 import id_token
from google.auth.transport import requests
from cryptography.fernet import Fernet, InvalidToken
from pymongo import MongoClient

app = Flask(__name__)
POSTGRES = {
    'user': 'lucksend',
    'pw': 'XD9pLYDxaqZHlJaBVSum6uWIyC4Q1Dob',
    'db': 'Raffles',
    'host': '127.0.0.1',
    'port': '5432',
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:\
%(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES
app.config['AES_KEY'] = "qlEVOu1ZSu3-KDMh1qVMtjIT8UepTyZFXvVRrJZ_AV0="


db = SQLAlchemy(app)
ma = Marshmallow(app)


client = MongoClient('mongodb+srv://lucksend:sXu2x4z6@lucksend-echos.mongodb.net/admin?retryWrites=true&w=majority')
mongodb = client['lucksend']
InstagramProfile = mongodb['InstagramProfile']
UserKeytoId = mongodb['UserKeytoId']
SocialMedia = mongodb['SocialMedia']
Search = mongodb['Search']


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
    type = db.Column(db.Boolean, nullable=False)
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


class RafflesSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ('title', 'id_share')


raffle_schema = RafflesSchema()
raffles_schema = RafflesSchema(many=True)


class WinnersSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ('name', 'id_share', 'status')


winner_schema = WinnersSchema()
winners_schema = WinnersSchema(many=True)


class ReservesSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ('name', 'id_share', 'status')


reserve_schema = ReservesSchema()
reserves_schema = ReservesSchema(many=True)


class SocialmediaSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ('id_share', 'author_name', 'media_image', 'sponsor', 'type')


socialmedia_schema = SocialmediaSchema()
socialmedias_schema = SocialmediaSchema(many=True)


class TagsearchSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ('id', 'tag_name')


socialsearch_schema = TagsearchSchema()
socialsearchs_schema = TagsearchSchema(many=True)


def filter_datetime(date):
    result = datetime.strftime(date, '%Y-%m-%d %H:%M:%S')
    return result


def key_check(api_key):
    key = Keys.query.filter_by(key=api_key).first()
    if key is not None:
        if datetime.utcnow() < key.expiration:
            return True
        else:
            return False
    else:
        return False


def version_check(version_code):
    version = Versions.query.filter_by(versions_secret_key=version_code).first()
    if version is not None:
        if datetime.utcnow() < version.expiration:
            return True
        else:
            return False
    else:
        return False


def get_ip():
    ip = request.access_route[0]
    return ip


def user_get_id(key):
    user_key_check = UserKeytoId.find_one({"key": key})
    if user_key_check is not None:
        return user_key_check['user_id']
    else:
        keys_query = Keys.query.filter_by(key=key).first()
        UserKeytoId.insert_one(
            {"key": keys_query.key, "user_id": keys_query.user_id, "cache_expiration": cache_expiration(72)})
        return keys_query.user_id


def social_get_id(id_share):
    socialmedia_check = SocialMedia.find_one({"id_share": id_share})
    if socialmedia_check is not None:
        return socialmedia_check['social_id']
    else:
        socialmedia = Socialmedia.query.filter_by(id_share=id_share).first()
        SocialMedia.insert_one(
            {"social_id": socialmedia.id,
             "id_share": socialmedia.id_share,
             "author_name": socialmedia.author_name,
             "media_id": socialmedia.media_id,
             "media_description": socialmedia.media_description,
             "media_image": socialmedia.media_image,
             "media_url": socialmedia.media_url,
             "provider_name": socialmedia.provider_name,
             "delete": socialmedia.delete,
             "disable": socialmedia.disable,
             "verification": socialmedia.verification,
             "sponsor": socialmedia.sponsor,
             "creation_date": socialmedia.creation_date,
             "last_update": socialmedia.last_update,
             "cache_expiration": cache_expiration(72)
             })
        return socialmedia.id


def uuid_short():
    rnd = randint(0, 2)
    if rnd == 0:
        result = shortuuid.ShortUUID().random(length=8)
    elif rnd == 1:
        result = shortuuid.ShortUUID().random(length=10)
    elif rnd == 2:
        result = shortuuid.ShortUUID().random(length=12)
    return result


def add_log(action, user_id, data):
    log = Logs()
    log.user_id = user_id
    log.ip_address = get_ip()
    log.action = action
    log.data = data
    log.creation_date = datetime.utcnow()
    db.session.add(log)
    db.session.commit()
    return True


def add_device_information(brand, model, release):
    device = Deviceinformation.query.filter_by(brand=brand).filter_by(model=model).filter_by(release=release).first()
    if device is None:
        device_information = Deviceinformation()
        device_information.brand = brand
        device_information.model = model
        device_information.release = release
        device_information.creation_date = datetime.utcnow()
        db.session.add(device_information)
        db.session.commit()
        return device_information.id
    else:
        return device.id


def key_generator(user_id,device_information_id,device_key):
    key = Keys()
    key.user_id = user_id
    key.device_information_id = device_information_id
    key.key = uuid.uuid4()
    key.device_key = device_key
    key.expiration = datetime.utcnow() + relativedelta(months=+6)
    key.creation_date = datetime.utcnow()
    db.session.add(key)
    db.session.commit()
    return key.key


def user_manager(provider_id,mail_adress,name,local,profile_picture):
    user = Users.query.filter_by(mail_adress=mail_adress).filter_by(provider_id=provider_id).first()
    if user is None:
        user = Users()
        user.provider_name = 'google'
        user.provider_id = provider_id
        user.mail_adress = mail_adress
        user.name = name
        user.local = local
        user.profile_picture = profile_picture
        user.id_share = uuid_short()
        user.is_active = True
        user.creation_date = datetime.utcnow()
        user.last_update = datetime.utcnow()
        db.session.add(user)
        db.session.commit()
        add_log("login", user.id, None)
        return user.id
    else:
        user_up = Users.query.filter_by(mail_adress=mail_adress).filter_by(provider_id=provider_id).first()
        user_up.last_update = datetime.utcnow()
        user_up.profile_picture = profile_picture
        user_up.local = local
        db.session.add(user_up)
        db.session.commit()
        add_log("login", user_up.id, None)
        return user_up.id


def add_tags(tags,raffle_id):
    tagtarget_count = Tagtargets.query.filter_by(raffle_id=raffle_id).count()
    if tagtarget_count is not 0:
        db.session.query(Tagtargets).filter_by(raffle_id=raffle_id).delete()

    for tag in tags:
        tag_check = Tags.query.filter_by(tag_name=tag.strip()).first()
        if tag_check is not None:
            add_tagtarget = Tagtargets()
            add_tagtarget.tag_id = tag_check.id
            add_tagtarget.raffle_id = raffle_id
            add_tagtarget.creation_date = datetime.utcnow()
            db.session.add(add_tagtarget)
            db.session.commit()
        else:
            add_tag = Tags()
            add_tag.tag_name = tag.strip()
            add_tag.creation_date = datetime.utcnow()
            db.session.add(add_tag)
            db.session.commit()

            add_tagtarget = Tagtargets()
            add_tagtarget.tag_id = add_tag.id
            add_tagtarget.raffle_id = raffle_id
            add_tagtarget.creation_date = datetime.utcnow()
            db.session.add(add_tagtarget)
            db.session.commit()


def add_social_tags(tags,social_id):
    tagtarget_count = Socialtagtargets.query.filter_by(social_id=social_id).count()
    if tagtarget_count is not 0:
        db.session.query(Socialtagtargets).filter_by(social_id=social_id).delete()

    for tag in tags:
        tag_check = Tags.query.filter_by(tag_name=tag.strip()).first()
        if tag_check is not None:
            add_tagtarget = Socialtagtargets()
            add_tagtarget.tag_id = tag_check.id
            add_tagtarget.social_id = social_id
            db.session.add(add_tagtarget)
            db.session.commit()
        else:
            add_tag = Tags()
            add_tag.tag_name = tag.strip()
            add_tag.creation_date = datetime.utcnow()
            db.session.add(add_tag)
            db.session.commit()

            add_tagtarget = Socialtagtargets()
            add_tagtarget.tag_id = add_tag.id
            add_tagtarget.social_id = social_id
            db.session.add(add_tagtarget)
            db.session.commit()


def add_countries(countries,raffle_id):
    db.session.query(Countrytargets).filter_by(raffle_id=raffle_id).delete()
    if len(countries) is not 1:
        try:
            countries.remove("ALL")
            pass
        except ValueError:
            pass

    for country in countries:
        country_info = Countries.query.filter_by(country_code=country.strip()).first()
        add_country = Countrytargets()
        add_country.country_id = country_info.id
        add_country.raffle_id = raffle_id
        db.session.add(add_country)
        db.session.commit()


def add_social_countries(countries,social_id):
    db.session.query(Socialcountrytargets).filter_by(social_id=social_id).delete()
    if len(countries) is not 1:
        try:
            countries.remove("ALL")
            pass
        except ValueError:
            pass

    for country in countries:
        country_info = Countries.query.filter_by(country_code=country.strip()).first()
        add_country = Socialcountrytargets()
        add_country.country_id = country_info.id
        add_country.social_id = social_id
        db.session.add(add_country)
        db.session.commit()


def raffle_check_country(raffle_id,user_id):
    user = Users.query.filter_by(id=user_id).first()
    country = user.local.upper()

    country_info_all = Countries.query.filter_by(country_code='ALL').first()
    if country_info_all is not None:
        country_check = Countrytargets.query.filter_by(raffle_id=raffle_id).filter_by(
            country_id=country_info_all.id).first()
        if country_check is not None:
            return True
        else:
            country_info = Countries.query.filter_by(country_code=country).first()
            if country_info is not None:
                country_check = Countrytargets.query.filter_by(raffle_id=raffle_id).filter_by(
                    country_id=country_info.id).first()
                if country_check is not None:
                    return True
                else:
                    return False
            else:
                return False
    else:
        return False


def aes_encode(text):
    """key = Fernet.generate_key()"""
    f = Fernet(bytes(app.config['AES_KEY'], 'utf-8'))
    encode_text = f.encrypt(bytes(text, 'utf-8'))
    return encode_text.decode("utf-8")


def aes_decode(text):
    f = Fernet(bytes(app.config['AES_KEY'], 'utf-8'))
    decode_text = f.decrypt(bytes(text, 'utf-8'))
    return decode_text.decode("utf-8")


def cache_expiration(hours):
    date = datetime.utcnow() + relativedelta(hours=+hours)
    return date


def date_back_to(hours):
    date = datetime.utcnow() + relativedelta(hours=-hours)
    return date


def instagram_profile_image(user_name):
    try:
        image_check = InstagramProfile.find_one({"author_name": user_name})
        if image_check is not None:
            return image_check['author_image']
        else:
            with urllib.request.urlopen("https://www.instagram.com/" + user_name + "/") as url:
                data = url.read()
                html = BeautifulSoup(data, 'html.parser')
                image = html.find('meta', property="og:image")
                InstagramProfile.insert_one({"author_name": user_name, "author_image": image['content'],
                                             "cache_expiration": cache_expiration(12)})
        return image["content"]
    except:
        return 'https://lucksend.com/static/app/images/noprofile.png'


def socialmedia_statistics(user_id,social_id,clicks):
    statistics = Socialstatistics()
    statistics.user_id = user_id
    statistics.social_id = social_id
    statistics.clicks = clicks
    statistics.creation_date = datetime.utcnow()
    db.session.add(statistics)
    db.session.commit()
    return True


@app.route('/')
def hello_world():
    return 'app start '


@app.route('/account/check', methods=['POST'])
def account_check():
    token = request.form['token']
    brand = request.form['brand']
    model = request.form['model']
    release = request.form['release']
    device_key = request.form['device_key']
    try:
        # if idinfo['hd'] != GSUITE_DOMAIN_NAME:
        user_info = id_token.verify_oauth2_token(token, requests.Request(), '770983460919-8dmftdap4pu55gmpn21aeilk4t2o7eau.apps.googleusercontent.com')

        if user_info['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')

        name = user_info['name']
        profile_picture = user_info['picture']
        local = user_info['locale']
        mail_adress = user_info['email']
        provider_id = user_info['sub']

        user_id = user_manager(provider_id, mail_adress, name, local, profile_picture)
        device_information_id = add_device_information(brand, model, release)
        key = key_generator(user_id, device_information_id, device_key)
        user = Users.query.filter_by(id=user_id).first()
        return jsonify(key=key, local=user.local, mail_address=user.mail_adress, name=user.name, profile_picture=user.profile_picture, id_share=user.id_share)
    except ValueError:
        return jsonify(api_status=False, api_result='Login_failed_please_try_again')


@app.route('/account/my', methods=['POST'])
def account_my():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    user_id = user_get_id(api_key)
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user = Users.query.filter_by(id=user_id).first()
        if user is not None:
            return jsonify(mail_adress=user.mail_adress,name=user.name,id_share=user.id_share,creation_date=str(filter_datetime(user.creation_date)),last_update=str(filter_datetime(user.last_update)),msg_status=1)
        else:
            return jsonify(api_status=False, api_result='404_not_found')


@app.route('/account/exit', methods=['POST'])
def account_exit():
    api_key = request.form['api_key']
    key = Keys.query.filter_by(key=api_key).first()
    key.expiration = datetime.utcnow()
    db.session.add(key)
    db.session.commit()
    return jsonify(api_status=True)


@app.route('/raffles/list', methods=['POST'])
def raffles_list():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user_id = user_get_id(api_key)
        raffles = Raffles.query.filter_by(user_id=user_id).filter_by(delete=False).filter_by(disable=False).order_by(desc(Raffles.id)).all()
        result = raffles_schema.dump(raffles)
        return jsonify(result.data)


@app.route('/participants/list', methods=['POST'])
def participants_list():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user_id = user_get_id(api_key)
        raffles = db.session.query(Raffles.id_share,Raffles.title).join(Participants, Raffles.id == Participants.raffle_id).filter_by(user_id=user_id).filter(Raffles.delete==False).filter(Raffles.disable==False).order_by(desc(Participants.creation_date)).all()
        result = raffles_schema.dump(raffles)
        return jsonify(result.data)


@app.route('/raffle/my/detail', methods=['POST'])
def raffle_my_detail():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    id_share = request.form['id_share']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user_id = user_get_id(api_key)
        user = Users.query.filter_by(id=user_id).first()
        raffle = Raffles.query.filter_by(user_id=user_id).filter_by(delete=False).filter_by(disable=False).filter_by(id_share=id_share).first()
        if raffle is not None:
            raffle_join_count = Participants.query.filter_by(raffle_id=raffle.id).count()
            tags = db.session.query(Tags.tag_name).join(Tagtargets, Tags.id == Tagtargets.tag_id).filter(
                Tagtargets.raffle_id == raffle.id).all()
            raffle_tag = []
            for tag in tags:
                raffle_tag.append(str(tag[0]))

            countries_selected = db.session.query(Countries.country_code,Countrymultilang.country_name).join(Countrytargets,
                                                                           Countries.id == Countrytargets.country_id).join(Countrymultilang,
                                                                           Countries.country_code == Countrymultilang.country_code).filter(
                Countrytargets.raffle_id == raffle.id).filter(Countrymultilang.multi_code == user.local).all()

            raffle_countries = []
            for tag in countries_selected:
                item = {}
                item['name'] = str(tag[1])
                item['value'] = str(tag[0])
                raffle_countries.append(item)
            return jsonify(id_share=raffle.id_share,title=raffle.title,description=raffle.description,contact_information=raffle.contact_information,expiration=str(raffle.expiration),winners=raffle.winners,reserves=raffle.reserves,creation_date=str(filter_datetime(raffle.creation_date)),last_update=str(filter_datetime(raffle.last_update)),raffle_join_count=raffle_join_count,status=raffle.status,completed=raffle.completed,tags=raffle_tag,countries=raffle_countries)
        else:
            return jsonify(api_status=False, api_result='404_not_found')


@app.route('/raffle/create', methods=['POST'])
def create_raffle():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user_id = user_get_id(api_key)
        title = request.form['title']
        description = request.form['description']
        expiration = request.form['expiration']
        winners = request.form['winners']
        reserves = request.form['reserves']
        tags = request.form['tags']
        countries = request.form['countries']
        contact_information = request.form['contact_information']

        tags = tags.replace('[', '')
        tags = tags.replace(']', '')
        countries = countries.replace('[', '')
        countries = countries.replace(']', '')
        tags = tags.split(',')
        countries = countries.split(',')

        while ('' in tags):
            tags.remove('')

        while ('' in countries):
            countries.remove('')

        if title.strip() is "":
            return jsonify(result="the_title_cannot_be_blank",status=False)
        elif description.strip() is "":
            return jsonify(result="description_cannot_be_left_blank",status=False)
        elif description.strip() is "":
            return jsonify(result="contact_information_cannot_be_blank",status=False)
        elif expiration.strip() is "":
            return jsonify(result="end_date_cannot_be_blank",status=False)
        elif winners.strip() is "":
            return jsonify(result="the_number_of_winners_cannot_be_blank", status=False)
        elif reserves.strip() is "":
            return jsonify(result="the_number_of_replacement_people_cannot_be_blank", status=False)
        elif int(winners) <= 0:
            return jsonify(result="the_number_of_people_to_win_cannot_be_less_than_zero_or_zero",status=False)
        elif int(reserves) < 0:
            return jsonify(result="the_number_of_backup_contacts_cannot_be_less_than_zero", status=False)
        elif int(len(title)) > 60:
            return jsonify(result="the_title_cannot_be_greater_than_60_characters", status=False)
        elif int(len(description)) > 350:
            return jsonify(result="the_description_cannot_be_greater_than_350_characters", status=False)
        elif int(len(contact_information)) > 350:
            return jsonify(result="contact_information_cannot_be_greater_than_350_characters", status=False)
        elif int(winners) > 50:
            return jsonify(result="the_number_of_people_who_will_win_can_not_be_more_than_50",status=False)
        elif int(reserves) > 50:
            return jsonify(result="the_number_of_reserve_persons_cannot_be_more_than_50", status=False)
        elif len(tags) < 2:
            return jsonify(result="at_least_two_labels_must_be_entered", status=False)
        elif len(tags) > 4:
            return jsonify(result="up_to_four_labels_must_be_entered", status=False)
        elif len(countries) == 0:
            return jsonify(result="At_least_one_country_must_be_selected", status=False)
        elif len(countries) > 10:
            return jsonify(result="A_maximum_of_ten_countries_should_be_selected", status=False)
        else:
            raffle = Raffles()
            raffle.title = title
            raffle.description = description
            raffle.contact_information = contact_information
            raffle.expiration = expiration
            raffle.id_share = uuid_short()
            raffle.status = False
            raffle.processing = False
            raffle.completed = False
            raffle.delete = False
            raffle.disable = False
            raffle.winners = winners
            raffle.reserves = reserves
            raffle.user_id = user_id
            raffle.creation_date = datetime.utcnow()
            raffle.last_update = datetime.utcnow()
            raffle.raffle_date = datetime.utcnow()
            db.session.add(raffle)
            db.session.commit()
            add_tags(tags, raffle.id)
            add_countries(countries, raffle.id)
            add_log("raffle_created",user_id,json.dumps({"raffle_id": raffle.id}))
            return jsonify(result="raffle_created",status=True)


@app.route('/raffle/update', methods=['POST'])
def update_raffle():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user_id = user_get_id(api_key)
        id_share = request.form['id_share']
        raffle = Raffles.query.filter_by(id_share=id_share).filter_by(user_id=user_id).first()
        title = request.form['title']
        description = request.form['description']
        contact_information = request.form['contact_information']
        expiration = request.form['expiration']
        winners = request.form['winners']
        reserves = request.form['reserves']
        tags = request.form['tags']
        countries = request.form['countries']

        tags = tags.replace('[', '')
        tags = tags.replace(']', '')
        countries = countries.replace('[', '')
        countries = countries.replace(']', '')
        tags = tags.split(',')
        countries = countries.split(',')

        while ('' in tags):
            tags.remove('')

        while ('' in countries):
            countries.remove('')

        if title.strip() is "":
            return jsonify(result="the_title_cannot_be_blank", status=False)
        elif description.strip() is "":
            return jsonify(result="description_cannot_be_left_blank", status=False)
        elif contact_information.strip() is "":
            return jsonify(result="contact_information_cannot_be_blank", status=False)
        elif expiration.strip() is "":
            return jsonify(result="end_date_cannot_be_blank", status=False)
        elif winners.strip() is "":
            return jsonify(result="the_number_of_winners_cannot_be_blank", status=False)
        elif reserves.strip() is "":
            return jsonify(result="the_number_of_replacement_people_cannot_be_blank", status=False)
        elif int(winners) <= 0:
            return jsonify(result="the_number_of_people_to_win_cannot_be_less_than_zero_or_zero", status=False)
        elif int(reserves) < 0:
            return jsonify(result="the_number_of_backup_contacts_cannot_be_less_than_zero", status=False)
        elif int(len(title)) > 60:
            return jsonify(result="the_title_cannot_be_greater_than_60_characters", status=False)
        elif int(len(description)) > 350:
            return jsonify(result="the_description_cannot_be_greater_than_350_characters", status=False)
        elif int(len(contact_information)) > 350:
            return jsonify(result="contact_information_cannot_be_greater_than_350_characters", status=False)
        elif int(winners) > 50:
            return jsonify(result="the_number_of_people_who_will_win_can_not_be_more_than_50", status=False)
        elif int(reserves) > 50:
            return jsonify(result="the_number_of_reserve_persons_cannot_be_more_than_50", status=False)
        elif raffle.status is True:
            return jsonify(result="the_lottery_doesnt_update_because_it_started", status=False)
        elif raffle.delete is True:
            return jsonify(result="raffle_deleted_update_failed", status=False)
        elif raffle.disable is True:
            return jsonify(result="raffle_disable_update_failed", status=False)
        elif len(tags) < 2:
            return jsonify(result="at_least_two_labels_must_be_entered", status=False)
        elif len(tags) > 4:
            return jsonify(result="up_to_four_labels_must_be_entered", status=False)
        elif len(countries) == 0:
            return jsonify(result="At_least_one_country_must_be_selected", status=False)
        elif len(countries) > 10:
            return jsonify(result="A_maximum_of_ten_countries_should_be_selected", status=False)
        else:
            raffle.title = title
            raffle.description = description
            raffle.contact_information = contact_information
            raffle.expiration = expiration
            raffle.winners = winners
            raffle.reserves = reserves
            raffle.last_update = datetime.utcnow()
            db.session.add(raffle)
            db.session.commit()
            add_tags(tags, raffle.id)
            add_countries(countries, raffle.id)
            add_log("raffle_updated",user_id , json.dumps({"raffle_id": raffle.id, "raffle_share": raffle.id_share}))
            return jsonify(result="raffle_updated", status=True)


@app.route('/raffle/delete', methods=['POST'])
def delete_raffle():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user_id = user_get_id(api_key)
        id_share = request.form['id_share']
        raffle = Raffles.query.filter_by(id_share=id_share).filter_by(user_id=user_id).first()
        if raffle.delete is True:
            return jsonify(result="your_deletion_request_has_already_been_received", status=False)
        elif raffle.status is True:
            return jsonify(result="could_not_be_deleted_because_the_lottery_was_started", status=False)
        elif raffle.disable is True:
            return jsonify(result="The_raffle_cannot_be_deleted_because_it_is_disabled", status=False)
        else:
            raffle = Raffles.query.filter_by(id_share=id_share).filter_by(user_id=user_id).first()
            raffle.last_update = datetime.utcnow()
            raffle.delete = True
            db.session.add(raffle)
            db.session.commit()
            add_log("your_request_for_deletion_has_been_received",user_id,
                    json.dumps({"raffle_id": raffle.id, "raffle_share": raffle.id_share, "raffle_title": raffle.title}))
            return jsonify(result="your_request_for_deletion_has_been_received", status=True)


@app.route('/raffle/start', methods=['POST'])
def start_raffle():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user_id = user_get_id(api_key)
        id_share = request.form['id_share']
        raffle = Raffles.query.filter_by(id_share=id_share).filter_by(user_id=user_id).first()
        raffle_count = Participants.query.filter_by(raffle_id=raffle.id).count()
        total = raffle.winners + raffle.reserves
        if int(raffle_count) == 0:
            return jsonify(result="sufficient_participants_could_not_be_provided", status=False)
        elif int(raffle_count) <= int(total):
            return jsonify(result="sufficient_participants_could_not_be_provided", status=False)
        elif raffle.status is True:
            return jsonify(result="the_raffle_has_already_started", status=False)
        elif raffle.delete is True:
            return jsonify(result="cannot_start_because_the_raffle_was_deleted", status=False)
        elif raffle.disable is True:
            return jsonify(result="The_raffle_cannot_be_deleted_because_it_is_disabled", status=False)
        else:
            raffle = Raffles.query.filter_by(id_share=id_share).filter_by(user_id=user_id).first()
            raffle.raffle_date = datetime.utcnow() + timedelta(minutes=10)
            raffle.last_update = datetime.utcnow()
            raffle.status = True
            db.session.add(raffle)
            db.session.commit()
            add_log("the_raffle_starts_in_minutes",user_id, None)
            return jsonify(result="the_raffle_starts_in_minutes", status=True)


@app.route('/winners/list', methods=['POST'])
def winners_list():
    id_share = request.form['id_share']
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        raffle = Raffles.query.filter_by(id_share=id_share).filter_by(delete=False).filter_by(disable=False).filter_by(completed=True).first()
        winners = db.session.query(Users.name,Luckys.status,Luckys.check_key,Users.id_share).join(Luckys,Users.id == Luckys.user_id).filter_by(raffles_id=raffle.id).filter_by(status=True).all()
        result = winners_schema.dump(winners)
        return jsonify(result.data)


@app.route('/reserves/list', methods=['POST'])
def reserves_list():
    id_share = request.form['id_share']
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        raffle = Raffles.query.filter_by(id_share=id_share).filter_by(delete=False).filter_by(disable=False).filter_by(completed=True).first()
        reserves = db.session.query(Users.name,Luckys.status,Luckys.check_key,Users.id_share).join(Luckys,Users.id == Luckys.user_id).filter_by(raffles_id=raffle.id).filter_by(status=False).all()
        result = reserves_schema.dump(reserves)
        return jsonify(result.data)


@app.route('/raffle/secretkeycheck', methods=['POST'])
def rafflesecretkeycheck():
    id_share = request.form['id_share']
    secretkey = request.form['secretkey']
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user_id = user_get_id(api_key)
        raffle = Raffles.query.filter_by(id_share=id_share).filter_by(delete=False).filter_by(disable=False).filter_by(completed=True).filter_by(user_id=user_id).first()
        if raffle is not None:
            result = db.session.query(Users.name, Luckys.status, Users.id_share).join(Luckys,Users.id == Luckys.user_id).filter_by(secret_key=secretkey).first()
            if result is not None:
                lucky_key_check = Luckys.query.filter_by(secret_key=secretkey).first()
                lucky_key_check.check_key = True
                db.session.add(lucky_key_check)
                db.session.commit()
                return jsonify(name=result.name,status=result.status,id_share=result.id_share)
            else:
                return jsonify(result="no_contact_found",error=True)
        return jsonify(result="no_raffles_found",error=True)


@app.route('/participant/my/raffle/detail', methods=['POST'])
def participant_my_raffle_detail():
    id_share = request.form['id_share']
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        raffle = Raffles.query.filter_by(delete=False).filter_by(disable=False).filter_by(id_share=id_share).first()
        raffle_join_count = Participants.query.filter_by(raffle_id=raffle.id).count()
        return jsonify(id_share=raffle.id_share,title=raffle.title,description=raffle.description,expiration=str(raffle.expiration),winners=raffle.winners,reserves=raffle.reserves,creation_date=str(filter_datetime(raffle.creation_date)),last_update=str(filter_datetime(raffle.last_update)),raffle_join_count=raffle_join_count,completed=raffle.completed)


@app.route('/participant/my/raffle/result', methods=['POST'])
def participant_my_raffle_result():
    id_share = request.form['id_share']
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user_id = user_get_id(api_key)
        raffle = Raffles.query.filter_by(id_share=id_share).filter_by(delete=False).filter_by(disable=False).filter_by(completed=True).first()
        if raffle is not None:
            my_lucky_information = Luckys.query.filter_by(raffles_id=raffle.id).filter_by(user_id=user_id).first()
            if my_lucky_information is not None:
                return jsonify(secret_key=my_lucky_information.secret_key,contact_information=raffle.contact_information)
            else:
                return jsonify(secret_key=None,contact_information=None)
        else:
            return jsonify(api_status=False, api_result='404_not_found')


@app.route('/raffle/search', methods=['POST'])
def raffle_search():
    id_share = request.form['id_share']
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        raffle = Raffles.query.filter_by(delete=False).filter_by(disable=False).filter_by(id_share=id_share).first()
        if raffle is not None:
            return jsonify(id_share=raffle.id_share,title=raffle.title)
        else:
            return jsonify(id_share='',title='404',found=False)


@app.route('/raffle/search/detail', methods=['POST'])
def raffle_search_detail():
    id_share = request.form['id_share']
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user_id = user_get_id(api_key)
        raffle = Raffles.query.filter_by(delete=False).filter_by(disable=False).filter_by(id_share=id_share).first()
        raffle_join_count = Participants.query.filter_by(raffle_id=raffle.id).count()
        raffle_join = Participants.query.filter_by(raffle_id=raffle.id).filter_by(user_id=user_id).count()
        if raffle_join is 0:
            raffle_join_result = True
        else:
            raffle_join_result = False

        return jsonify(id_share=raffle.id_share,title=raffle.title,description=raffle.description,expiration=str(raffle.expiration),winners=raffle.winners,reserves=raffle.reserves,creation_date=str(filter_datetime(raffle.creation_date)),last_update=str(filter_datetime(raffle.last_update)),raffle_join_count=raffle_join_count,raffle_join_result=raffle_join_result,completed=raffle.completed)


@app.route('/raffle/join', methods=['POST'])
def raffle_join():
    id_share = request.form['id_share']
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user_id = user_get_id(api_key)
        raffle = Raffles.query.filter_by(id_share=id_share).first()
        raffle_join_count = Participants.query.filter_by(user_id=user_id).filter_by(raffle_id=raffle.id).count()
        if raffle is None:
            return jsonify(result="no_raffles_found", status=False)
        elif raffle.delete is True:
            return jsonify(result="no_attendance_for_the_raffle_was_deleted", status=False)
        elif raffle.disable is True:
            return jsonify(result="Participation_did_not_take_place_because_the_raffle_was_disabled", status=False)
        elif raffle.expiration < datetime.utcnow():
            return jsonify(result="ended_participation", status=False)
        elif raffle.user_id is user_id:
            return jsonify(result="you_cant_participate_in_your_own_lottery", status=False)
        elif raffle_join_count > 0:
            return jsonify(result="you_ve_already_joined", status=False)
        elif raffle_check_country(raffle.id,user_id) is False:
            return jsonify(result="Is_unavailable_in_your_country", status=False)
        else:
            participant = Participants()
            participant.user_id = user_id
            participant.raffle_id = raffle.id
            participant.date = datetime.strftime(datetime.utcnow(), '%Y-%m-%d')
            participant.creation_date = datetime.utcnow()
            db.session.add(participant)
            db.session.commit()
            add_log("you_took_the_lottery", user_id, json.dumps({"raffle_id": raffle.id, "raffle_share": raffle.id_share}))
            return jsonify(result="you_took_the_lottery", status=True)


@app.route('/raffle/countries/list', methods=['POST'])
def rafflecountrieslist():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user_id = user_get_id(api_key)
        user = Users.query.filter_by(id=user_id).first()
        countries = db.session.query(Countries.country_code, Countrymultilang.country_name).join(Countrymultilang,Countries.country_code == Countrymultilang.country_code).filter_by(multi_code=user.local).order_by(Countrymultilang.country_name).all()
        data = []
        for country in countries:
            item = {}
            item["value"] = country.country_code
            item["name"] = country.country_name
            data.append(item)
        return jsonify(data)


@app.route('/feedbacks', methods=['POST'])
def feedbacks():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    description = request.form['description']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    elif description.strip() is '':
        return jsonify(api_status=False, api_result='feedback_cant_be_left_blank')
    elif len(description) > 350:
        return jsonify(api_status=False, api_result='the_feedback_cannot_be_more_than_350_characters')
    else:
        user_id = user_get_id(api_key)
        creation_date = datetime.now()
        last_update = datetime.now()
        feedback = Feedbacks(user_id=user_get_id(api_key), description=description, read=False, creation_date=creation_date,last_update=last_update)
        db.session.add(feedback)
        db.session.commit()
        add_log("send", user_id, None)
    return jsonify(api_status=True, api_result='Feedback_sent')


@app.route('/dashboard/stats', methods=['POST'])
def dashboard_stats():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user_id = user_get_id(api_key)
        raffle = Raffles.query.filter_by(user_id=user_id).filter_by(delete=False).filter_by(disable=False).count()
        participants = Participants.query.filter_by(user_id=user_id).count()
        return jsonify(api_status=True, raffle=raffle, participants=participants)


@app.route('/qrcode', methods=['POST'])
def qrcode():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    try:
        qr_key = aes_decode(request.form['qr_key'])
    except InvalidToken:
        return jsonify(api_status=False)
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        qrcode = Qrcode.query.filter(Qrcode.expiration > datetime.utcnow()).filter_by(status=False).filter_by(
            key=qr_key).first()
        if qrcode is not None:
            return jsonify(api_status=True)
        else:
            user_id = user_get_id(api_key)
            qrcore_create = Qrcode()
            qrcore_create.user_id = user_id
            qrcore_create.key = qr_key
            qrcore_create.status = False
            qrcore_create.expiration = datetime.utcnow() + relativedelta(minutes=+2)
            db.session.add(qrcore_create)
            db.session.commit()
            add_log("QR_code_generated", user_id, None)
            return jsonify(api_status=True)


@app.route('/release/status', methods=['POST'])
def release_status():
    version_code = request.form['version_code']
    if version_check(version_code) is False:
        return jsonify(api_status=False)
    else:
        return jsonify(api_status=True)


@app.route('/socialmedia/create', methods=['POST'])
def socialmedia_create():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    media_url = request.form['url']
    type = request.form['type']
    tags = request.form['tags']
    countries = request.form['countries']

    tags = tags.replace('[', '')
    tags = tags.replace(']', '')
    countries = countries.replace('[', '')
    countries = countries.replace(']', '')
    tags = tags.split(',')
    countries = countries.split(',')

    while ('' in tags):
        tags.remove('')

    while ('' in countries):
        countries.remove('')

    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    elif len(tags) < 2:
        return jsonify(api_result="at_least_two_labels_must_be_entered", api_status=False)
    elif len(tags) > 4:
        return jsonify(api_result="up_to_four_labels_must_be_entered", api_status=False)
    elif len(countries) == 0:
        return jsonify(api_result="At_least_one_country_must_be_selected", api_status=False)
    elif len(countries) > 10:
        return jsonify(api_result="A_maximum_of_ten_countries_should_be_selected", api_status=False)
    elif media_url == '':
        return jsonify(api_result="Url_cannot_be_empty", api_status=False)
    elif type == 'null':
        return jsonify(api_result="Select_product_type", api_status=False)
    else:
        parse = urlparse(media_url)
        media_url = "https://"+parse.netloc+parse.path
        if parse.netloc == "www.instagram.com" or parse.netloc == "instagram.com":
            try:
                with urllib.request.urlopen("https://api.instagram.com/oembed/?url=" + media_url) as url:
                    data = json.loads(url.read().decode())
                    media_shortcode = parse.path.replace('p', '', 1)
                    media_shortcode = media_shortcode.replace('/', '')
                    socialmedia = Socialmedia.query.filter_by(media_id=data["media_id"]).first()
                    if socialmedia is not None:
                        return jsonify(api_status=False, api_result="Raffle_already_registered")
                    else:
                        user_id = user_get_id(api_key)
                        socialmedia = Socialmedia()
                        socialmedia.id_share = uuid_short()
                        socialmedia.author_name = data["author_name"]
                        socialmedia.media_id = media_shortcode
                        socialmedia.media_description = data["title"]
                        socialmedia.media_image = 'https://instagram.com/p/'+media_shortcode+'/media/?size=l'
                        socialmedia.media_url = media_url
                        socialmedia.provider_name = data["provider_name"]
                        socialmedia.delete = False
                        socialmedia.disable = False
                        socialmedia.verification = True
                        socialmedia.sponsor = False
                        socialmedia.type = eval(type)
                        socialmedia.creation_date = datetime.utcnow()
                        socialmedia.last_update = datetime.utcnow()
                        db.session.add(socialmedia)
                        db.session.commit()
                        add_social_tags(tags, socialmedia.id)
                        add_social_countries(countries, socialmedia.id)

                        saved = Socialsaved()
                        saved.user_id = user_id
                        saved.social_id = socialmedia.id
                        saved.creation_date = datetime.utcnow()
                        db.session.add(saved)
                        db.session.commit()

                        add_log("raffle_created", user_id, json.dumps({"media_url": media_url}))
                        return jsonify(api_status=True, api_result="The_product_has_been_sent")
            except ValueError:
                return jsonify(api_status=False, api_result="404_not_found")
        else:
            return jsonify(api_status=False, api_result="Invalid_url")


@app.route('/socialmedia/list', methods=['POST'])
def socialmedia_list():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    page = int(request.form['page'])
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user = db.session.query(Users.local).filter_by(id=user_get_id(api_key)).first()
        country = db.session.query(Countries.id).filter_by(country_code=user.local.upper()).first()
        socialmedia = db.session.query(Socialmedia.id_share,Socialmedia.author_name,Socialmedia.media_image,Socialmedia.sponsor,Socialmedia.type).join(Socialcountrytargets,Socialmedia.id == Socialcountrytargets.social_id).filter(Socialmedia.delete==False,Socialmedia.disable==False,Socialmedia.verification==True,Socialcountrytargets.country_id==country, Socialmedia.last_update.between(date_back_to(120), datetime.utcnow())).order_by(desc(Socialmedia.sponsor),desc(Socialmedia.last_update)).paginate(page, 15, False).items
        result = socialmedias_schema.dump(socialmedia)
        return jsonify(result.data)


@app.route('/socialmedia/saved/list', methods=['POST'])
def socialmedia_saved_list():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    page = int(request.form['page'])
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        socialmedia = db.session.query(Socialmedia.id_share,Socialmedia.author_name,Socialmedia.media_image,Socialmedia.sponsor,Socialmedia.type).join(Socialsaved,Socialmedia.id == Socialsaved.social_id).filter(Socialmedia.delete==False,Socialmedia.disable==False,Socialmedia.verification==True).order_by(desc(Socialmedia.sponsor),desc(Socialmedia.last_update)).paginate(page, 15, False).items
        result = socialmedias_schema.dump(socialmedia)
        return jsonify(result.data)


@app.route('/socialmedia/show', methods=['POST'])
def socialmedia_show():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    id_share = request.form['id_share']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user_id = user_get_id(api_key)
        socialmedia_check = SocialMedia.find_one({"id_share": id_share, "delete": False, "disable": False, "verification": True})
        if socialmedia_check is not None:
            socialmedia_statistics(user_id, socialmedia_check['social_id'], False)
            display = Socialstatistics.query.filter_by(social_id=socialmedia_check['social_id'], clicks=False).count()
            author_image = instagram_profile_image(socialmedia_check['author_name'])
            saved_count = Socialsaved.query.filter_by(social_id=socialmedia_check['social_id']).count()
            if saved_count == 1:
                saved = True
            else:
                saved = False

            return jsonify(
                api_status=True,
                id_share=socialmedia_check['id_share'],
                author_name=socialmedia_check['author_name'],
                author_image=author_image,
                media_description=socialmedia_check['media_description'],
                media_image=socialmedia_check['media_image'],
                media_url=socialmedia_check['media_url'],
                sponsor=socialmedia_check['sponsor'],
                type=socialmedia_check['type'],
                display=display,
                saved=saved
            )
        else:
            socialmedia = Socialmedia.query.filter_by(id_share=id_share, delete=False, disable=False, verification=True).first()
            if socialmedia is not None:
                socialmedia_statistics(user_id, socialmedia.id, False)
                display = Socialstatistics.query.filter_by(social_id=socialmedia.id, clicks=False).count()
                author_image = instagram_profile_image(socialmedia.author_name)
                saved_count = Socialsaved.query.filter_by(social_id=socialmedia.id).count()
                if saved_count == 1:
                    saved = True
                else:
                    saved = False

                SocialMedia.insert_one(
                    {"social_id": socialmedia.id,
                     "id_share": socialmedia.id_share,
                     "author_name": socialmedia.author_name,
                     "media_id": socialmedia.media_id,
                     "media_description": socialmedia.media_description,
                     "media_image": socialmedia.media_image,
                     "media_url": socialmedia.media_url,
                     "provider_name": socialmedia.provider_name,
                     "delete": socialmedia.delete,
                     "disable": socialmedia.disable,
                     "verification": socialmedia.verification,
                     "sponsor": socialmedia.sponsor,
                     "type": socialmedia.type,
                     "creation_date": socialmedia.creation_date,
                     "last_update": socialmedia.last_update,
                     "cache_expiration": cache_expiration(72)
                     })

                return jsonify(
                    api_status=True,
                    id_share=socialmedia.id_share,
                    author_name=socialmedia.author_name,
                    author_image=author_image,
                    media_description=socialmedia.media_description,
                    media_image=socialmedia.media_image,
                    media_url=socialmedia.media_url,
                    sponsor=socialmedia.sponsor,
                    type=socialmedia.type,
                    display=display,
                    saved=saved
                )
            else:
                return jsonify(api_status=False, api_result='404_not_found')


@app.route('/socialmedia/statistics', methods=['POST'])
def socialmedia_statistics_clicks():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    id_share = request.form['id_share']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user_id = user_get_id(api_key)
        social_id = social_get_id(id_share)
        socialmedia_statistics(user_id,social_id,True)
        return jsonify(api_status=True)


@app.route('/socialmedia/saved', methods=['POST'])
def socialmedia_saved():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    id_share = request.form['id_share']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user_id = user_get_id(api_key)
        social_id = social_get_id(id_share)
        socialmedia = Socialsaved.query.filter_by(social_id=social_id).first()
        if socialmedia is not None:
            try:
                db.session.query(Socialsaved).filter(Socialsaved.user_id == user_id).filter(Socialsaved.social_id == social_id).delete()
                db.session.commit()
                return jsonify(api_status=False)
            except:
                db.session.rollback()
                return jsonify(api_status=False)
        else:
            saved = Socialsaved()
            saved.user_id = user_id
            saved.social_id = social_id
            saved.creation_date = datetime.utcnow()
            db.session.add(saved)
            db.session.commit()
        return jsonify(api_status=True)


@app.route('/socialmedia/report', methods=['POST'])
def socialmedia_report():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    id_share = request.form['id_share']
    description = request.form['description']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    elif description.strip() is '':
        return jsonify(api_status=False, api_result='feedback_cant_be_left_blank')
    elif len(description) > 350:
        return jsonify(api_status=False, api_result='the_feedback_cannot_be_more_than_350_characters')
    else:
        user_id = user_get_id(api_key)
        social_id = social_get_id(id_share)
        report = Socialreports()
        report.user_id = user_id
        report.social_id = social_id
        report.description = description
        report.read = False
        report.creation_date = datetime.utcnow()
        db.session.add(report)
        db.session.commit()
        return jsonify(api_status=True, api_result='Feedback_sent')


@app.route('/socialmedia/search', methods=['POST'])
def socialmedia_search():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    tag = request.form['tag']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        tags = db.session.query(Tags).filter(Tags.tag_name.like(tag+'%')).all()
        result = socialsearchs_schema.dump(tags)
        return jsonify(result.data)


@app.route('/socialmedia/search/list', methods=['POST'])
def socialmedia_search_list():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    tag_id = request.form['tag_id']
    page = int(request.form['page'])
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        socialmedia = db.session.query(Socialmedia.id_share, Socialmedia.author_name, Socialmedia.media_image,
                                       Socialmedia.sponsor,Socialmedia.type).join(Socialtagtargets,
                                                                 Socialmedia.id == Socialtagtargets.social_id).filter(
            Socialmedia.delete == False, Socialmedia.disable == False, Socialmedia.verification == True, Socialtagtargets.tag_id == tag_id).order_by(
            desc(Socialmedia.sponsor), desc(Socialmedia.last_update)).paginate(page, 15, False).items
        result = socialmedias_schema.dump(socialmedia)
        if len(result.data) > 0:
            if page == 1:
                user = Users.query.filter_by(id=user_get_id(api_key)).first()
                tag_search = Tags.query.filter_by(id=tag_id).first()
                Search.insert_one(
                    {"tag_id": tag_search.id,
                     "tag_name": tag_search.tag_name,
                     "locale": user.local,
                     "user_id": user.id,
                     "create_date": datetime.utcnow()
                     })
        return jsonify(result.data)


@app.route('/socialmedia/search/top', methods=['POST'])
def socialmedia_search_top():
    api_key = request.form['api_key']
    version_code = request.form['version_code']
    if key_check(api_key) is False:
        return jsonify(api_status=False, api_result='Please_log_in_again')
    elif version_check(version_code) is False:
        return jsonify(api_status=False, api_result='New_version_available_please_update')
    else:
        user = Users.query.filter_by(id=user_get_id(api_key)).first()
        pipeline = [
            {"$unwind": "$tag_name"},
            {"$match": {"locale": user.local, "create_date": {"$gte": date_back_to(360), "$lte": datetime.utcnow()}}},
            {"$group": {"_id": {"tag_id": "$tag_id", "tag_name": "$tag_name"},"count": {"$sum": 1}}},
            {"$sort": SON([("count", -1), ("_id", -1)])},
            {"$limit": 8}
        ]

        result = list(Search.aggregate(pipeline))
        data = []
        for search in result:
            item = {}
            item["id"] = search['_id']['tag_id']
            item["tag_name"] = search['_id']['tag_name']
            data.append(item)
        return jsonify(data)


if __name__ == '__main__':
    app.run(host='192.168.1.3', port=5000, debug=True)
