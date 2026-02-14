from flask import Flask, render_template, request, redirect, session, url_for, flash, abort
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, EqualTo, Email
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
import random
from werkzeug.utils import secure_filename
from sqlalchemy import create_engine, Column, Integer, String, Text, TIMESTAMP, ForeignKey, Table, UniqueConstraint, Boolean
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.orm import scoped_session, sessionmaker, relationship, backref
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from sqlalchemy import or_ # For complex queries
import os


app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'uma_senha_super_secreta_qualquer_para_desenvolvimento')

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

app.config['RECAPTCHA_USE_SSL'] = False

app.config['RECAPTCHA_PUBLIC_KEY'] = os.environ.get('RECAPTCHA_PUBLIC_KEY', '')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.environ.get('RECAPTCHA_PRIVATE_KEY', '')
app.config['RECAPTCHA_OPTIONS'] = {'theme': 'white'}

# Print reCAPTCHA config for debugging
print(f"RECAPTCHA_PUBLIC_KEY: {app.config['RECAPTCHA_PUBLIC_KEY']}")
print(f"RECAPTCHA_PRIVATE_KEY: {'*' * len(app.config['RECAPTCHA_PRIVATE_KEY']) if app.config['RECAPTCHA_PRIVATE_KEY'] else 'NOT SET'}")
print(f"RECAPTCHA_USE_SSL: {app.config['RECAPTCHA_USE_SSL']}")

app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0 # Disable caching for static files in development

# Flask-Mail configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() in ('true', '1', 't')
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
app.config['MAIL_TIMEOUT'] = int(os.environ.get('MAIL_TIMEOUT', 60)) # Set email sending timeout to 60 seconds

# Uploads Configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

PER_PAGE = 20 # Number of users to display per page

COUNTRIES = sorted([
    "Brasil", "Estados Unidos", "Canadá", "México", "Argentina", "Chile", "Colômbia", "Portugal", "Espanha", "França",
    "Alemanha", "Itália", "Reino Unido", "Irlanda", "Suíça", "Bélgica", "Holanda", "Suécia", "Noruega", "Dinamarca",
    "Rússia", "China", "Índia", "Japão", "Coreia do Sul", "Austrália", "Nova Zelândia", "África do Sul", "Egito", "Nigéria",
    "Tailândia", "Vietnã", "Indonésia", "Malásia", "Filipinas", "Turquia", "Grécia", "Polônia", "Ucrânia", "Romênia",
    "Hungria", "República Tcheca", "Áustria", "Irlanda", "Finlândia", "Singapura", "Hong Kong", "Emirados Árabes Unidos",
    "Arábia Saudita", "Israel", "Catar", "Kuwait", "Bahrein", "Omã", "México", "Peru", "Equador", "Bolívia", "Paraguai",
    "Uruguai", "Venezuela", "Cuba", "Jamaica", "República Dominicana", "Porto Rico", "Colômbia", "Panamá", "Costa Rica",
    "Guatemala", "Honduras", "El Salvador", "Nicarágua", "Canadá", "Noruega", "Suécia", "Dinamarca", "Finlândia",
    "Islândia", "Estônia", "Letônia", "Lituânia", "Bielorrússia", "Moldávia", "Geórgia", "Armênia", "Azerbaijão",
    "Cazaquistão", "Uzbequistão", "Turcomenistão", "Quirguistão", "Tajiquistão", "Afeganistão", "Paquistão", "Bangladesh",
    "Sri Lanka", "Nepal", "Butão", "Maldivas", "Mianmar", "Laos", "Camboja", "Timor-Leste", "Coreia do Norte", "Fiji",
    "Papua Nova Guiné", "Ilhas Salomão", "Vanuatu", "Nova Caledônia", "Samoa", "Tonga", "Tuvalu", "Quiribati", "Nauru",
    "Palau", "Micronésia", "Ilhas Marshall", "Ilhas Cook", "Niue", "Togo", "Benim", "Gana", "Costa do Marfim", "Libéria",
    "Serra Leoa", "Guiné", "Guiné-Bissau", "Gâmbia", "Senegal", "Mauritânia", "Mali", "Burkina Faso", "Níger", "Chade",
    "Sudão", "Sudão do Sul", "Eritreia", "Djibuti", "Etiópia", "Somália", "Quênia", "Uganda", "Ruanda", "Burundi",
    "Tanzânia", "Comores", "Seicheles", "Madagascar", "Maurício", "Malauí", "Moçambique", "Zâmbia", "Zimbábue", "Botsuana",
    "Namíbia", "Angola", "Congo (Brazzaville)", "Congo (Kinshasa)", "Gabão", "Guiné Equatorial", "Camarões",
    "República Centro-Africana", "São Tomé e Príncipe", "Cabo Verde", "Argélia", "Tunísia", "Marrocos", "Líbia", "Egito",
    "Sérvia", "Croácia", "Bósnia e Herzegovina", "Montenegro", "Albânia", "Macedônia do Norte", "Bulgária", "Chipre",
    "Malta", "Luxemburgo", "Eslovênia", "Eslováquia", "Lichtenstein", "Andorra", "Mônaco", "San Marino", "Vaticano",
    "Liechtenstein", "São Marino", "Liechtenstein", "Montserrat", "Guiana Francesa", "Reunião", "Martinica", "Guadalupe",
    "Polinésia Francesa", "Nova Caledônia", "Wallis e Futuna", "Mayotte", "São Pedro e Miquelão", "Terras Austrais e Antárticas Francesas",
    "Ilhas Faroé", "Groenlândia", "Svalbard e Jan Mayen", "Gibraltar", "Ilha de Man", "Jersey", "Guernsey", "Aland",
    "Curaçao", "Aruba", "São Martinho (Países Baixos)", "Bonaire, Santo Eustáquio e Saba", "Anguila", "Bermudas",
    "Ilhas Virgens Britânicas", "Ilhas Cayman", "Ilhas Malvinas", "Turks e Caicos", "Santa Helena, Ascensão e Tristão da Cunha",
    "Geórgia do Sul e Ilhas Sandwich do Sul", "Território Britânico do Oceano Índico", "Pitcairn", "Ilhas Virgens Americanas",
    "Samoa Americana", "Guam", "Marianas Setentrionais", "Estados Federados da Micronésia", "Ilhas Marshall", "Palau",
    "Porto Rico", "Wake Island", "Midway Atoll", "Johnston Atoll", "Kingman Reef", "Palmyra Atoll", "Jarvis Island",
    "Baker Island", "Howland Island", "Ilha Navassa", "Niue", "Tokelau", "Ilhas Cook", "Tonga", "Samoa", "Tuvalu",
    "Quiribati", "Nauru", "Wallis e Futuna", "Kiribati", "Vanuatu", "Ilhas Salomão", "Timor-Leste", "Papua Nova Guiné",
    "Fiji", "Vanuatu", "Nauru", "Camboja", "Laos", "Mianmar", "Filipinas", "Indonésia", "Malásia", "Singapura", "Tailândia",
    "Vietnã", "Brunei", "Líbano", "Jordânia", "Síria", "Iraque", "Irã", "Chipre", "Geórgia", "Armênia", "Azerbaijão",
    "Cazaquistão", "Uzbequistão", "Turcomenistão", "Quirguistão", "Tajiquistão", "Mongólia", "Coreia do Norte", "Coreia do Sul",
    "Japão", "Hong Kong", "Macau", "Taiwan", "China", "Índia", "Paquistão", "Bangladesh", "Sri Lanka", "Nepal", "Butão",
    "Maldivas", "Afeganistão", "Turquia", "Grécia", "Bulgária", "Romênia", "Sérvia", "Croácia", "Bósnia e Herzegovina",
    "Montenegro", "Albânia", "Macedônia do Norte", "Kosovo", "Hungria", "Eslováquia", "República Tcheca", "Polônia",
    "Lituânia", "Letônia", "Estônia", "Finlândia", "Suécia", "Noruega", "Islândia", "Dinamarca", "Irlanda", "Reino Unido",
    "Países Baixos", "Bélgica", "Luxemburgo", "França", "Alemanha", "Suíça", "Áustria", "Itália", "Espanha", "Portugal",
    "Andorra", "Mônaco", "San Marino", "Vaticano", "Malta", "Chipre", "Gibraltar", "Ilha de Man", "Jersey", "Guernsey"
])


# Mapping of country names to their ISO 3166-1 alpha-2 codes
# This list is not exhaustive and focuses on countries in the `COUNTRIES` list and common ones.
COUNTRY_CODE_MAP = {
    "Brasil": "BR",
    "Estados Unidos": "US",
    "Canadá": "CA",
    "México": "MX",
    "Argentina": "AR",
    "Chile": "CL",
    "Colômbia": "CO",
    "Portugal": "PT",
    "Espanha": "ES",
    "França": "FR",
    "Alemanha": "DE",
    "Itália": "IT",
    "Reino Unido": "GB",
    "Irlanda": "IE",
    "Suíça": "CH",
    "Bélgica": "BE",
    "Holanda": "NL", # Netherlands
    "Suécia": "SE",
    "Noruega": "NO",
    "Dinamarca": "DK",
    "Rússia": "RU",
    "China": "CN",
    "Índia": "IN",
    "Japão": "JP",
    "Coreia do Sul": "KR",
    "Austrália": "AU",
    "Nova Zelândia": "NZ",
    "África do Sul": "ZA",
    "Egito": "EG",
    "Nigéria": "NG",
    "Polônia": "PL",
    "Ucrânia": "UA",
    "Turquia": "TR",
    "Grécia": "GR",
    "Tailândia": "TH",
    "Vietnã": "VN",
    "Indonésia": "ID",
    "Malásia": "MY",
    "Filipinas": "PH",
    "Cuba": "CU",
    "Peru": "PE",
    "Emirados Árabes Unidos": "AE",
    "Arábia Saudita": "SA",
    "Israel": "IL",
    "Catar": "QA",
    "Kuwait": "KW",
    "Hong Kong": "HK",
    "Singapura": "SG",
    "Finlândia": "FI",
    "Islândia": "IS",
    "Sérvia": "RS",
    "Croácia": "HR",
    "Bósnia e Herzegovina": "BA",
    "Hungria": "HU",
    "República Tcheca": "CZ",
    "Áustria": "AT",
    "Luxemburgo": "LU",
    "Malta": "MT",
    "Chipre": "CY",
    "Romênia": "RO",
    "Bulgária": "BG",
    "Eslováquia": "SK",
    "Eslovênia": "SI",
    "Lituânia": "LT",
    "Letônia": "LV",
    "Estônia": "EE",
    "Bielorrússia": "BY",
    "Moldávia": "MD",
    "Geórgia": "GE",
    "Armênia": "AM",
    "Azerbaijão": "AZ",
    "Cazaquistão": "KZ",
    "Uzbequistão": "UZ",
    "Turcomenistão": "TM",
    "Quirguistão": "KG",
    "Tajiquistão": "TJ",
    "Afeganistão": "AF",
    "Paquistão": "PK",
    "Bangladesh": "BD",
    "Sri Lanka": "LK",
    "Nepal": "NP",
    "Butão": "BT",
    "Maldivas": "MV",
    "Mianmar": "MM",
    "Laos": "LA",
    "Camboja": "KH",
    "Timor-Leste": "TL",
    "Coreia do Norte": "KP",
    "Fiji": "FJ",
    "Papua Nova Guiné": "PG",
    "Ilhas Salomão": "SB",
    "Vanuatu": "VU",
    "Nova Caledônia": "NC",
    "Samoa": "WS",
    "Tonga": "TO",
    "Tuvalu": "TV",
    "Quiribati": "KI",
    "Nauru": "NR",
    "Palau": "PW",
    "Micronésia": "FM",
    "Ilhas Marshall": "MH",
    "Ilhas Cook": "CK",
    "Niue": "NU",
    "Togo": "TG",
    "Benim": "BJ",
    "Gana": "GH",
    "Costa do Marfim": "CI",
    "Libéria": "LR",
    "Serra Leoa": "SL",
    "Guiné": "GN",
    "Guiné-Bissau": "GW",
    "Gâmbia": "GM",
    "Senegal": "SN",
    "Mauritânia": "MR",
    "Mali": "ML",
    "Burkina Faso": "BF",
    "Níger": "NE",
    "Chade": "TD",
    "Sudão": "SD",
    "Sudão do Sul": "SS",
    "Eritreia": "ER",
    "Djibuti": "DJ",
    "Etiópia": "ET",
    "Somália": "SO",
    "Quênia": "KE",
    "Uganda": "UG",
    "Ruanda": "RW",
    "Burundi": "BI",
    "Tanzânia": "TZ",
    "Comores": "KM",
    "Seicheles": "SC",
    "Madagascar": "MG",
    "Maurício": "MU",
    "Malauí": "MW",
    "Moçambique": "MZ",
    "Zâmbia": "ZM",
    "Zimbábue": "ZW",
    "Botsuana": "BW",
    "Namíbia": "NA",
    "Angola": "AO",
    "Congo (Brazzaville)": "CG",
    "Congo (Kinshasa)": "CD",
    "Gabão": "GA",
    "Guiné Equatorial": "GQ",
    "Camarões": "CM",
    "República Centro-Africana": "CF",
    "São Tomé e Príncipe": "ST",
    "Cabo Verde": "CV",
    "Argélia": "DZ",
    "Tunísia": "TN",
    "Marrocos": "MA",
    "Líbia": "LY",
    "Svalbard e Jan Mayen": "SJ", # Special case, often represented as NO
    "Gibraltar": "GI",
    "Ilha de Man": "IM",
    "Jersey": "JE",
    "Guernsey": "GG",
    "Aland": "AX",
    "Curaçao": "CW",
    "Aruba": "AW",
    "São Martinho (Países Baixos)": "SX",
    "Bonaire, Santo Eustáquio e Saba": "BQ",
    "Anguila": "AI",
    "Bermudas": "BM",
    "Ilhas Virgens Britânicas": "VG",
    "Ilhas Cayman": "KY",
    "Ilhas Malvinas": "FK",
    "Turks e Caicos": "TC",
    "Santa Helena, Ascensão e Tristão da Cunha": "SH",
    "Geórgia do Sul e Ilhas Sandwich do Sul": "GS",
    "Território Britânico do Oceano Índico": "IO",
    "Pitcairn": "PN",
    "Ilhas Virgens Americanas": "VI",
    "Samoa Americana": "AS",
    "Guam": "GU",
    "Marianas Setentrionais": "MP",
    "Estados Federados da Micronésia": "FM",
    "Wake Island": "UM", # Minor Outlying Islands, often just US
    "Porto Rico": "PR",
    "Montserrat": "MS",
    "Guiana Francesa": "GF",
    "Reunião": "RE",
    "Martinica": "MQ",
    "Guadalupe": "GP",
    "Polinésia Francesa": "PF",
    "Wallis e Futuna": "WF",
    "Mayotte": "YT",
    "São Pedro e Miquelão": "PM",
    "Terras Austrais e Antárticas Francesas": "TF",
    "Ilhas Faroé": "FO",
    "Groenlândia": "GL",
    "Andorra": "AD",
    "Mônaco": "MC",
    "San Marino": "SM",
    "Vaticano": "VA",
    "Liechtenstein": "LI",
    "Kosovo": "XK" # User-assigned code, not ISO 3166-1 alpha-2, but commonly used for emojis
}

def get_emoji_flag(country_code):
    """Converts a two-letter country code to its emoji flag."""
    if not country_code or len(country_code) != 2:
        return ""
    return "".join(chr(0x1F1E6 + (ord(c) - ord('A'))) for c in country_code.upper())

def country_to_emoji(country_name):
    """
    Converts a full country name to its emoji flag.
    Returns an empty string if the country name is not found in the map.
    """
    country_code = COUNTRY_CODE_MAP.get(country_name)
    if country_code:
        return get_emoji_flag(country_code)
    return ""

from werkzeug.utils import secure_filename


mail = Mail(app)
# s = URLSafeTimedSerializer(app.config['SECRET_KEY']) # REMOVE this line


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    # email = StringField('Email', validators=[DataRequired(), Email()]) # REMOVED
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    recaptcha = RecaptchaField()





# Configuração do banco de dados PostgreSQL com SQLAlchemy
# DATABASE_URL = "postgresql://mingleoo_db_user:ekTxiRGjD5nVj5P3zLTFdcRt6p34PmWE@dpg-d5tu2f7pm1nc73fnbt1g-a.virginia-postgres.render.com/mingleoo_db"
DATABASE_URL = os.environ.get('DATABASE_URL', "postgresql://mingleoo_db_user:ekTxiRGjD5nVj5P3zLTFdcRt6p34PmWE@dpg-d5tu2f7pm1nc73fnbt1g-a.virginia-postgres.render.com/mingleoo_db")
engine = create_engine(DATABASE_URL)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

# Modelos ORM
user_tags = Table('user_tags', Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    Column('tag_id', Integer, ForeignKey('tags.id', ondelete='CASCADE'), primary_key=True)
)

class Account(Base):
    __tablename__ = 'accounts'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=False, nullable=True) # Modified to be nullable and non-unique
    password_hash = Column(String(255), nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now())
    # confirmed = Column(Boolean, nullable=False, default=False) # REMOVED
    # confirmed_on = Column(TIMESTAMP, nullable=True) # REMOVED
    user = relationship('User', uselist=False, back_populates='account', cascade="all, delete-orphan", single_parent=True, lazy=True)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    account_id = Column(Integer, ForeignKey('accounts.id', ondelete='CASCADE'), unique=True, nullable=False)
    account = relationship('Account', back_populates='user')
    name = Column(String(80), nullable=False)
    bio = Column(Text)
    avatar_url = Column(String(255), nullable=False, default='/static/images/1.png')
    banner_url = Column(String(255), nullable=False, default='')
    age = Column(Integer, nullable=True)
    nationality = Column(String(80), nullable=True)
    gender = Column(String(50), nullable=True)
    sexuality = Column(String(50), nullable=True)
    profile_color = Column(String(7), nullable=False, default='#e24040') # Default to a red color
    background_color = Column(String(7), nullable=False, default='#f8f8f8') # Default to a light gray color
    tags = relationship('Tag', secondary=user_tags, back_populates='users')
    links = relationship('UserLink', backref='user', cascade="all, delete-orphan")
    sections = relationship('UserSection', backref='user', cascade="all, delete-orphan")

    following_users = relationship(
        'User', 
        secondary='follows',
        primaryjoin="User.id == Follow.follower_id",
        secondaryjoin="User.id == Follow.followed_id",
        backref='follower_users',
        viewonly=True
    )


class Tag(Base):
    __tablename__ = 'tags'
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)
    users = relationship('User', secondary=user_tags, back_populates='tags')

class Follow(Base):
    __tablename__ = 'follows'
    follower_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
    followed_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
    timestamp = Column(TIMESTAMP, server_default=func.now())
    is_read = Column(Boolean, default=False)
    
    __table_args__ = (UniqueConstraint('follower_id', 'followed_id', name='_follower_followed_uc'),)

    follower = relationship('User', foreign_keys=[follower_id], backref=backref('following_associations', cascade="all, delete-orphan"))
    followed = relationship('User', foreign_keys=[followed_id], backref=backref('followed_by_associations', cascade="all, delete-orphan"))

class UserMessage(Base):
    __tablename__ = 'user_messages'
    id = Column(Integer, primary_key=True)
    sender_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    recipient_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    content = Column(Text, nullable=False)
    timestamp = Column(TIMESTAMP, server_default=func.now())
    is_read = Column(Boolean, default=False)

    sender = relationship('User', foreign_keys=[sender_id], backref=backref('sent_usermessages', lazy='dynamic'))
    recipient = relationship('User', foreign_keys=[recipient_id], backref=backref('received_usermessages', lazy='dynamic'))

class UserLink(Base):
    __tablename__ = 'user_links'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'))
    platform = Column(String(50))
    url = Column(Text)

class UserSection(Base):
    __tablename__ = 'user_sections'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'))
    title = Column(String(100))
    content = Column(Text)


def shutdown_session(exception=None):
    db_session.remove()

def current_user():
    if "account_id" not in session:
        return None
    return User.query.filter(User.account_id == session["account_id"]).first()

@app.context_processor
def inject_global_data():
    logged_in_user = current_user()
    if logged_in_user:
        notification_count = Follow.query.filter_by(followed_id=logged_in_user.id, is_read=False).count() # Only unread follows
        unread_message_count = UserMessage.query.filter_by(recipient_id=logged_in_user.id, is_read=False).count()
        logged_in_user_flag_emoji = country_to_emoji(logged_in_user.nationality) if logged_in_user.nationality else ""
        return dict(
            logged_in_user=logged_in_user,
            notification_count=notification_count,
            unread_message_count=unread_message_count,
            logged_in_user_flag_emoji=logged_in_user_flag_emoji
        )
    return dict(logged_in_user=None, notification_count=0, unread_message_count=0, logged_in_user_flag_emoji="")


@app.route("/")
def index():
    page = request.args.get('page', 1, type=int) # Get page number from URL, default to 1
    if current_user():
        return redirect(url_for("dashboard"))
    
    # Calculate offset and limit for manual pagination
    offset = (page - 1) * PER_PAGE
    
    # Fetch users with offset and limit
    base_query = User.query.join(Account).order_by(Account.created_at.desc())
    users = base_query.offset(offset).limit(PER_PAGE).all()
    
    # Manually calculate pagination info
    total_users = base_query.count()
    has_next = (page * PER_PAGE) < total_users
    has_prev = page > 1
    next_num = page + 1 if has_next else None
    prev_num = page - 1 if has_prev else None
    
    pagination_info = {
        'page': page,
        'per_page': PER_PAGE,
        'total': total_users,
        'has_next': has_next,
        'has_prev': has_prev,
        'next_num': next_num,
        'prev_num': prev_num,
        'items': users # Current page items
    }

    return render_template(
        "index.html",
        pagination=pagination_info, # Pass the dictionary with pagination info
        users=pagination_info['items'], # Pass items for current page
        total_users=pagination_info['total'] # Total count of users
    )


@app.route("/search")
def search():
    tag_name = request.args.get("tag")
    if not tag_name:
        return redirect(url_for("index"))
    
    tag = Tag.query.filter_by(name=tag_name).first()
    users = tag.users if tag else []
    
    return render_template("search.html", users=users, tag=tag_name)

@app.route("/notifications")
def notifications():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    follows_received = Follow.query.filter_by(followed_id=user.id).order_by(Follow.timestamp.desc()).all()
    
    # Mark all unread follow notifications as read
    db_session.query(Follow).filter_by(followed_id=user.id, is_read=False).update({"is_read": True})
    db_session.commit()

    notifications_list = [
        {
            "from_user_id": f.follower.id,
            "from_user_name": f.follower.name,
            "created_at": f.timestamp,
            "is_read": f.is_read
        }
        for f in follows_received
    ]

    return render_template(
        "notifications.html",
        notifications=notifications_list
    )

@app.route("/surprise")
def surprise():
    user = User.query.order_by(func.random()).first()
    if not user:
        return redirect(url_for("index"))
    return redirect(url_for("view_profile", user_id=user.id))

@app.route("/follow/<int:user_id>", methods=["POST"])
def follow_user(user_id):
    follower = current_user()
    if not follower:
        return redirect(url_for("login"))

    if follower.id == user_id:
        flash("Você não pode se Mingle com você mesmo.", "error")
        return redirect(url_for("view_profile", user_id=user_id))

    followed = User.query.get(user_id)
    if not followed:
        flash("Usuário não encontrado.", "error")
        return redirect(url_for("dashboard"))

    existing_follow = Follow.query.filter_by(follower_id=follower.id, followed_id=followed.id).first()
    if existing_follow:
        flash(f"Você já fez Mingle com {followed.name}.", "info")
        return redirect(url_for("view_profile", user_id=user_id))

    new_follow = Follow(follower_id=follower.id, followed_id=followed.id, is_read=False) # Newly created follow is unread
    db_session.add(new_follow)
    db_session.commit()
    flash(f"Você fez Mingle com {followed.name}!", "success")
    return redirect(url_for("view_profile", user_id=user_id))

@app.route("/unfollow/<int:user_id>", methods=["POST"])
def unfollow_user(user_id):
    follower = current_user()
    if not follower:
        return redirect(url_for("login"))

    followed = User.query.get(user_id)
    if not followed:
        flash("Usuário não encontrado.", "error")
        return redirect(url_for("dashboard"))

    follow = Follow.query.filter_by(follower_id=follower.id, followed_id=followed.id).first()
    if follow:
        db_session.delete(follow)
        db_session.commit()
        flash(f"Você desfez o Mingle com {followed.name}.", "info")
    else:
        flash("Você não fez Mingle com este usuário.", "error")

    return redirect(url_for("view_profile", user_id=user_id))

@app.route("/like/<int:user_id>", methods=["POST"])
def like_user(user_id):
    liker = current_user()
    if not liker:
        return redirect(url_for("login"))

    if liker.id == user_id:
        flash("Você não pode curtir seu próprio perfil.", "error")
        return redirect(url_for("view_profile", user_id=user_id))

    liked_user = User.query.get(user_id)
    if not liked_user:
        flash("Usuário não encontrado.", "error")
        return redirect(url_for("dashboard"))

    existing_like = Like.query.filter_by(user_id=liked_user.id, liker_id=liker.id).first()
    if existing_like:
        flash(f"Você já curtiu o perfil de {liked_user.name}.", "info")
        return redirect(url_for("view_profile", user_id=user_id))

    new_like = Like(user_id=liked_user.id, liker_id=liker.id)
    db_session.add(new_like)
    db_session.commit()
    flash(f"Você curtiu o perfil de {liked_user.name}!", "success")
    return redirect(url_for("view_profile", user_id=user_id))

@app.route("/unlike/<int:user_id>", methods=["POST"])
def unlike_user(user_id):
    liker = current_user()
    if not liker:
        return redirect(url_for("login"))

    liked_user = User.query.get(user_id)
    if not liked_user:
        flash("Usuário não encontrado.", "error")
        return redirect(url_for("dashboard"))

    like = Like.query.filter_by(user_id=liked_user.id, liker_id=liker.id).first()
    if like:
        db_session.delete(like)
        db_session.commit()
        flash(f"Você descurtiu o perfil de {liked_user.name}.", "info")
    else:
        flash("Você não curtiu este perfil.", "error")

    return redirect(url_for("view_profile", user_id=user_id))

@app.route("/messages")
def list_conversations():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    # Find unique users with whom the current user has exchanged messages
    conversations = []
    
    # Messages sent by current user
    sent_recipients = db_session.query(User).join(UserMessage, User.id == UserMessage.recipient_id).filter(UserMessage.sender_id == user.id).distinct().all()
    for recipient in sent_recipients:
        last_message = UserMessage.query.filter(
            or_(
                (UserMessage.sender_id == user.id) & (UserMessage.recipient_id == recipient.id),
                (UserMessage.sender_id == recipient.id) & (UserMessage.recipient_id == user.id)
            )
        ).order_by(UserMessage.timestamp.desc()).first()
        if last_message: # Ensure there's a message before adding to conversations
            conversations.append({'user': recipient, 'last_message': last_message})

    # Messages received by current user, excluding those already in sent_recipients
    received_senders = db_session.query(User).join(UserMessage, User.id == UserMessage.sender_id).filter(
        UserMessage.recipient_id == user.id,
        ~User.id.in_([r.id for r in sent_recipients])
    ).distinct().all()
    for sender in received_senders:
        last_message = UserMessage.query.filter(
            or_(
                (UserMessage.sender_id == user.id) & (UserMessage.recipient_id == sender.id),
                (UserMessage.sender_id == sender.id) & (UserMessage.recipient_id == user.id)
            )
        ).order_by(UserMessage.timestamp.desc()).first()
        if last_message: # Ensure there's a message before adding to conversations
            conversations.append({'user': sender, 'last_message': last_message})

    # Sort conversations by last message timestamp
    conversations.sort(key=lambda c: c['last_message'].timestamp, reverse=True)
    
    return render_template("messages.html", conversations=conversations)

@app.route("/messages/<int:user_id>", methods=["GET", "POST"])
def view_conversation(user_id):
    current_user_obj = current_user()
    if not current_user_obj:
        return redirect(url_for("login"))

    other_user = User.query.get(user_id)
    if not other_user:
        flash("Usuário não encontrado.", "error")
        return redirect(url_for("list_conversations"))

    if request.method == "POST":
        content = request.form["content"].strip()
        if content:
            new_message = UserMessage(sender_id=current_user_obj.id, recipient_id=user_id, content=content)
            db_session.add(new_message)
            db_session.commit()
            flash("Mensagem enviada!", "success")
        else:
            flash("A mensagem não pode estar vazia.", "error")
        return redirect(url_for("view_conversation", user_id=user_id))

    # Fetch messages between current_user and other_user
    messages = UserMessage.query.filter(
        or_(
            (UserMessage.sender_id == current_user_obj.id) & (UserMessage.recipient_id == user_id),
            (UserMessage.sender_id == user_id) & (UserMessage.recipient_id == current_user_obj.id)
        )
    ).order_by(UserMessage.timestamp).all()

    # Mark received messages as read
    db_session.query(UserMessage).filter_by(recipient_id=current_user_obj.id, sender_id=user_id, is_read=False).update({"is_read": True})
    db_session.commit()
    
    return render_template("conversation.html", other_user=other_user, messages=messages, current_user_id=current_user_obj.id)


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per day")
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        if Account.query.filter_by(username=username).first():
            flash("Usuário já existe", "error")
            return redirect(url_for("register"))
        
        password_hash = generate_password_hash(password)
        new_account = Account(username=username, password_hash=password_hash)
        
        new_user = User(name=username)
        new_account.user = new_user

        db_session.add(new_account)
        db_session.commit()
        
        flash('Registro concluído com sucesso! Bem-vindo ao Mingleoo.', 'success')
        
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        account = Account.query.filter_by(username=username).first()

        if account and check_password_hash(account.password_hash, password):
            session["account_id"] = account.id
            return redirect(url_for("dashboard"))
        
        flash("Usuário ou senha inválidos", "error")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("account_id", None)
    flash("Você foi desconectado.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    notification_count = Follow.query.filter_by(followed_id=user.id).count()
    
    is_uncustomized_profile = (
        user.bio is None or user.bio == "" or 
        user.avatar_url == '/static/images/1.png'
    )

    user_tag_ids = [tag.id for tag in user.tags]
    compatible_users = []
    if user_tag_ids:
        followed_ids = [f.followed_id for f in user.following_associations if f.follower_id == user.id]
        
        compatible_users = db_session.query(
            User.id, User.name, User.bio, User.avatar_url, func.count(user_tags.c.tag_id).label('common_tags')
        ).join(user_tags).filter(
            user_tags.c.tag_id.in_(user_tag_ids),
            User.id != user.id,
            User.id.notin_(followed_ids)
        ).group_by(User.id, User.name, User.bio, User.avatar_url).order_by(func.count(user_tags.c.tag_id).desc()).all()


    return render_template(
        "dashboard.html",
        username=user.name,
        notification_count=notification_count,
        compatible_users=compatible_users,
        is_uncustomized_profile=is_uncustomized_profile
    )

@app.route("/ai-info")
def ai_info():
    return render_template("ai_info.html")

@app.route("/how-it-works")
def how_it_works():
    return render_template("how_it_works.html")


@app.route("/profile/<int:user_id>")
def view_profile(user_id):
    viewed_user = User.query.get(user_id)
    if not viewed_user:
        return redirect(url_for("index"))
    
    logged_in_user = current_user()
    is_following = False
    has_liked = False
    if logged_in_user:
        is_following = Follow.query.filter_by(follower_id=logged_in_user.id, followed_id=viewed_user.id).first() is not None
        has_liked = Like.query.filter_by(user_id=viewed_user.id, liker_id=logged_in_user.id).first() is not None
        notification_count = Follow.query.filter_by(followed_id=logged_in_user.id).count()
    else:
        notification_count = 0

    user_dict = {
        'id': viewed_user.id, 
        'name': viewed_user.name, 
        'bio': viewed_user.bio, 
        'avatar_url': viewed_user.avatar_url,
        'banner_url': viewed_user.banner_url,
        'profile_color': viewed_user.profile_color,
        'background_color': viewed_user.background_color,
        'age': viewed_user.age,
        'nationality': viewed_user.nationality,
        'gender': viewed_user.gender,
        'sexuality': viewed_user.sexuality,
        'flag_emoji': country_to_emoji(viewed_user.nationality) if viewed_user.nationality else ""
    }
    sections_list = [{'title': s.title, 'content': s.content} for s in viewed_user.sections]
    tags_list = [tag.name for tag in viewed_user.tags]
    links_list = [{'platform': l.platform, 'url': l.url} for l in viewed_user.links]
    
    return render_template(
        "profile.html",
        user=user_dict,
        sections=sections_list,
        tags=tags_list,
        links=links_list,
        is_following=is_following,
        current_user_id=logged_in_user.id if logged_in_user else None,
        notification_count=notification_count
    )

@app.route("/profile", methods=["GET", "POST"])
def edit_profile():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        user.bio = request.form.get("bio", "")
        
        # Handle Avatar Upload or URL Input
        avatar_updated = False
        if 'avatar_file' in request.files:
            avatar_file = request.files['avatar_file']
            if avatar_file.filename != '' and allowed_file(avatar_file.filename):
                filename = secure_filename(avatar_file.filename)
                avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                avatar_file.save(avatar_path)
                user.avatar_url = '/' + avatar_path # Store relative path
                avatar_updated = True
        
        if not avatar_updated:
            avatar_url_input = request.form.get("avatar_url_input", "").strip()
            if avatar_url_input:
                user.avatar_url = avatar_url_input
            elif 'avatar_url_input' in request.form: # Check if the field was present, meaning user might have cleared it
                user.avatar_url = '/static/images/1.png' # Revert to default if cleared

        # Handle Banner Upload or URL Input
        banner_updated = False
        if 'banner_file' in request.files:
            banner_file = request.files['banner_file']
            if banner_file.filename != '' and allowed_file(banner_file.filename):
                filename = secure_filename(banner_file.filename)
                banner_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                banner_file.save(banner_path)
                user.banner_url = '/' + banner_path # Store relative path
                banner_updated = True
        
        if not banner_updated:
            banner_url_input = request.form.get("banner_url_input", "").strip()
            if banner_url_input:
                user.banner_url = banner_url_input
            elif 'banner_url_input' in request.form: # Check if the field was present, meaning user might have cleared it
                user.banner_url = '' # Clear banner if cleared (no default)

        profile_color = request.form.get("profile_color", "").strip()
        if profile_color:
            user.profile_color = profile_color
        else:
            user.profile_color = '#e24040' # Reverte para o padrão se o campo for esvaziado

        background_color = request.form.get("background_color", "").strip()
        if background_color:
            user.background_color = background_color
        else:
            user.background_color = '#f8f8f8' # Reverte para o padrão se o campo for esvaziado

        # Handle New Personal Info Fields
        user.age = request.form.get("age", type=int)
        user.nationality = request.form.get("nationality", "").strip()
        user.gender = request.form.get("gender", "").strip()
        user.sexuality = request.form.get("sexuality", "").strip()

        # Tags
        tag_names = request.form.getlist("tags")
        if not tag_names:
            flash("Pelo menos uma hashtag é obrigatória!", "error")
            return redirect(url_for("edit_profile"))
        
        # Check if the 'tags' field was explicitly submitted.
        # If the form renders existing tags, but the user removes them all, tag_names will be empty.
        # If the user doesn't touch the tag section, 'tags' might not even be in request.form if JS handles it.
        # To avoid accidental deletion if the form didn't submit anything for tags, we check 'in request.form'.
        if "tags" in request.form: # This means the tags section was part of the form submission
            user.tags.clear() # Clear all current tags
            for name in tag_names:
                name = name.strip()
                if name:
                    tag = Tag.query.filter_by(name=name).first()
                    if not tag:
                        tag = Tag(name=name)
                        db_session.add(tag)
                    user.tags.append(tag)
        # If "tags" not in request.form, assume no change intended, keep existing tags.


        # Links
        link_data = request.form.getlist("links")
        if "links" in request.form: # Only clear if new links are being submitted
            UserLink.query.filter_by(user_id=user.id).delete()
            for link_str in link_data:
                if "|" in link_str:
                    platform, url = map(str.strip, link_str.split("|", 1))
                    if platform and url:
                        new_link = UserLink(user_id=user.id, platform=platform, url=url)
                        db_session.add(new_link)
        # Else: if "links" not in request.form, assume no change intended, keep existing links.

        # Seções
        titles = request.form.getlist("section_title")
        contents = request.form.getlist("section_content")
        
        # If the section title input field was present in the submitted form
        if "section_title" in request.form: 
            UserSection.query.filter_by(user_id=user.id).delete() # Delete all existing sections
            
            # Re-add only the submitted sections that have content
            for t, c in zip(titles, contents):
                if t.strip() or c.strip(): # Only add if title OR content is not empty
                    new_section = UserSection(user_id=user.id, title=t.strip(), content=c.strip())
                    db_session.add(new_section)
        # Else: if "section_title" was not in request.form, the sections block was not submitted,
        #       so we leave existing sections as they are.

        db_session.commit()
        return redirect(url_for("view_profile", user_id=user.id))

    user_dict = {'name': user.name, 'bio': user.bio, 'avatar_url': user.avatar_url, 'banner_url': user.banner_url, 'profile_color': user.profile_color, 'background_color': user.background_color,
                 'age': user.age, 'nationality': user.nationality, 'gender': user.gender, 'sexuality': user.sexuality}
    user_tags_list = [tag.name for tag in user.tags]
    user_links_list = [{'platform': l.platform, 'url': l.url} for l in user.links]
    user_sections_list = [{'title': s.title, 'content': s.content} for s in user.sections]
    
    return render_template(
        "edit_profile.html",
        user=user_dict,
        user_tags=user_tags_list,
        user_links=user_links_list,
        user_sections=user_sections_list,
        countries=COUNTRIES # Pass the list of countries to the template
    )
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)