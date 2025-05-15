from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from flask_migrate import Migrate
import os
import logging
import uuid
from PIL import Image
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from flask_caching import Cache
from flask_compress import Compress
from flask_session import Session
from werkzeug.utils import secure_filename

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
def compress_image(filepath, max_size_kb=100, max_dimensions=(1920, 1080)):
    """Compress an image to ensure it is under the specified size in KB and dimensions."""
    max_size_bytes = max_size_kb * 1024  # Konverter KB til bytes
    quality = 85  # Startkvalitet

    with Image.open(filepath) as img:
        img = img.convert("RGB")  # Sørg for, at billedet er i RGB-format

        # Ret rotation baseret på EXIF-data
        try:
            exif = img._getexif()
            if exif:
                orientation = exif.get(274)  # 274 er EXIF-tagget for orientering
                if orientation == 3:
                    img = img.rotate(180, expand=True)
                elif orientation == 6:
                    img = img.rotate(270, expand=True)
                elif orientation == 8:
                    img = img.rotate(90, expand=True)
        except AttributeError:
            pass  # Hvis der ikke er EXIF-data, fortsæt uden at rotere

        # Reducer billedets dimensioner, hvis det er større end max_dimensions
        if img.size[0] > max_dimensions[0] or img.size[1] > max_dimensions[1]:
            img.thumbnail(max_dimensions)

        while True:
            # Gem billedet midlertidigt med den aktuelle kvalitet
            img.save(filepath, "JPEG", quality=quality)
            # Tjek filstørrelsen
            if os.path.getsize(filepath) <= max_size_bytes or quality <= 10:
                break  # Stop, hvis filen er under grænsen, eller kvaliteten er for lav
            quality -= 5  # Reducer kvaliteten for yderligere komprimering
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log', encoding='utf-8')
    ]
)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'static/uploads/profile_pictures'
MAX_IMAGE_SIZE = (300, 300)  # Maksimal størrelse på billedet (bredde, højde)

def get_logged_in_user():
    """Hent den loggede bruger fra sessionen."""
    if 'user_id' not in session:
        flash('Du skal være logget ind for at se denne side.', 'danger')
        return None, redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    if not user:
        flash('Bruger ikke fundet.', 'danger')
        return None, redirect(url_for('login'))

    return user, None

def get_user_stats(user):
    """Beregner statistik for en bruger."""
    total_beers = sum(beer.count for beer in user.beers)
    last_beer_time = user.beers[-1].timestamp.strftime('%Y-%m-%d %H:%M:%S') if user.beers else None
    return total_beers, last_beer_time

def get_friendship_status(user_id, other_user_id):
    friendship = Friendship.query.filter(
        ((Friendship.user_id == user_id) & (Friendship.friend_id == other_user_id)) |
        ((Friendship.user_id == other_user_id) & (Friendship.friend_id == user_id))
    ).first()

    if not friendship:
        return 'none', None
    elif friendship.status == 'pending' and friendship.user_id == user_id:
        return 'pending_sent', friendship
    elif friendship.status == 'pending' and friendship.friend_id == user_id:
        return 'pending_received', friendship
    elif friendship.status == 'accepted':
        return 'accepted', friendship
    return 'none', None

def get_friends_with_stats(user_id):
    """Hent venner og deres statistik."""
    friends = db.session.query(
        Friendship,
        User,
        db.func.sum(BeerLog.count).label('total_beers'),
        db.func.max(BeerLog.timestamp).label('last_beer_time')
    ).join(User, 
           db.or_(
               Friendship.friend_id == User.id, 
               Friendship.user_id == User.id
           )) \
     .outerjoin(BeerLog, BeerLog.user_id == User.id) \
     .filter(
        (Friendship.status == 'accepted') &
        (db.or_(Friendship.user_id == user_id, Friendship.friend_id == user_id)) &
        (User.id != user_id)  # Ekskluder den loggede bruger
    ).group_by(Friendship.id, User.id).all()

    friends_list = []
    for friendship, friend, total_beers, last_beer_time in friends:
        friends_list.append({
            'id': friend.id,
            'username': friend.username,
            'profile_picture': friend.profile_picture or User.default_profile_picture,
            'total_beers': total_beers or 0,
            'last_beer_time': last_beer_time.strftime('%Y-%m-%d %H:%M:%S') if last_beer_time else None,
            'created_at': friendship.created_at.strftime('%d-%m-%Y'),
            'friendship_id': friendship.id
        })
    return friends_list

def get_leaderboard_data(user_id, time_delta=None):
    """Hent leaderboard-data for en given tidsperiode."""
    users = User.query.all()
    leaderboard_data = []

    for u in users:
        query = BeerLog.query.filter_by(user_id=u.id)
        if time_delta:
            query = query.filter(BeerLog.timestamp >= datetime.utcnow() - time_delta)
        total_beers = query.with_entities(db.func.sum(BeerLog.count)).scalar() or 0

        # Find status for venneanmodning
        status, friendship = get_friendship_status(user_id, u.id)

        leaderboard_data.append({
            'id': u.id,
            'username': u.username,
            'profile_picture': u.profile_picture or User.default_profile_picture,
            'total_beers': total_beers,
            'status': status,
            'friendship_id': friendship.id if friendship else None
        })

    leaderboard_data.sort(key=lambda x: x['total_beers'], reverse=True)
    return leaderboard_data[:10]

def is_rate_limited(ip, endpoint, limit, period):
    """Tjek om en IP-adresse har overskredet grænsen for et endpoint."""
    now = datetime.utcnow()
    window_start = now - timedelta(seconds=period)

    # Tæl anmodninger fra denne IP til dette endpoint inden for perioden
    request_count = RateLimit.query.filter(
        RateLimit.ip_address == ip,
        RateLimit.endpoint == endpoint,
        RateLimit.timestamp >= window_start
    ).count()

    if request_count >= limit:
        return True

    # Gem den nye anmodning i databasen
    new_request = RateLimit(ip_address=ip, endpoint=endpoint, timestamp=now)
    db.session.add(new_request)
    db.session.commit()

    return False

def set_cache(key, value, timeout=300):
    """Gem data i cachen."""
    expires_at = datetime.utcnow() + timedelta(seconds=timeout)
    entry = CacheEntry.query.filter_by(key=key).first()
    if entry:
        entry.value = value
        entry.expires_at = expires_at
    else:
        entry = CacheEntry(key=key, value=value, expires_at=expires_at)
        db.session.add(entry)
    db.session.commit()

def get_cache(key):
    """Hent data fra cachen."""
    entry = CacheEntry.query.filter_by(key=key).first()
    if entry and entry.expires_at > datetime.utcnow():
        return entry.value
    return None

def cleanup_rate_limit_data():
    """Slet gamle rate limiting-poster fra databasen."""
    expiration_time = datetime.utcnow() - timedelta(days=1)  # Behold data i 1 dag
    RateLimit.query.filter(RateLimit.timestamp < expiration_time).delete()
    db.session.commit()

app = Flask(__name__, static_folder='static')
load_dotenv()  # Indlæs miljøvariabler fra en .env-fil
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL') + '?sslmode=require'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Slå ændringssporing fra (for performance)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')  # Brug miljøvariabel
app.config['UPLOAD_FOLDER'] = 'static/uploads/profile_pictures'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}
#app.config['SESSION_COOKIE_SECURE'] = True  # Kun tillad cookies over HTTPS
#app.config['SESSION_COOKIE_HTTPONLY'] = True  # Forhindre JavaScript-adgang til cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Beskyt mod CSRF-angreb
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'max_overflow': 20,
    'pool_timeout': 30
}
app.config['MAX_CONTENT_LENGTH'] = 30 * 1024 * 1024  # Maks. 30 MB
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

db = SQLAlchemy(app)

app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db  # Brug SQLAlchemy-databasen
app.config['SESSION_PERMANENT'] = False  # Sessioner udløber, når browseren lukkes
Session(app)
migrate = Migrate(app, db)

cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache'})

Compress(app)

# Sørg for, at upload-mappen eksisterer
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

class BeerLog(db.Model):
    __tablename__ = 'beer_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Rettet fra 'user.id' til 'users.id'
    count = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Tilføjet created_at

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    allow_location = db.Column(db.Boolean, default=False)  # Tilføjet felt til lokationstilladelse
    beers = db.relationship('BeerLog', backref='user', lazy=True)
    __table_args__ = {'extend_existing': True}
    profile_picture = db.Column(db.String(300), nullable=True)  # Sti til profilbillede
    default_profile_picture = 'static/icon-5355896_640.png'
    last_username_change = db.Column(db.DateTime, nullable=True)  # Add this field
    bio = db.Column(db.String(500), nullable=True)  # Begræns biografien til 500 tegn
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Tilføjet created_at
    
class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Tilføj denne linje
    status = db.Column(db.String(20), default='pending')  # 'pending', 'accepted', 'rejected'
    user = db.relationship('User', foreign_keys=[user_id], backref='friendships')
    friend = db.relationship('User', foreign_keys=[friend_id], backref='friends')
    
class RateLimit(db.Model):
    __tablename__ = 'rate_limits'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)  # IPv4/IPv6
    endpoint = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class CacheEntry(db.Model):
    __tablename__ = 'cache'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(255), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    
class VersionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

csrf = CSRFProtect(app)

ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

@app.context_processor
def inject_logged_in_user():
    user_id = session.get('user_id')
    if user_id:
        return {'logged_in_user': db.session.get(User, user_id)}
    return {'logged_in_user': None}

@app.before_request
def before_request():
    ip = request.remote_addr
    endpoint = request.endpoint

    # Rate limiting for POST requests
    if request.method == 'POST' and is_rate_limited(ip, endpoint, limit=10, period=20):
        return "Too many requests. Please try again later.", 429

    # Check for cookie consent
    cookies_accepted = request.cookies.get('cookie_consent')
    g.cookies_accepted = cookies_accepted == 'true'

    # Deaktiver ikke-nødvendige funktioner, hvis cookies ikke er accepteret
    g.analytics_enabled = g.cookies_accepted

    # Undgå omdirigering til /cookie_policy på undtagne sider
    excluded_endpoints = ['register', 'set_cookie_consent', 'cookie_policy', 'privacy_policy', 'static', 'login']
    if not cookies_accepted and endpoint not in excluded_endpoints:
        # Hvis brugeren ikke har givet samtykke, og det ikke er en undtaget side
        if endpoint == 'index' and 'user_id' not in session:  # Kun hvis brugeren ikke er logget ind
            return redirect(url_for('register'))

    # Hvis brugeren er logget ind, men ikke findes i databasen, ryd sessionen
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if not user:
            session.clear()
            flash('Din session er udløbet. Log venligst ind igen.', 'warning')
            return redirect(url_for('login'))

@app.after_request
def add_security_headers(response):
    nonce = uuid.uuid4().hex  # Generate a random nonce
    response.headers['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' https://unpkg.com https://code.jquery.com https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com; "
        f"style-src 'self' https://unpkg.com https://stackpath.bootstrapcdn.com 'unsafe-inline'; "
        f"img-src 'self' data: https://*.tile.openstreetmap.org; "
        f"font-src 'self' https://stackpath.bootstrapcdn.com; "
        f"connect-src 'self';"
    )
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.set_cookie('csp_nonce', nonce)  # Pass the nonce to the client via a cookie
    return response

@app.route('/cookie_policy')
def cookie_policy():
    return render_template('cookie_policy.html', show_navbar=False, show_back_button=False)

@app.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy_policy.html', show_navbar=False, show_back_button=False)

@app.route('/')
def index():
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user:
            # Beregn nødvendige data
            total_beers = sum(beer.count for beer in user.beers)
            last_beer_time = user.beers[-1].timestamp.strftime('%Y-%m-%d %H:%M:%S') if user.beers else None
            total_beers_ever = BeerLog.query.with_entities(db.func.sum(BeerLog.count)).scalar() or 0

            # Beregn øl drukket af brugeren og deres venner
            friends_beers = 0
            for friendship in user.friendships:
                friend = friendship.friend
                friends_beers += sum(beer.count for beer in friend.beers)
            total_user_and_friends_beers = total_beers + friends_beers

            is_new_user = session.pop('is_new_user', False)  # Hent og fjern 'is_new_user' fra sessionen

            return render_template(
                'index.html',
                user=user,  # Send hele user-objektet til skabelonen
                username=user.username,
                total_beers=total_beers,
                last_beer_time=last_beer_time,
                is_admin=user.is_admin,
                total_beers_ever=total_beers_ever,
                total_user_and_friends_beers=total_user_and_friends_beers,
                is_new_user=is_new_user,
                show_back_button=False,
            )
    return redirect(url_for('register'))

@app.route('/upload_profile_picture', methods=['POST'])
def upload_profile_picture():
    ip = request.remote_addr
    if is_rate_limited(ip, 'upload_profile_picture', limit=5, period=60):  # Maks. 5 uploadforsøg pr. minut
        flash("For mange uploadforsøg. Prøv igen senere.", "danger")
        return redirect(url_for('profile', user_id=session.get('user_id')))

    if 'user_id' not in session:
        flash('Du skal være logget ind for at uploade et profilbillede.', 'danger')
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    if not user:
        flash('Bruger ikke fundet.', 'danger')
        return redirect(url_for('login'))

    if 'profile_picture' not in request.files:
        flash('Ingen fil valgt.', 'danger')
        return redirect(url_for('profile', user_id=user.id))

    file = request.files['profile_picture']
    if file.filename == '':
        flash('Ingen fil valgt.', 'danger')
        return redirect(url_for('profile', user_id=user.id))

    if file and allowed_file(file.filename):
        try:
            # Sikr filnavnet
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Slet det gamle profilbillede, hvis det findes og ikke er standardbilledet
            if user.profile_picture and user.profile_picture != User.default_profile_picture:
                old_filepath = os.path.join(os.getcwd(), user.profile_picture)
                if os.path.exists(old_filepath):
                    os.remove(old_filepath)

            # Gem den nye fil midlertidigt
            file.save(filepath)

            # Reducer billedets dimensioner og komprimer det
            compress_image(filepath, max_size_kb=500, max_dimensions=(1920, 1080))

            # Opdater brugerens profilbillede i databasen
            relative_path = os.path.relpath(filepath, os.getcwd())  # Gem relativ sti
            user.profile_picture = relative_path.replace("\\", "/")  # Brug forward slashes for kompatibilitet
            db.session.commit()

            return redirect(url_for('profile', user_id=user.id))
        except Exception as e:
            app.logger.error(f"Fejl under upload af profilbillede: {e}")
            flash('Der opstod en fejl under upload af billedet. Prøv igen.', 'danger')
            return redirect(url_for('profile', user_id=user.id))

    flash('Formatet på billedet understøttes ikke. Kun PNG, JPG, JPEG og GIF understøttes.', 'danger')
    return redirect(url_for('profile', user_id=user.id))

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    ip = request.remote_addr  # Hent IP-adressen for klienten

    # Rate limiting kun for POST-anmodninger (loginforsøg)
    if request.method == 'POST' and is_rate_limited(ip, 'admin_login', limit=3, period=20):
        return "Too many login attempts. Please try again later.", 429

    if request.method == 'POST':
        admin_username = request.form.get('username')
        admin_password = request.form.get('password')

        # Valider input
        if not admin_username or not admin_password:
            flash('Udfyld både brugernavn og adgangskode.', 'danger')
            return redirect(url_for('admin_login'))

        # Sammenlign med miljøvariabler
        if admin_username == ADMIN_USERNAME and admin_password == ADMIN_PASSWORD:
            session['is_admin'] = True  # Sæt admin-session
            return redirect(url_for('admin'))
        else:
            flash('Forkert brugernavn eller adgangskode.', 'danger')

    # GET-anmodning: Vis login-siden
    return render_template('admin_login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    ip = request.remote_addr
    error_message = None

    if request.method == 'POST' and is_rate_limited(ip, 'register', limit=2, period=10):
        error_message = "For mange registreringsforsøg. Prøv igen senere."
        return render_template('register.html', error_message=error_message)

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_age = request.form.get('confirm_age')
        accept_terms = request.form.get('accept_terms')
        accept_privacy_policy = request.form.get('accept_privacy_policy')
        allow_location = request.form.get('allow_location')

        # Valider obligatoriske felter
        if not confirm_age:
            error_message = "Du skal bekræfte, at du er over 18 år."
        elif not accept_terms:
            error_message = "Du skal acceptere brugervilkårene."
        elif not accept_privacy_policy:
            error_message = "Du skal acceptere privatlivspolitikken."
        elif not username or not password:
            error_message = "Brugernavn og adgangskode skal udfyldes."
        elif len(username) > 20:  # Tjek længden af brugernavnet
            error_message = "Brugernavnet må ikke være længere end 20 tegn."
        else:
            # Tjek om brugernavnet allerede er taget (case-insensitive)
            existing_user = User.query.filter(User.username.ilike(username)).first()
            if existing_user:
                error_message = "Brugernavnet er allerede taget. Vælg venligst et andet."
            else:
                try:
                    # Opret ny bruger
                    new_user = User(
                        username=username,  # Gem brugernavnet som det er
                        password=generate_password_hash(password, method='pbkdf2:sha256'),
                        allow_location=(allow_location == 'on')
                    )
                    db.session.add(new_user)
                    db.session.commit()

                    # Log brugeren ind
                    session['user_id'] = new_user.id
                    return redirect(url_for('index'))
                except Exception as e:
                    db.session.rollback()
                    app.logger.error(f"Fejl under registrering: {e}")
                    error_message = "Der opstod en fejl under registreringen. Prøv igen."

    return render_template('register.html', error_message=error_message, show_navbar=False, show_back_button=False)

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = request.remote_addr
    error_message = None

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username and password:
            if is_rate_limited(ip, 'login', limit=5, period=20):
                error_message = "For mange loginforsøg. Prøv igen senere."
            else:
                # Find brugeren med case-insensitive søgning
                user = User.query.filter(User.username.ilike(username)).first()
                if user and check_password_hash(user.password, password):
                    session['user_id'] = user.id
                    return redirect(url_for('index'))
                else:
                    error_message = "Brugernavnet findes ikke eller adgangskoden er forkert."
        else:
            error_message = "Udfyld både brugernavn og adgangskode."

    return render_template('login.html', show_navbar=False, show_back_button=False, error_message=error_message)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)  # Fjern admin-session
    return redirect(url_for('login'))

@app.route('/admin_logout')
def admin_logout():
    session.pop('is_admin', None)  # Fjern admin-session
    flash('You have been logged out.', 'success')
    return redirect(url_for('admin_login'))

@app.route('/add_beer', methods=['POST'])
def add_beer():
    ip = request.remote_addr  # Hent IP-adressen for klienten
    if is_rate_limited(ip, 'add_beer', limit=5, period=60):  # Maks. 5 øl-tilføjelser pr. minut
        return "Too many beer additions. Please try again later.", 429

    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user:
            latitude = request.form.get('latitude')
            longitude = request.form.get('longitude')
            beer_log = BeerLog(user_id=user.id, count=1, timestamp=datetime.utcnow(), latitude=latitude, longitude=longitude)
            db.session.add(beer_log)
            db.session.commit()
    return redirect(url_for('index'))

@app.route('/profile/<int:user_id>', methods=['GET', 'POST'])
def profile(user_id):
    # Hent den loggede bruger
    logged_in_user = db.session.get(User, session.get('user_id'))
    if not logged_in_user:
        flash('Du skal være logget ind for at se profiler.', 'danger')
        return redirect(url_for('login'))

    # Hent den ønskede bruger
    user = db.session.get(User, user_id)
    if not user:
        flash('Brugeren blev ikke fundet.', 'warning')
        return redirect(url_for('index'))
    
    # Beregn cooldown for brugernavnsskift
    cooldown_message = None
    if user.id == logged_in_user.id and user.last_username_change:
        cooldown_end = user.last_username_change + timedelta(days=7)
        if datetime.utcnow() < cooldown_end:
            remaining_time = cooldown_end - datetime.utcnow()
            days = remaining_time.days
            hours = remaining_time.seconds // 3600
            cooldown_message = f"Du kan skifte dit brugernavn igen om {days} dage og {hours} timer."

    # Hvis det er brugerens egen profil, tillad ændringer
    is_own_profile = logged_in_user.id == user.id

    # Håndter ændring af brugernavn
    if request.method == 'POST' and is_own_profile:
        new_username = request.form.get('new_username')
        if new_username:
            # Tjek om brugernavnet allerede er taget
            existing_user = User.query.filter_by(username=new_username).first()
            if existing_user:
                flash('Brugernavnet er allerede taget. Vælg venligst et andet.', 'danger')
            else:
                user.username = new_username
                user.last_username_change = datetime.utcnow()
                db.session.commit()
                flash('Dit brugernavn er blevet opdateret!', 'success')
                return redirect(url_for('profile', user_id=user.id))

    # Beregn statistik for den viste bruger
    total_beers = sum(beer.count for beer in user.beers) if user.beers else 0
    last_beer_time = user.beers[-1].timestamp.strftime('%Y-%m-%d %H:%M:%S') if user.beers else None

    # Hent venskabsstatus, hvis det ikke er brugerens egen profil
    status, friendship = None, None
    if not is_own_profile:
        status, friendship = get_friendship_status(logged_in_user.id, user.id)

    return render_template(
        'profile.html',
        user=user,
        logged_in_user=logged_in_user,
        is_own_profile=is_own_profile,
        status=status,
        friendship_id=friendship.id if friendship else None,
        friendship_created_at=friendship.created_at if friendship and friendship.status == 'accepted' else None,
        total_beers=total_beers,
        last_beer_time=last_beer_time,
        cooldown_message=cooldown_message  # Send cooldown-besked til skabelonen
    )

@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    ip = request.remote_addr  # Hent IP-adressen for klienten
    if is_rate_limited(ip, 'delete_account', limit=5, period=60):  # Maks. 5 forsøg pr. minut
        return "Too many account deletion attempts. Please try again later.", 429

    if 'user_id' not in session:
        flash('Du skal være logget ind for at slette din konto.', 'danger')
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    if user:
        try:
            # Delete the profile picture file if it exists and is not the default
            if user.profile_picture and user.profile_picture != User.default_profile_picture:
                profile_picture_path = os.path.join(os.getcwd(), user.profile_picture)
                if os.path.exists(profile_picture_path):
                    os.remove(profile_picture_path)

            # Delete user-related data (e.g., friendships, logs)
            BeerLog.query.filter_by(user_id=user.id).delete()
            Friendship.query.filter((Friendship.user_id == user.id) | (Friendship.friend_id == user.id)).delete()

            # Delete the user
            db.session.delete(user)
            db.session.commit()

            flash('Din konto er blevet slettet.', 'success')
        except Exception as e:
            app.logger.error(f"Fejl under sletning af konto: {e}")
            flash('Der opstod en fejl under sletning af din konto. Prøv igen.', 'danger')
            return redirect(url_for('profile'))

    session.clear()  # Log the user out
    return redirect(url_for('index'))

@app.route('/admin')
def admin():
    if session.get('is_admin'):  # Tjek om brugeren er logget ind som admin
        users = User.query.all()
        return render_template('admin.html', users=users)
    flash('You do not have access to this page.', 'danger')
    return redirect(url_for('admin_login'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    ip = request.remote_addr
    if is_rate_limited(ip, 'delete_user', limit=2, period=1):  # Maks. 2 sletninger pr. sekund
        return "Too many user deletions. Please try again later.", 429

    if session.get('is_admin'):  # Check if the user is an admin
        # Tjek om bekræftelse er givet
        confirm_delete = request.form.get('confirm_delete')
        if not confirm_delete or confirm_delete != 'CONFIRM':
            flash('Du skal bekræfte, at du vil slette brugeren ved at skrive "CONFIRM".', 'danger')
            return redirect(url_for('admin'))

        user = db.session.get(User, user_id)
        if user:
            try:
                # Slet profilbilledet
                if user.profile_picture and user.profile_picture != User.default_profile_picture:
                    profile_picture_path = os.path.join(os.getcwd(), user.profile_picture)
                    if os.path.exists(profile_picture_path):
                        os.remove(profile_picture_path)

                # Slet relaterede data
                BeerLog.query.filter_by(user_id=user.id).delete()
                Friendship.query.filter(
                    (Friendship.user_id == user.id) | (Friendship.friend_id == user.id)
                ).delete()

                # Slet brugeren
                db.session.delete(user)
                db.session.commit()
                flash('Brugeren blev slettet.', 'success')
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Fejl ved sletning af bruger {user_id}: {e}")
                flash('Der opstod en fejl under sletningen af brugeren.', 'danger')
        else:
            flash('Brugeren blev ikke fundet.', 'warning')
    else:
        flash('Du har ikke tilladelse til at udføre denne handling.', 'danger')
    return redirect(url_for('admin'))

@app.route('/delete_all_users', methods=['POST'])
def delete_all_users():
    ip = request.remote_addr
    if is_rate_limited(ip, 'delete_all_users', limit=2, period=600):  
        return "Too many requests. Please try again later.", 429

    if session.get('is_admin'):  # Ensure only admins can delete all users
        # Tjek om bekræftelse er givet
        confirm_delete = request.form.get('confirm_delete')
        if not confirm_delete or confirm_delete != 'CONFIRM':
            flash('Du skal bekræfte, at du vil slette alle brugere ved at skrive "CONFIRM".', 'danger')
            return redirect(url_for('admin'))

        try:
            # Slet profilbilleder
            users = User.query.all()
            for user in users:
                if user.profile_picture and user.profile_picture != User.default_profile_picture:
                    profile_picture_path = os.path.join(os.getcwd(), user.profile_picture)
                    if os.path.exists(profile_picture_path):
                        os.remove(profile_picture_path)

            # Slet relaterede data
            BeerLog.query.delete()
            Friendship.query.delete()
            CacheEntry.query.delete()
            RateLimit.query.delete()

            # Slet alle brugere
            User.query.delete()

            db.session.commit()
            flash('Alle brugere blev slettet.', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Fejl ved sletning af alle brugere: {e}")
            flash('Der opstod en fejl under sletningen af alle brugere.', 'danger')
    else:
        flash('Du har ikke tilladelse til at udføre denne handling.', 'danger')
    return redirect(url_for('admin'))

@app.route('/friends', methods=['GET', 'POST'])
def friends():
    ip = request.remote_addr
    if request.method == 'POST' and is_rate_limited(ip, 'friends', limit=3, period=5):
        return "Too many requests. Please try again later.", 429
    user, redirect_response = get_logged_in_user()
    if redirect_response:
        return redirect_response

    # Hent venner og deres statistik
    friends_list = get_friends_with_stats(user.id)

    # Hent venneanmodninger
    friend_requests = []
    for friendship in Friendship.query.filter_by(friend_id=user.id, status='pending').all():
        requester = friendship.user
        friend_requests.append({
            'id': requester.id,  # Brug brugerens ID i stedet for friendship.id
            'username': requester.username,
            'profile_picture': requester.profile_picture or User.default_profile_picture
        })

    # Håndter søgefunktionalitet
    search_results = []
    if request.method == 'POST':
        search_username = request.form['search_username']
        search_results_query = User.query.filter(
            User.username.ilike(f'%{search_username}%'),
            User.id != user.id  # Ekskluder den loggede bruger
        ).all()

        for result in search_results_query:
            status, _ = get_friendship_status(user.id, result.id)
            search_results.append({
                'id': result.id,
                'username': result.username,
                'profile_picture': result.profile_picture or User.default_profile_picture,
                'status': status
            })

    return render_template(
        'friends.html',
        user=user,
        friends=friends_list,
        friend_requests=friend_requests,
        search_results=search_results
    )

@app.route('/friend_action', methods=['POST'])
def friend_action():
    ip = request.remote_addr  # Hent IP-adressen for klienten
    if is_rate_limited(ip, 'friend_action', limit=5, period=20):  # Maks. 5 anmodninger pr. minut
        return jsonify({'status': 'error', 'message': 'For mange anmodninger. Prøv igen senere.'}), 429

    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Du skal være logget ind for at udføre denne handling.'}), 401

    data = request.get_json()
    action = data.get('action')
    user_id = session['user_id']
    target_user_id = data.get('user_id')
    friendship_id = data.get('friendship_id')

    try:
        if action == 'send_request':
            # Logik for at sende venneanmodning
            friend = db.session.get(User, target_user_id)
            if not friend:
                return jsonify({'status': 'error', 'message': 'Brugeren blev ikke fundet.'}), 404

            if user_id == target_user_id:
                return jsonify({'status': 'error', 'message': 'Du kan ikke sende en venneanmodning til dig selv.'}), 400

            existing_request = Friendship.query.filter_by(user_id=user_id, friend_id=target_user_id).first()
            if existing_request:
                return jsonify({'status': 'info', 'message': 'Du har allerede sendt en venneanmodning.'}), 200

            friendship = Friendship(user_id=user_id, friend_id=target_user_id, status='pending')
            db.session.add(friendship)
            db.session.commit()
            return jsonify({'status': 'success', 'message': 'Venneanmodning sendt.', 'new_status': 'pending_sent'}), 201

        elif action == 'cancel_request':
            # Logik for at annullere venneanmodning
            friendship = Friendship.query.filter_by(user_id=user_id, friend_id=target_user_id, status='pending').first()
            if not friendship:
                return jsonify({'status': 'error', 'message': 'Ingen venneanmodning blev fundet.'}), 404

            db.session.delete(friendship)
            db.session.commit()
            return jsonify({'status': 'success', 'message': 'Venneanmodning annulleret.', 'new_status': 'none'}), 200

        elif action == 'accept_request':
        # Logik for at acceptere venneanmodning
            friendship = Friendship.query.get(friendship_id)
            if not friendship:
                return jsonify({'status': 'error', 'message': 'Venneanmodningen blev ikke fundet.'}), 404

        # Sørg for, at den loggede bruger er modtageren af venneanmodningen
            if friendship.friend_id != user_id:
                return jsonify({'status': 'error', 'message': 'Du har ikke tilladelse til at acceptere denne venneanmodning.'}), 403

        # Sørg for, at brugeren ikke bliver venner med sig selv
            if friendship.user_id == friendship.friend_id:
                return jsonify({'status': 'error', 'message': 'Ugyldig venneanmodning: Brugeren kan ikke være venner med sig selv.'}), 400

        # Opdater status til 'accepted'
            friendship.status = 'accepted'
            db.session.commit()

            return jsonify({
                'status': 'success',
                'new_status': 'accepted',
                'friendship_created_at': friendship.created_at.strftime('%d. %B %Y')
            }), 200

        elif action == 'reject_request':
        # Logik for at afvise venneanmodning
                friendship = Friendship.query.get(friendship_id)
                if not friendship:
                    return jsonify({'status': 'error', 'message': 'Venneanmodningen blev ikke fundet.'}), 404

        # Sørg for, at den loggede bruger er modtageren af venneanmodningen
                if friendship.friend_id != user_id:
                    return jsonify({'status': 'error', 'message': 'Du har ikke tilladelse til at afvise denne venneanmodning.'}), 403

        # Slet venneanmodningen
                db.session.delete(friendship)
                db.session.commit()

                return jsonify({'status': 'success', 'new_status': 'none'}), 200

        elif action == 'remove_friend':
            # Logik for at fjerne ven
            friendship = Friendship.query.get(friendship_id)
            if not friendship or (friendship.user_id != user_id and friendship.friend_id != user_id):
                return jsonify({'status': 'error', 'message': 'Venskabet blev ikke fundet eller er ugyldigt.'}), 404

            db.session.delete(friendship)
            db.session.commit()
            return jsonify({'status': 'success', 'message': 'Ven fjernet.', 'new_status': 'none'}), 200

        else:
            return jsonify({'status': 'error', 'message': 'Ugyldig handling.'}), 400

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Fejl under vennehandling: {e}")
        return jsonify({'status': 'error', 'message': 'Der opstod en fejl. Prøv igen senere.'}), 500

@app.route('/delete_beer', methods=['POST'])
def delete_beer():
    ip = request.remote_addr  # Hent IP-adressen for klienten
    if is_rate_limited(ip, 'delete_beer', limit=5, period=60):  # Maks. 5 øl-sletninger pr. minut
        return "Too many beer deletions. Please try again later.", 429

    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user:
            last_beer_log = BeerLog.query.filter_by(user_id=user.id).order_by(BeerLog.timestamp.desc()).first()
            if last_beer_log:
                db.session.delete(last_beer_log)
                db.session.commit()
    return redirect(url_for('index'))

@app.route('/map')
@cache.cached(timeout=300)  # Cache i 5 minutter
def map():
    ip = request.remote_addr
    if is_rate_limited(ip, 'map', limit=5, period=60):  # Maks. 5 anmodninger pr. minut
        return "Too many requests. Please try again later.", 429

    if 'user_id' in session:
        try:
            user = db.session.get(User, session['user_id'])
            if user:
                # Hent logs
                all_logs = BeerLog.query.all()
                user_logs = BeerLog.query.filter_by(user_id=user.id).all()
                friend_ids = [friendship.friend.id for friendship in user.friendships]
                friends_logs = BeerLog.query.filter(BeerLog.user_id.in_(friend_ids)).all()

                # Serialiser logs
                def serialize_logs(logs):
                    return [
                        {
                            'latitude': log.latitude,
                            'longitude': log.longitude,
                            'count': log.count,
                            'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                        }
                        for log in logs if log.latitude and log.longitude
                    ]

                user_logs_serializable = serialize_logs(user_logs)
                friends_logs_serializable = serialize_logs(friends_logs)
                all_logs_serializable = serialize_logs(all_logs)

                return render_template(
                    'map.html',
                    user=user,
                    user_logs=user_logs_serializable,
                    friends_logs=friends_logs_serializable,
                    all_logs=all_logs_serializable
                )
        except Exception as e:
            app.logger.error(f"Fejl under hentning af kortdata: {e}")
            flash('Der opstod en fejl under hentning af kortdata.', 'danger')
            return redirect(url_for('index'))

    flash('Du skal være logget ind for at se kortet.', 'danger')
    return redirect(url_for('login'))

@app.route('/set_cookie_consent', methods=['POST'])
def set_cookie_consent():
    response = redirect(request.referrer or url_for('index'))
    response.set_cookie('cookie_consent', 'true', max_age=365*24*60*60)  # 1 år
    return response

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    user, redirect_response = get_logged_in_user()
    if redirect_response:
        return redirect_response

    if request.method == 'POST':
        # Opdater lokationstilladelse
        allow_location = request.form.get('allow_location') == 'on'
        user.allow_location = allow_location
        db.session.commit()

    return render_template('settings.html', user=user)

@app.route('/leaderboard')
def leaderboard():
    ip = request.remote_addr
    if is_rate_limited(ip, 'leaderboard', limit=5, period=60):  # Maks. 5 anmodninger pr. minut
        return "Too many requests. Please try again later.", 429

    cache_key = 'leaderboard'
    cached_data = get_cache(cache_key)
    if cached_data:
        return cached_data

    # Hent den loggede bruger
    user, redirect_response = get_logged_in_user()
    if redirect_response:
        return redirect_response

    total_users = User.query.count()

    # Generer leaderboard-sektioner
    leaderboard_sections = [
        ("Inden for de sidste 24 timer", get_leaderboard_data(user.id, timedelta(days=1))),
        ("Inden for den sidste uge", get_leaderboard_data(user.id, timedelta(weeks=1))),
        ("Inden for den sidste måned", get_leaderboard_data(user.id, timedelta(days=30))),
        ("Inden for det sidste år", get_leaderboard_data(user.id, timedelta(days=365))),
        ("Flest øl drukket nogensinde", get_leaderboard_data(user.id))
    ]

    # Tilføj venskabsstatus og friendship_id for hver bruger
    for section_title, users in leaderboard_sections:
        for u in users:
            status, friendship = get_friendship_status(user.id, u['id'])
            u['status'] = status
            u['friendship_id'] = friendship.id if friendship else None

    # Render leaderboardet
    rendered_data = render_template(
        'leaderboard.html',
        user=user,
        total_users=total_users,
        leaderboard_sections=leaderboard_sections
    )

    # Cache resultatet i 5 minutter
    set_cache(cache_key, rendered_data, timeout=300)
    return rendered_data
    
@app.route('/change_username', methods=['POST'])
def change_username():
    ip = request.remote_addr  # Hent IP-adressen for klienten
    if is_rate_limited(ip, 'change_username', limit=5, period=60):  # Maks. 5 forsøg pr. minut
        return "Too many username change attempts. Please try again later.", 429

    if 'user_id' not in session:
        flash('Du skal være logget ind for at ændre dit brugernavn.', 'danger')
        return redirect(url_for('login'))

    new_username = request.form.get('new_username')
    confirm_change = request.form.get('confirm_change')  # Check for confirmation
    if not new_username:
        flash('Brugernavn må ikke være tomt.', 'danger')
        return redirect(url_for('profile', user_id=session['user_id']))

    user = db.session.get(User, session['user_id'])
    if not user:
        flash('Bruger ikke fundet.', 'danger')
        return redirect(url_for('profile', user_id=session['user_id']))

    # Check if the username is already taken
    existing_user = User.query.filter_by(username=new_username).first()
    if existing_user:
        flash('Brugernavnet er allerede taget. Vælg venligst et andet.', 'danger')
        return redirect(url_for('profile', user_id=session['user_id']))

    # Check for cooldown
    if user.last_username_change:
        cooldown_end = user.last_username_change + timedelta(days=7)
        if datetime.utcnow() < cooldown_end:
            remaining_time = cooldown_end - datetime.utcnow()
            flash(
                f'Du kan skifte dit brugernavn igen om {remaining_time.days} dage og {remaining_time.seconds // 3600} timer.',
                'danger'
            )
            return redirect(url_for('profile', user_id=session['user_id']))

    # If confirmation is not provided, show the warning
    if not confirm_change:
        return redirect(url_for('profile', user_id=session['user_id']))

    # Update the username and last_username_change timestamp
    user.username = new_username
    user.last_username_change = datetime.utcnow()
    db.session.commit()

    return redirect(url_for('profile', user_id=session['user_id']))
    
@app.route('/about')
def about():
    if 'user_id' not in session:
        flash('Du skal være logget ind for at se denne side.', 'danger')
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    if not user:
        flash('Bruger ikke fundet.', 'danger')
        return redirect(url_for('login'))

    return render_template('about.html', user=user)

@app.route('/credits')
def credits():
    return render_template('credits.html', show_navbar=False, show_back_button=False)

@app.route('/terms')
def terms():
    return render_template('terms.html', show_navbar=False, show_back_button=False)

@app.route('/update_bio', methods=['POST'])

def update_bio():
    if 'user_id' not in session:
        flash('Du skal være logget ind for at opdatere din biografi.', 'danger')
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    if not user:
        flash('Bruger ikke fundet.', 'danger')
        return redirect(url_for('index'))

    bio = request.form.get('bio')
    if bio:
        if len(bio) > 500:  # Maksimal længde på 500 tegn
            flash('Din biografi må ikke være længere end 500 tegn.', 'danger')
            return redirect(url_for('profile', user_id=user.id))
        user.bio = bio
        db.session.commit()
    else:
        flash('Du skal angive en gyldig biografi.', 'danger')

    return redirect(url_for('profile', user_id=user.id))

@app.route('/which_beer')
def which_beer():
    ip = request.remote_addr
    if is_rate_limited(ip, 'which_beer', limit=10, period=60):  # Maks. 10 anmodninger pr. minut
        return "Too many requests. Please try again later.", 429
    if 'user_id' not in session:
        flash('Du skal være logget ind for at se denne side.', 'danger')
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    if not user:
        flash('Bruger ikke fundet.', 'danger')
        return redirect(url_for('login'))

    return render_template('which_beer.html', user=user)

@app.route('/versions')
def versions():
    version_logs = VersionLog.query.order_by(VersionLog.created_at.desc()).all()
    return render_template('versions.html', version_logs=version_logs, show_navbar=False, show_back_button=False)

@app.route('/log_version', methods=['POST'])
def log_version():
    version = request.form.get('version')
    description = request.form.get('description')

    if not version or not description:
        flash('Både version og beskrivelse skal udfyldes.', 'danger')
        return redirect(url_for('admin'))

    new_version = VersionLog(version=version, description=description)
    db.session.add(new_version)
    db.session.commit()

    flash('Ny version logget!', 'success')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run()