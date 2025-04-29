from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from flask_migrate import Migrate
import os
import logging
from PIL import Image
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from flask_caching import Cache
from flask_compress import Compress
from flask_session import Session

def allowed_file(file):
    """Valider filens MIME-type."""
    allowed_mime_types = ['image/jpeg', 'image/png']
    return file.content_type in allowed_mime_types
def compress_image(filepath, max_size_kb=100):
    """Compress an image to ensure it is under the specified size in KB."""
    max_size_bytes = max_size_kb * 1024  # Konverter KB til bytes
    quality = 85  # Startkvalitet

    with Image.open(filepath) as img:
        img = img.convert("RGB")  # Sørg for, at billedet er i RGB-format
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

def get_friendship_status(user_id, friend_id):
    """Hent status for venskab mellem to brugere."""
    friendship = Friendship.query.filter(
        ((Friendship.user_id == user_id) & (Friendship.friend_id == friend_id)) |
        ((Friendship.user_id == friend_id) & (Friendship.friend_id == user_id))
    ).first()

    if not friendship:
        return 'none', None
    return friendship.status, friendship

def get_friends_with_stats(user_id):
    """Hent venner og deres statistik."""
    friends = db.session.query(
        Friendship,
        User,
        db.func.sum(BeerLog.count).label('total_beers'),
        db.func.max(BeerLog.timestamp).label('last_beer_time')
    ).join(User, Friendship.friend_id == User.id) \
     .outerjoin(BeerLog, BeerLog.user_id == User.id) \
     .filter(
        ((Friendship.user_id == user_id) | (Friendship.friend_id == user_id)) &
        (Friendship.status == 'accepted')
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
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Slå ændringssporing fra (for performance)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')  # Brug miljøvariabel
app.config['UPLOAD_FOLDER'] = 'static/uploads/profile_pictures'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}
app.config['SESSION_COOKIE_SECURE'] = True  # Kun tillad cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Forhindre JavaScript-adgang til cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Beskyt mod CSRF-angreb
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'max_overflow': 20,
    'pool_timeout': 30
}
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # Maks. 2 MB
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

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    beers = db.relationship('BeerLog', backref='user', lazy=True)
    __table_args__ = {'extend_existing': True}
    profile_picture = db.Column(db.String(300), nullable=True)  # Sti til profilbillede
    default_profile_picture = 'static/icon-5355896_640.png'
    last_username_change = db.Column(db.DateTime, nullable=True)  # Add this field
    
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

csrf = CSRFProtect(app)

ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

@app.before_request
def check_rate_limit():
    ip = request.remote_addr
    endpoint = request.endpoint

    if request.method == 'POST' and is_rate_limited(ip, endpoint, limit=5, period=60):
        return "Too many requests. Please try again later.", 429
def check_cookie_consent():
    if 'cookie_consent' not in request.cookies and request.endpoint not in ['set_cookie_consent', 'static']:
        # Brugeren har ikke givet samtykke, vis cookie-banner
        pass

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://stackpath.bootstrapcdn.com; "
        "img-src 'self' data:; "
        "font-src 'self' https://stackpath.bootstrapcdn.com; "
        "connect-src 'self';"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

@app.route('/cookie_policy')
def cookie_policy():
    return render_template('cookie_policy.html')

@app.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy_policy.html')

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
                is_new_user=is_new_user
            )
    return redirect(url_for('register'))

@app.route('/upload_profile_picture', methods=['POST'])
def upload_profile_picture():
    ip = request.remote_addr
    if is_rate_limited(ip, 'upload_profile_picture', limit=5, period=60):  # Maks. 5 uploadforsøg pr. minut
        return "Too many upload attempts. Please try again later.", 429

    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if 'profile_picture' not in request.files:
            return {'status': 'error', 'message': 'Ingen fil valgt.'}, 400
        
        file = request.files['profile_picture']
        if file.filename == '':
            return {'status': 'error', 'message': 'Ingen fil valgt.'}, 400
        
        if file and allowed_file(file):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            try:
                # Slet det gamle profilbillede, hvis det findes og ikke er standardbilledet
                if user.profile_picture and user.profile_picture != User.default_profile_picture:
                    old_filepath = os.path.join(os.getcwd(), user.profile_picture)
                    if os.path.exists(old_filepath):
                        os.remove(old_filepath)
                
                # Gem den nye fil
                file.save(filepath)
                
                # Komprimer billedet
                compress_image(filepath, max_size_kb=100)
                
                # Opdater brugerens profilbillede i databasen
                user.profile_picture = os.path.join(app.config['UPLOAD_FOLDER'], filename)  # Gem relativ sti
                db.session.commit()
                
                return {'status': 'success', 'image_url': url_for('static', filename=user.profile_picture)}, 200
            except Exception as e:
                return {'status': 'error', 'message': 'Der opstod en fejl under upload af billedet.'}, 500
        
        return {'status': 'error', 'message': 'Formatet på billedet understøttes ikke. Kun png, jpg og jpeg understøttes'}, 400
    return {'status': 'error', 'message': 'Du skal være logget ind for at uploade et billede.'}, 401

@app.route('/send_friend_request/<int:friend_id>', methods=['POST'])
def send_friend_request(friend_id):
    ip = request.remote_addr  # Hent IP-adressen for klienten
    if is_rate_limited(ip, 'send_friend_request', limit=5, period=60):  # Maks. 5 venneanmodninger pr. minut
        return {'status': 'danger', 'message': 'Too many friend requests. Please try again later.'}, 429

    if 'user_id' not in session:
        return {'status': 'danger', 'message': 'Du skal være logget ind for at sende en venneanmodning.'}, 401

    user = db.session.get(User, session['user_id'])
    if not user:
        return {'status': 'danger', 'message': 'Brugeren blev ikke fundet.'}, 404

    if user.id == friend_id:
        return {'status': 'danger', 'message': 'Du kan ikke sende en venneanmodning til dig selv.'}, 400

    friend = db.session.get(User, friend_id)
    if not friend:
        return {'status': 'warning', 'message': 'Brugeren blev ikke fundet.'}, 404

    existing_request = Friendship.query.filter_by(user_id=user.id, friend_id=friend.id).first()
    if existing_request:
        if existing_request.status == 'pending':
            return {'status': 'info', 'message': 'Du har allerede sendt en venneanmodning.'}, 200
        elif existing_request.status == 'accepted':
            return {'status': 'info', 'message': 'I er allerede venner.'}, 200

    try:
        friendship = Friendship(user_id=user.id, friend_id=friend.id, status='pending')
        db.session.add(friendship)
        db.session.commit()
        return {'status': 'success', 'new_status': 'pending_sent'}, 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Fejl under oprettelse af venneanmodning: {e}")
        return {'status': 'danger', 'message': 'Der opstod en fejl under oprettelsen af venneanmodningen.'}, 500
    
@app.route('/accept_friend_request/<int:friendship_id>', methods=['POST'])
def accept_friend_request(friendship_id):
    ip = request.remote_addr  # Hent IP-adressen for klienten
    if is_rate_limited(ip, 'accept_friend_request', limit=5, period=60):  # Maks. 5 anmodninger pr. minut
        return {'status': 'danger', 'message': 'Too many friend request acceptances. Please try again later.'}, 429

    app.logger.info(f"Forsøger at acceptere venneanmodning med ID: {friendship_id}")

    if 'user_id' not in session:
        return {'status': 'danger', 'message': 'Du skal være logget ind for at acceptere en venneanmodning.'}, 401

    friendship = Friendship.query.get(friendship_id)
    if not friendship:
        app.logger.warning(f"Venneanmodning med ID {friendship_id} blev ikke fundet.")
        return {'status': 'danger', 'message': 'Venneanmodningen blev ikke fundet.'}, 404

    if friendship.friend_id != session['user_id']:
        app.logger.warning(f"Bruger har ikke tilladelse til at acceptere venneanmodning med ID {friendship_id}.")
        return {'status': 'danger', 'message': 'Du har ikke tilladelse til at acceptere denne venneanmodning.'}, 403

    try:
        friendship.status = 'accepted'
        db.session.commit()
        app.logger.info(f"Venneanmodning med ID {friendship_id} blev accepteret.")
        return {'status': 'success', 'new_status': 'remove_friend', 'message': 'Venneanmodning accepteret.'}, 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Fejl under accept af venneanmodning: {e}")
        return {'status': 'danger', 'message': 'Der opstod en fejl under accept af venneanmodningen.'}, 500
    
@app.route('/reject_friend_request/<int:friendship_id>', methods=['POST'])
def reject_friend_request(friendship_id):
    ip = request.remote_addr  # Hent IP-adressen for klienten
    if is_rate_limited(ip, 'reject_friend_request', limit=5, period=60):  # Maks. 5 anmodninger pr. minut
        return {'status': 'danger', 'message': 'Too many friend request rejections. Please try again later.'}, 429

    app.logger.info(f"Forsøger at afvise venneanmodning med ID: {friendship_id}")

    if 'user_id' not in session:
        return {'status': 'danger', 'message': 'Du skal være logget ind for at afvise en venneanmodning.'}, 401

    friendship = Friendship.query.get(friendship_id)
    if not friendship:
        app.logger.warning(f"Venneanmodning med ID {friendship_id} blev ikke fundet.")
        return {'status': 'danger', 'message': 'Venneanmodningen blev ikke fundet.'}, 404

    if friendship.friend_id != session['user_id']:
        app.logger.warning(f"Bruger har ikke tilladelse til at afvise venneanmodning med ID {friendship_id}.")
        return {'status': 'danger', 'message': 'Du har ikke tilladelse til at afvise denne venneanmodning.'}, 403

    try:
        db.session.delete(friendship)
        db.session.commit()
        app.logger.info(f"Venneanmodning med ID {friendship_id} blev afvist.")
        return {'status': 'success', 'new_status': 'none', 'message': 'Venneanmodning afvist.'}, 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Fejl under afvisning af venneanmodning: {e}")
        return {'status': 'danger', 'message': 'Der opstod en fejl under afvisning af venneanmodningen.'}, 500
    
@app.route('/cancel_friend_request/<int:friend_id>', methods=['POST'])
def cancel_friend_request(friend_id):
    ip = request.remote_addr  # Hent IP-adressen for klienten
    if is_rate_limited(ip, 'cancel_friend_request', limit=5, period=60):  # Maks. 5 anmodninger pr. minut
        return {'status': 'danger', 'message': 'Too many friend request cancellations. Please try again later.'}, 429

    if 'user_id' not in session:
        return {'status': 'danger', 'message': 'Du skal være logget ind for at annullere en venneanmodning.'}, 401

    user = db.session.get(User, session['user_id'])
    if not user:
        return {'status': 'danger', 'message': 'Brugeren blev ikke fundet.'}, 404

    friendship = Friendship.query.filter_by(user_id=user.id, friend_id=friend_id, status='pending').first()
    if not friendship:
        return {'status': 'warning', 'message': 'Ingen venneanmodning blev fundet.'}, 404

    try:
        db.session.delete(friendship)
        db.session.commit()
        return {'status': 'success', 'new_status': 'none'}, 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Fejl under annullering af venneanmodning: {e}")
        return {'status': 'danger', 'message': 'Der opstod en fejl under annulleringen af venneanmodningen.'}, 500

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    ip = request.remote_addr  # Hent IP-adressen for klienten
    if is_rate_limited(ip, 'admin_login', limit=5, period=60):  # Maks. 5 loginforsøg pr. minut
        return "Too many login attempts. Please try again later.", 429

    if request.method == 'POST':
        admin_username = request.form['username']
        admin_password = request.form['password']

        # Hardkodede admin-oplysninger (kan flyttes til miljøvariabler for sikkerhed)
        if admin_username == ADMIN_USERNAME and admin_password == ADMIN_PASSWORD:
            session['is_admin'] = True  # Sæt admin-session
            return redirect(url_for('admin'))
        else:
            flash('Invalid admin credentials.', 'danger')
    return render_template('admin_login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    ip = request.remote_addr

    # Begræns kun POST-anmodninger
    if request.method == 'POST' and is_rate_limited(ip, 'register', limit=2, period=10):  # Maks. 2 registreringsforsøg pr. 10 sekunder
        return "Too many registration attempts. Please try again later.", 429

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Tjek om brugernavnet allerede er taget
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Brugernavnet er allerede taget. Vælg venligst et andet.')
            return redirect(url_for('register'))

        # Opret ny bruger
        new_user = User(username=username, password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit()

        # Log brugeren ind
        session['user_id'] = new_user.id
        return redirect(url_for('index'))

    # GET-anmodning: Vis registreringssiden
    return render_template('register.html', show_navbar=False)

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = request.remote_addr
    if is_rate_limited(ip, 'login', limit=5, period=60):  # Maks. 5 loginforsøg pr. minut
        return "Too many login attempts. Please try again later.", 429

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            flash('Brugernavnet findes ikke eller adgangskoden er forkert.', 'danger')
    return render_template('login.html')

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

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    user, redirect_response = get_logged_in_user()
    if redirect_response:
        return redirect_response

    total_beers, last_beer_time = get_user_stats(user)

    # Beregn cooldown for brugernavnsskift
    cooldown_message = None
    if user.last_username_change:
        cooldown_end = user.last_username_change + timedelta(days=7)
        if datetime.utcnow() < cooldown_end:
            remaining_time = cooldown_end - datetime.utcnow()
            cooldown_message = f"Du kan skifte dit brugernavn igen om {remaining_time.days} dage og {remaining_time.seconds // 3600} timer."

    return render_template(
        'profile.html',
        user=user,
        total_beers=total_beers,
        last_beer_time=last_beer_time,
        cooldown_message=cooldown_message
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
    if is_rate_limited(ip, 'delete_user', limit=5, period=60):  # Maks. 5 sletninger pr. minut
        return "Too many user deletions. Please try again later.", 429
    if session.get('is_admin'):  # Check if the user is an admin
        user = db.session.get(User, user_id)
        if user:  # Ensure the user exists
            try:
                # Delete the user's profile picture if it exists and is not the default
                if user.profile_picture and user.profile_picture != User.default_profile_picture:
                    profile_picture_path = os.path.join(os.getcwd(), user.profile_picture)
                    if os.path.exists(profile_picture_path):
                        os.remove(profile_picture_path)

                # Delete all BeerLog entries for the user
                BeerLog.query.filter_by(user_id=user.id).delete()

                # Delete all friendships involving the user
                Friendship.query.filter(
                    (Friendship.user_id == user.id) | (Friendship.friend_id == user.id)
                ).delete()

                # Delete the user
                db.session.delete(user)
                db.session.commit()

                flash(f'Brugeren "{user.username}" blev slettet.', 'success')
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
    if is_rate_limited(ip, 'delete_all_users', limit=1, period=3600):  # Maks. 1 sletning pr. time
        return "Too many requests. Please try again later.", 429
    if session.get('is_admin'):  # Ensure only admins can delete all users
        try:
            # Delete all BeerLogs
            BeerLog.query.delete()

            # Delete all Friendships
            Friendship.query.delete()

            # Delete all Users
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
@cache.cached(timeout=300)  # Cache i 5 minutter
def friends():
    ip = request.remote_addr
    if request.method == 'POST' and is_rate_limited(ip, 'friends', limit=10, period=60):  # Maks. 10 anmodninger pr. minut
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
            'id': friendship.id,
            'username': requester.username,
            'profile_picture': requester.profile_picture or User.default_profile_picture
        })

    # Håndter søgefunktionalitet
    search_results = []
    if request.method == 'POST':
        search_username = request.form['username']
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

@app.route('/add_friend/<int:friend_id>', methods=['POST'])
def add_friend(friend_id):
    ip = request.remote_addr  # Hent IP-adressen for klienten
    if is_rate_limited(ip, 'add_friend', limit=5, period=60):  # Maks. 5 venneanmodninger pr. minut
        return {'status': 'danger', 'message': 'Too many friend requests. Please try again later.'}, 429

    if 'user_id' not in session:
        return {'status': 'danger', 'message': 'Du skal være logget ind for at tilføje venner.'}, 401

    user = db.session.get(User, session['user_id'])
    if not user:
        return {'status': 'danger', 'message': 'Brugeren blev ikke fundet.'}, 404

    if user.id == friend_id:
        return {'status': 'danger', 'message': 'Du kan ikke tilføje dig selv som ven.'}, 400

    friend = db.session.get(User, friend_id)
    if not friend:
        return {'status': 'warning', 'message': 'Brugeren blev ikke fundet.'}, 404

    # Tjek om venskabet allerede eksisterer
    existing_friendship = Friendship.query.filter_by(user_id=user.id, friend_id=friend.id).first()
    if existing_friendship:
        return {
            'status': 'info',
            'message': f'{friend.username} er allerede din ven.',
            'friend': {
                'id': friend.id,
                'username': friend.username,
                'profile_picture': friend.profile_picture or User.default_profile_picture,
                'total_beers': sum(beer.count for beer in friend.beers),
                'last_beer_time': friend.beers[-1].timestamp.strftime('%d-%m-%Y %H:%M') if friend.beers else None,
                'created_at': existing_friendship.created_at.strftime('%d-%m-%Y')  # Tilføj dato for venskab
            }
        }, 200

    # Opret venskab
    try:
        friendship = Friendship(user_id=user.id, friend_id=friend.id, created_at=datetime.utcnow())
        db.session.add(friendship)
        db.session.commit()

        return {
            'status': 'success',
            'message': f'{friend.username} er blevet tilføjet som ven!',
            'friend': {
                'id': friend.id,
                'username': friend.username,
                'profile_picture': friend.profile_picture or User.default_profile_picture,
                'total_beers': sum(beer.count for beer in friend.beers),
                'last_beer_time': friend.beers[-1].timestamp.strftime('%d-%m-%Y %H:%M') if friend.beers else None,
                'created_at': friendship.created_at.strftime('%d-%m-%Y')  # Tilføj dato for venskab
            }
        }, 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Fejl under tilføjelse af ven: {e}")
        return {'status': 'danger', 'message': 'Der opstod en fejl under tilføjelsen af vennen.'}, 500

@app.route('/remove_friend/<int:friendship_id>', methods=['POST'])
def remove_friend(friendship_id):
    ip = request.remote_addr  # Hent IP-adressen for klienten
    if is_rate_limited(ip, 'remove_friend', limit=5, period=60):  # Maks. 5 anmodninger pr. minut
        return {'status': 'danger', 'message': 'Too many friend removal requests. Please try again later.'}, 429

    app.logger.info(f"Anmodning om at fjerne ven med ID: {friendship_id}")

    if 'user_id' not in session:
        app.logger.warning("Bruger ikke logget ind.")
        return {'status': 'danger', 'message': 'Du skal være logget ind for at fjerne en ven.'}, 401

    user_id = session['user_id']
    app.logger.info(f"Bruger ID: {user_id}")

    # Tjek om venskabet findes
    friendship = Friendship.query.get(friendship_id)

    if not friendship:
        app.logger.warning(f"Venskabet med ID {friendship_id} blev ikke fundet.")
        return {'status': 'warning', 'message': 'Venskabet findes ikke.'}, 404

    # Tjek om brugeren har tilladelse til at fjerne venskabet
    if friendship.user_id != user_id and friendship.friend_id != user_id:
        app.logger.warning(f"Bruger {user_id} har ikke tilladelse til at fjerne venskabet med ID {friendship_id}.")
        return {'status': 'danger', 'message': 'Du har ikke tilladelse til at fjerne dette venskab.'}, 403

    try:
        # Log hvem der fjernes som ven
        friend_user_id = friendship.friend_id if friendship.user_id == user_id else friendship.user_id
        friend_user = db.session.get(User, friend_user_id)
        friend_username = friend_user.username if friend_user else "Ukendt bruger"

        db.session.delete(friendship)
        db.session.commit()
        app.logger.info(f"Venskabet med ID {friendship_id} mellem bruger {user_id} og {friend_user_id} blev fjernet.")
        return {'status': 'success', 'message': f'Vennen "{friend_username}" blev fjernet.'}, 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Fejl under fjernelse af ven med ID {friendship_id}: {e}")
        return {'status': 'danger', 'message': 'Der opstod en fejl under fjernelsen af vennen.'}, 500

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
        user = db.session.get(User, session['user_id'])
        if user:
            # Hent alle logs én gang
            all_logs = BeerLog.query.all()

            # Filtrer brugerens egne logs
            user_logs = [log for log in all_logs if log.user_id == user.id]

            # Filtrer logs for brugerens venner
            friends = [friendship.friend for friendship in user.friendships]
            friends_logs = [log for log in all_logs if log.user_id in [friend.id for friend in friends]]

            # Serialiser logs
            user_logs_serializable = [
                {
                    'latitude': log.latitude,
                    'longitude': log.longitude,
                    'count': log.count,
                    'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                } for log in user_logs if log.latitude and log.longitude
            ]

            friends_logs_serializable = [
                {
                    'latitude': log.latitude,
                    'longitude': log.longitude,
                    'count': log.count,
                    'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                } for log in friends_logs if log.latitude and log.longitude
            ]

            all_logs_serializable = [
                {
                    'latitude': log.latitude,
                    'longitude': log.longitude,
                    'count': log.count,
                    'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                } for log in all_logs if log.latitude and log.longitude
            ]

            # Pass the user object to the template
            return render_template(
                'map.html',
                user=user,  # Pass the user object
                user_logs=user_logs_serializable,
                friends_logs=friends_logs_serializable,
                all_logs=all_logs_serializable
            )
    flash('Du skal være logget ind for at se kortet.', 'danger')
    return redirect(url_for('login'))

@app.route('/set_cookie_consent', methods=['POST'])
def set_cookie_consent():
    response = redirect(request.referrer or url_for('index'))
    response.set_cookie('cookie_consent', 'true', max_age=365*24*60*60)  # 1 år
    return response

@app.route('/settings')
def settings():
    user, redirect_response = get_logged_in_user()
    if redirect_response:
        return redirect_response

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

    # Generer leaderboard-data
    user, redirect_response = get_logged_in_user()
    if redirect_response:
        return redirect_response

    total_users = User.query.count()

    leaderboard_sections = [
        ("Inden for de sidste 24 timer", get_leaderboard_data(user.id, timedelta(days=1))),
        ("Inden for den sidste uge", get_leaderboard_data(user.id, timedelta(weeks=1))),
        ("Inden for den sidste måned", get_leaderboard_data(user.id, timedelta(days=30))),
        ("Inden for det sidste år", get_leaderboard_data(user.id, timedelta(days=365))),
        ("Flest øl drukket nogensinde", get_leaderboard_data(user.id))
    ]

    rendered_data = render_template(
        'leaderboard.html',
        user=user,
        total_users=total_users,
        leaderboard_sections=leaderboard_sections
    )

    set_cache(cache_key, rendered_data, timeout=300)  # Cache i 5 minutter
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
        return redirect(url_for('profile'))

    user = db.session.get(User, session['user_id'])
    if not user:
        flash('Bruger ikke fundet.', 'danger')
        return redirect(url_for('profile'))

    # Check if the username is already taken
    existing_user = User.query.filter_by(username=new_username).first()
    if existing_user:
        flash('Brugernavnet er allerede taget. Vælg venligst et andet.', 'danger')
        return redirect(url_for('profile'))

    # Check for cooldown
    if user.last_username_change:
        cooldown_end = user.last_username_change + timedelta(days=7)
        if datetime.utcnow() < cooldown_end:
            remaining_time = cooldown_end - datetime.utcnow()
            flash(
                f'Du kan skifte dit brugernavn igen om {remaining_time.days} dage og {remaining_time.seconds // 3600} timer.',
                'danger'
            )
            return redirect(url_for('profile'))

    # If confirmation is not provided, show the warning
    if not confirm_change:
        flash('Er du sikker på at du vil ændre dit navn? Der vil gå 7 dage før du kan ændre det igen.', 'warning')
        return redirect(url_for('profile'))

    # Update the username and last_username_change timestamp
    user.username = new_username
    user.last_username_change = datetime.utcnow()
    db.session.commit()

    flash('Dit brugernavn er blevet opdateret!', 'success')
    return redirect(url_for('profile'))
    
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Opret tabeller til dine modeller
    app.run()