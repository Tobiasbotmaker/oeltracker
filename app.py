from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from flask_migrate import Migrate
import os
import logging
from PIL import Image
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
logging.basicConfig(level=logging.INFO)

app = Flask(__name__, static_folder='static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://beer_game_db_user:hMVeKc07Z2hLBMs28p9cllxyglWMNqxy@dpg-cvslpd7diees73fj3mkg-a.frankfurt-postgres.render.com/beer_game_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Slå ændringssporing fra (for performance)
app.config['SECRET_KEY'] = 'CIpFfzd/lCsLNdeBtZ9sxGkS8gkkFz3w'
app.config['UPLOAD_FOLDER'] = 'static/uploads/profile_pictures'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}
db = SQLAlchemy(app)
migrate = Migrate(app, db)

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
    
class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)  # Rettet fra 'user.id' til 'users.id'
    friend_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)  # Rettet fra 'user.id' til 'users.id'
    user = db.relationship('User', foreign_keys=[user_id], backref='friendships')
    friend = db.relationship('User', foreign_keys=[friend_id], backref='friends')

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
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if 'profile_picture' not in request.files:
            flash('Ingen fil valgt.', 'warning')
            return redirect(url_for('index'))
        
        file = request.files['profile_picture']
        if file.filename == '':
            flash('Ingen fil valgt.', 'warning')
            return redirect(url_for('index'))
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            try:
                # Slet det gamle profilbillede, hvis det findes, og ikke er standardbilledet
                if user.profile_picture and user.profile_picture != 'static/icon-5355896_640.png':
                    old_filepath = os.path.join(os.getcwd(), user.profile_picture)
                    if os.path.exists(old_filepath):
                        os.remove(old_filepath)
                
                # Gem den nye fil
                file.save(filepath)
                
                # Åbn billedet og gør det mindre
                with Image.open(filepath) as img:
                    img = img.convert("RGB")  # Sikrer, at billedet er i RGB-format
                    img.thumbnail((300, 300))  # Sæt maks. størrelse til 300x300 pixels
                    img.save(filepath, "JPEG", quality=85)  # Gem som JPEG med 85% kvalitet
                
                # Opdater brugerens profilbillede i databasen
                user.profile_picture = filepath
                db.session.commit()
                
                flash('Profilbillede opdateret!', 'success')
            except Exception as e:
                # Hvis der opstår en fejl (f.eks. forkert format)
                app.logger.error(f"Fejl under upload af profilbillede: {e}")
                flash('Formatet på billedet understøttes ikke. Prøv igen med en PNG, JPG eller JPEG.', 'danger')
                return redirect(url_for('index'))
            
            return redirect(url_for('index'))
        else:
            flash('Formatet på billedet understøttes ikke. Prøv igen med en PNG, JPG eller JPEG.', 'danger')
            return redirect(url_for('index'))
    flash('Du skal være logget ind for at uploade et billede.', 'danger')
    return redirect(url_for('login'))

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        admin_username = request.form['username']
        admin_password = request.form['password']

        # Hardkodede admin-oplysninger (kan flyttes til miljøvariabler for sikkerhed)
        if admin_username == 'admin' and admin_password == 'secure_admin_password':
            session['is_admin'] = True  # Sæt admin-session
            return redirect(url_for('admin'))
        else:
            flash('Invalid admin credentials.', 'danger')
    return render_template('admin_login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
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
        
        # Log brugeren ind og marker som ny bruger
        session['user_id'] = new_user.id
        session['is_new_user'] = True  # Marker som ny bruger
        
        return redirect(url_for('index'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Håndter login for både admin og almindelige brugere
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin  # Gem admin-status i sessionen
            if user.is_admin:
                return redirect(url_for('admin'))  # Send admin-brugere til admin-siden
            return redirect(url_for('index'))  # Send almindelige brugere til forsiden
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
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user:
            latitude = request.form.get('latitude')
            longitude = request.form.get('longitude')
            beer_log = BeerLog(user_id=user.id, count=1, timestamp=datetime.utcnow(), latitude=latitude, longitude=longitude)
            db.session.add(beer_log)
            db.session.commit()
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
    if session.get('is_admin'):  # Tjek om brugeren er admin
        user = db.session.get(User, user_id)
        if user:  # Tjekker kun, om brugeren findes
            try:
                # Slet tilknyttede BeerLog-poster
                BeerLog.query.filter_by(user_id=user.id).delete()
                # Slet tilknyttede Friendship-poster
                Friendship.query.filter((Friendship.user_id == user.id) | (Friendship.friend_id == user.id)).delete()
                # Slet brugeren
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

@app.route('/friends', methods=['GET', 'POST'])
def friends():
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if not user:
            return redirect(url_for('login'))
        
        # Hent brugerens venner
        friends = []
        for friendship in user.friendships:
            friend = friendship.friend
            beer_logs = BeerLog.query.filter_by(user_id=friend.id).all()
            total_beers = sum(log.count for log in beer_logs)
            last_beer_time = beer_logs[-1].timestamp.strftime('%Y-%m-%d %H:%M:%S') if beer_logs else None
            friends.append({
                'id': friend.id,
                'username': friend.username,
                'total_beers': total_beers,
                'last_beer_time': last_beer_time  # Send som formateret streng
            })
        
        # Håndter søgning
        search_results = []
        if request.method == 'POST':
            search_username = request.form['username']
            search_results = User.query.filter(User.username.ilike(f'%{search_username}%')).all()
            friend_ids = [friend['id'] for friend in friends]
            search_results = [result for result in search_results if result.id != user.id and result.id not in friend_ids]
        
        return render_template('friends.html', user=user, friends=friends, search_results=search_results)
    return redirect(url_for('login'))

@app.route('/add_friend/<int:friend_id>', methods=['POST'])
def add_friend(friend_id):
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user and user.id != friend_id:
            friend = db.session.get(User, friend_id)
            if friend:
                friendship = Friendship(user_id=user.id, friend_id=friend.id)
                db.session.add(friendship)
                db.session.commit()
    return redirect(url_for('friends'))

@app.route('/delete_beer', methods=['POST'])
def delete_beer():
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user:
            last_beer_log = BeerLog.query.filter_by(user_id=user.id).order_by(BeerLog.timestamp.desc()).first()
            if last_beer_log:
                db.session.delete(last_beer_log)
                db.session.commit()
    return redirect(url_for('index'))

@app.route('/map')
def map():
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

            return render_template(
                'map.html',
                user_logs=user_logs_serializable,
                friends_logs=friends_logs_serializable,
                all_logs=all_logs_serializable
            )
    return redirect(url_for('login'))

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/add_test_beer_log')
def add_test_beer_log():
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user:
            beer_log = BeerLog(user_id=user.id, count=1, timestamp=datetime.utcnow(), latitude=37.7749, longitude=-122.4194)
            db.session.add(beer_log)
            db.session.commit()
    return redirect(url_for('map'))

@app.route('/leaderboard')
def leaderboard():
    users = User.query.all()
    
    def get_leaderboard_data(time_delta=None):
        leaderboard_data = []
        for user in users:
            query = BeerLog.query.filter_by(user_id=user.id)
            if time_delta:
                query = query.filter(BeerLog.timestamp >= datetime.utcnow() - time_delta)
            total_beers = query.with_entities(db.func.sum(BeerLog.count)).scalar() or 0
            leaderboard_data.append({
                'username': user.username,
                'profile_picture': user.profile_picture,  # Inkluder profilbillede
                'total_beers': total_beers
            })
        leaderboard_data.sort(key=lambda x: x['total_beers'], reverse=True)
        return leaderboard_data[:10]  # Limit to top 10 users

    # Beregn det samlede antal brugere
    total_users = User.query.count()  # Tæl antallet af brugere i databasen

    top_10_all_time = get_leaderboard_data()
    top_10_24_hours = get_leaderboard_data(timedelta(days=1))
    top_10_week = get_leaderboard_data(timedelta(weeks=1))
    top_10_month = get_leaderboard_data(timedelta(days=30))
    top_10_year = get_leaderboard_data(timedelta(days=365))

    return render_template(
        'leaderboard.html', 
        total_users=total_users,  # Send antallet af brugere til skabelonen
        top_10_all_time=top_10_all_time,
        top_10_24_hours=top_10_24_hours,
        top_10_week=top_10_week,
        top_10_month=top_10_month,
        top_10_year=top_10_year
    )
    
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/which_beer')
def which_beer():
    return render_template('which_beer.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)