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
    last_username_change = db.Column(db.DateTime, nullable=True)  # Add this field
    
class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Tilføj denne linje
    status = db.Column(db.String(20), default='pending')  # 'pending', 'accepted', 'rejected'
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
            app.logger.error("Ingen fil valgt.")
            return {'status': 'error', 'message': 'Ingen fil valgt.'}, 400
        
        file = request.files['profile_picture']
        if file.filename == '':
            app.logger.error("Ingen fil valgt.")
            return {'status': 'error', 'message': 'Ingen fil valgt.'}, 400
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            try:
                app.logger.info(f"Gemmer fil midlertidigt: {filepath}")
                
                # Delete the old profile picture if it exists and is not the default
                if user.profile_picture and user.profile_picture != User.default_profile_picture:
                    old_filepath = os.path.join(os.getcwd(), user.profile_picture)
                    if os.path.exists(old_filepath):
                        app.logger.info(f"Sletter gammelt profilbillede: {old_filepath}")
                        os.remove(old_filepath)
                
                # Save the new file temporarily
                file.save(filepath)
                app.logger.info(f"Fil gemt: {filepath}")
                
                # Resize and compress the image to a maximum of 100 KB
                compress_image(filepath, max_size_kb=100)
                app.logger.info(f"Fil komprimeret: {filepath}")
                
                # Update the user's profile picture in the database
                user.profile_picture = os.path.relpath(filepath, os.getcwd())  # Save relative path
                db.session.commit()
                app.logger.info(f"Profilbillede opdateret i databasen: {user.profile_picture}")
                
                return {'status': 'success', 'image_url': url_for('static', filename=user.profile_picture)}, 200
            except Exception as e:
                app.logger.error(f"Fejl under upload af profilbillede: {e}")
                return {'status': 'error', 'message': 'Der opstod en fejl under upload af billedet.'}, 500
        
        app.logger.error("Formatet på billedet understøttes ikke.")
        return {'status': 'error', 'message': 'Formatet på billedet understøttes ikke. Kun png, jpg og jpeg understøttes'}, 400
    app.logger.error("Bruger ikke logget ind.")
    return {'status': 'error', 'message': 'Du skal være logget ind for at uploade et billede.'}, 401

@app.route('/send_friend_request/<int:friend_id>', methods=['POST'])
def send_friend_request(friend_id):
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

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    # Ensure the user is logged in
    if 'user_id' not in session:
        flash('Du skal være logget ind for at se din profil.', 'danger')
        return redirect(url_for('login'))

    # Retrieve the logged-in user
    user = db.session.get(User, session['user_id'])
    if not user:
        flash('Bruger ikke fundet.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Handle profile picture upload
        if 'profile_picture' in request.files and request.files['profile_picture'].filename != '':
            file = request.files['profile_picture']
            if not allowed_file(file.filename):
                flash('Formatet på billedet understøttes ikke. Prøv igen med en PNG, JPG eller JPEG.', 'danger')
                return redirect(url_for('profile'))

            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            try:
                # Delete the old profile picture if it exists and is not the default
                if user.profile_picture and user.profile_picture != User.default_profile_picture:
                    old_filepath = os.path.join(os.getcwd(), user.profile_picture)
                    if os.path.exists(old_filepath):
                        os.remove(old_filepath)

                # Save the new file
                file.save(filepath)

                # Resize the image to a maximum of 300x300 pixels
                with Image.open(filepath) as img:
                    img = img.convert("RGB")  # Ensure the image is in RGB format
                    img.thumbnail((300, 300))  # Resize to max 300x300 pixels
                    img.save(filepath, "JPEG", quality=85)  # Save as JPEG with 85% quality

                # Update the user's profile picture in the database
                user.profile_picture = os.path.relpath(filepath, os.getcwd())  # Save relative path
                db.session.commit()

                flash('Profilbillede opdateret!', 'success')
            except Exception as e:
                app.logger.error(f"Fejl under upload af profilbillede: {e}")
                flash('Der opstod en fejl under upload af billedet. Prøv igen.', 'danger')
                return redirect(url_for('profile'))

    # Calculate cooldown for username change
    cooldown_message = None
    if user.last_username_change:
        cooldown_end = user.last_username_change + timedelta(days=7)
        if datetime.utcnow() < cooldown_end:
            remaining_time = cooldown_end - datetime.utcnow()
            cooldown_message = f"Du kan skifte dit brugernavn igen om {remaining_time.days} dage og {remaining_time.seconds // 3600} timer."

    # Render the profile page
    return render_template(
        'profile.html',
        user=user,
        cooldown_message=cooldown_message
    )

@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
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
def friends():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    if not user:
        return redirect(url_for('login'))

    # Fetch the user's friends
    friends = []
    for friendship in Friendship.query.filter(
        ((Friendship.user_id == user.id) | (Friendship.friend_id == user.id)) &
        (Friendship.status == 'accepted')
    ).all():
        if friendship.user_id == user.id:
            friend = friendship.friend
        else:
            friend = friendship.user

        beer_logs = BeerLog.query.filter_by(user_id=friend.id).all()
        total_beers = sum(log.count for log in beer_logs)
        last_beer_time = beer_logs[-1].timestamp.strftime('%Y-%m-%d %H:%M:%S') if beer_logs else None

        friends.append({
            'id': friend.id,
            'username': friend.username,
            'profile_picture': friend.profile_picture or 'static/icon-5355896_640.png',
            'total_beers': total_beers,
            'last_beer_time': last_beer_time,
            'created_at': friendship.created_at.strftime('%d-%m-%Y'),
            'friendship_id': friendship.id  # Tilføj friendship_id
        })

    # Fetch friend requests
    friend_requests = []
    for friendship in Friendship.query.filter_by(friend_id=user.id, status='pending').all():
        requester = friendship.user
        friend_requests.append({
            'id': friendship.id,
            'username': requester.username,
            'profile_picture': requester.profile_picture or 'static/icon-5355896_640.png'
        })

    # Handle search functionality
    search_results = []
    if request.method == 'POST':
        search_username = request.form['username']
        search_results_query = User.query.filter(
            User.username.ilike(f'%{search_username}%'),
            User.id != user.id  # Exclude the logged-in user
        ).all()

        for result in search_results_query:
            # Exclude users who are already friends
            friendship = Friendship.query.filter(
                ((Friendship.user_id == user.id) & (Friendship.friend_id == result.id)) |
                ((Friendship.user_id == result.id) & (Friendship.friend_id == user.id))
            ).first()

            if friendship and friendship.status == 'accepted':
                continue  # Skip users who are already friends

            if friendship:
                if friendship.status == 'pending' and friendship.user_id == user.id:
                    status = 'pending_sent'
                elif friendship.status == 'pending' and friendship.friend_id == user.id:
                    status = 'pending_received'
                else:
                    status = 'none'
            else:
                status = 'none'

            search_results.append({
                'id': result.id,
                'username': result.username,
                'profile_picture': result.profile_picture or 'static/icon-5355896_640.png',
                'status': status
            })

    return render_template(
        'friends.html',
        user=user,
        friends=friends,
        friend_requests=friend_requests,
        search_results=search_results
    )

@app.route('/add_friend/<int:friend_id>', methods=['POST'])
def add_friend(friend_id):
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

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        flash('Du skal være logget ind for at se indstillingerne.', 'danger')
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    if not user:
        flash('Bruger ikke fundet.', 'danger')
        return redirect(url_for('login'))

    return render_template('settings.html', user=user)

@app.route('/leaderboard')
def leaderboard():
    if 'user_id' not in session:
        flash('Du skal være logget ind for at se leaderboardet.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']  # Hent den aktuelle brugers ID fra sessionen
    user = db.session.get(User, user_id)
    if not user:
        flash('Bruger ikke fundet.', 'danger')
        return redirect(url_for('login'))

    users = User.query.all()

    def get_leaderboard_data(time_delta=None):
        leaderboard_data = []
        for u in users:
            query = BeerLog.query.filter_by(user_id=u.id)
            if time_delta:
                query = query.filter(BeerLog.timestamp >= datetime.utcnow() - time_delta)
            total_beers = query.with_entities(db.func.sum(BeerLog.count)).scalar() or 0

            # Find status for venneanmodning
            friendship = Friendship.query.filter(
                ((Friendship.user_id == user.id) & (Friendship.friend_id == u.id)) |
                ((Friendship.user_id == u.id) & (Friendship.friend_id == user.id))
            ).first()

            if friendship:
                if friendship.status == 'pending' and friendship.user_id == user.id:
                    status = 'pending_sent'
                elif friendship.status == 'pending' and friendship.friend_id == user.id:
                    status = 'pending_received'
                elif friendship.status == 'accepted':
                    status = 'accepted'  # Status for eksisterende venner
                else:
                    status = 'none'
            else:
                status = 'none'

            leaderboard_data.append({
                'id': u.id,
                'username': u.username,
                'profile_picture': u.profile_picture or User.default_profile_picture,
                'total_beers': total_beers,
                'status': status,
                'friendship_id': friendship.id if friendship else None  # Sørg for at sende friendship_id
            })

        app.logger.info(f"Leaderboard data: {leaderboard_data}")
        leaderboard_data.sort(key=lambda x: x['total_beers'], reverse=True)
        return leaderboard_data[:10]

    total_users = User.query.count()

    leaderboard_sections = [
        ("Inden for de sidste 24 timer", get_leaderboard_data(timedelta(days=1))),
        ("Inden for den sidste uge", get_leaderboard_data(timedelta(weeks=1))),
        ("Inden for den sidste måned", get_leaderboard_data(timedelta(days=30))),
        ("Inden for det sidste år", get_leaderboard_data(timedelta(days=365))),
        ("Flest øl drukket nogensinde", get_leaderboard_data())
    ]

    return render_template(
        'leaderboard.html',
        user=user,
        total_users=total_users,
        leaderboard_sections=leaderboard_sections
    )
    
@app.route('/change_username', methods=['POST'])
def change_username():
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
        db.create_all()
    app.run(debug=True)