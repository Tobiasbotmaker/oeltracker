from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_migrate import Migrate
import os
import logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__, static_folder='static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://beer_game_db_user:hMVeKc07Z2hLBMs28p9cllxyglWMNqxy@dpg-cvslpd7diees73fj3mkg-a.frankfurt-postgres.render.com/beer_game_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Slå ændringssporing fra (for performance)
app.config['SECRET_KEY'] = 'CIpFfzd/lCsLNdeBtZ9sxGkS8gkkFz3w'
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
            beer_logs = BeerLog.query.filter_by(user_id=user.id).all()
            total_beers = sum(log.count for log in beer_logs)
            last_beer_time = beer_logs[-1].timestamp.strftime('%Y-%m-%d %H:%M:%S') if beer_logs else None
            total_beers_ever = db.session.query(db.func.sum(BeerLog.count)).scalar() or 0
            return render_template('index.html', username=user.username, total_beers=total_beers, last_beer_time=last_beer_time, is_admin=user.is_admin, total_beers_ever=total_beers_ever)
    return redirect(url_for('register'))

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
        
        # Log brugeren ind
        session['user_id'] = new_user.id
        
        # Send brugeren til index-siden
        return redirect(url_for('index'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            if user.is_admin:
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('index'))
        else:
            flash('Brugernavnet findes ikke eller adgangskoden er forkert.')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

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
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user and user.is_admin:
            users = User.query.all()
            return render_template('admin.html', users=users)
    return redirect(url_for('login'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' in session:
        current_user = db.session.get(User, session['user_id'])
        if current_user and current_user.is_admin:
            user = db.session.get(User, user_id)
            if user and user.username != 'admin':  # Prevent deletion of admin user
                # Delete associated BeerLog entries
                BeerLog.query.filter_by(user_id=user.id).delete()
                # Delete associated Friendship entries
                Friendship.query.filter((Friendship.user_id == user.id) | (Friendship.friend_id == user.id)).delete()
                db.session.delete(user)
                db.session.commit()
    return redirect(url_for('admin'))

@app.route('/friends', methods=['GET', 'POST'])
def friends():
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if not user:
            return redirect(url_for('login'))
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
                'last_beer_time': last_beer_time
            })
        
        search_results = []
        if request.method == 'POST':
            search_username = request.form['username']
            search_results = User.query.filter(User.username.like(f'%{search_username}%')).all()
            # Filter out friends from search results
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
            beer_logs = BeerLog.query.filter_by(user_id=user.id).all()
            beer_logs_serializable = [
                {
                    'latitude': log.latitude,
                    'longitude': log.longitude,
                    'count': log.count,  # Tilføj count her
                    'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                } for log in beer_logs if log.latitude and log.longitude
            ]
            return render_template('map.html', beer_logs=beer_logs_serializable)
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
                'total_beers': total_beers
            })
        leaderboard_data.sort(key=lambda x: x['total_beers'], reverse=True)
        return leaderboard_data[:10]  # Limit to top 10 users

    top_10_all_time = get_leaderboard_data()
    top_10_24_hours = get_leaderboard_data(timedelta(days=1))
    top_10_week = get_leaderboard_data(timedelta(weeks=1))
    top_10_month = get_leaderboard_data(timedelta(days=30))
    top_10_year = get_leaderboard_data(timedelta(days=365))

    return render_template('leaderboard.html', 
                           top_10_all_time=top_10_all_time,
                           top_10_24_hours=top_10_24_hours,
                           top_10_week=top_10_week,
                           top_10_month=top_10_month,
                           top_10_year=top_10_year)
    
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/which_beer')
def which_beer():
    return render_template('which_beer.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create an admin user if it doesn't exist
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', password=generate_password_hash('admin_password', method='pbkdf2:sha256'), is_admin=True)
            db.session.add(admin_user)
            db.session.commit()
    app.run(debug=True)