from flask import Flask, render_template, request, redirect, session, jsonify, flash, url_for
from flask_sqlalchemy import SQLAlchemy
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import *
from authlib.integrations.flask_client import OAuth
import os
# from flask_mail import Mail, Message
import datetime
from sqlalchemy import func


app = Flask(__name__)
app.secret_key = secrets.token_hex(64)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@app.context_processor
def inject_user():
    return dict(
        user_id1=current_user.id if current_user.is_authenticated else None,
        user_authenticated1=current_user.is_authenticated,
        username1=current_user.username if current_user.is_authenticated else None
    )


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# ----------------------------------------------
# mail setting
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@example.com'
app.config['MAIL_PASSWORD'] = 'your-password'


# ----------------------

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='248108060247-lhfl7gkdngtd27t8lbh8j6j8q0vf6clt.apps.googleusercontent.com',
    client_secret='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',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)

# -------------------------------


app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgres:ahmadreza83@localhost/goldis'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.Enum('user', 'admin', name='user_roles'),
                     default='user', nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(
    ), onupdate=db.func.current_timestamp())
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)
    comment_likes = db.relationship('CommentLike', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(
        'users.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(
    ), onupdate=db.func.current_timestamp())
    comments = db.relationship('Comment', backref='post', lazy=True)
    likes = db.relationship('Like', backref='post', lazy=True)

    def __repr__(self):
        return f'<Post {self.title}>'


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey(
        'posts.id', ondelete='CASCADE'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey(
        'users.id', ondelete='CASCADE'), nullable=True)
    body = db.Column(db.Text, nullable=False)

    likes = db.relationship('CommentLike', backref='comment', lazy=True)

    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(
    ), onupdate=db.func.current_timestamp())

    def __repr__(self):
        return f'<Comment {self.body[:20]}>'


class Like(db.Model):
    __tablename__ = 'likes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(
        'users.id', ondelete='CASCADE'), nullable=True)
    post_id = db.Column(db.Integer, db.ForeignKey(
        'posts.id', ondelete='CASCADE'), nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<Like User:{self.user_id} Post:{self.post_id}>'


class CommentLike(db.Model):
    __tablename__ = 'comment_likes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(
        'users.id', ondelete='CASCADE'), nullable=True)
    comment_id = db.Column(db.Integer, db.ForeignKey(
        'comments.id', ondelete='CASCADE'), nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<CommentLike User:{self.user_id} Comment:{self.comment_id}>'


@app.route('/')
def index():

    # top_posts = db.session.query(
    #     Post,
    #     func.count(Like.id).label('likes_count')
    # ).join(Like, Like.post_id == Post.id) .group_by(Post.id).order_by(func.count(Like.id).desc()).limit(3).all()

    # posts = Post.query.limit(3).all()
    posts = Post.query.order_by(Post.created_at.desc()).limit(3).all()

    is_authenticated = current_user.is_authenticated
    is_authenticated = current_user.is_authenticated

    print(current_user.is_authenticated)
    return render_template('home.html', posts=posts)


@app.route('/login')
def login_show():
    return render_template('login.html')


@app.route('/signup')
def signup_get():
    # flash("You are already registered", "info")
    return render_template('signup.html')


@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    existing_user = User.query.filter(
        (User.username == username) | (User.email == email)).first()

    if existing_user:
        flash("User already exists", "error")
        return redirect('/signup')

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, email=email,
                    password=hashed_password, role='user')
    db.session.add(new_user)
    db.session.commit()

    # flash("Signup successful! Please log in", "success")
    return redirect('/login')


@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        login_user(user)
        # flash("Login successful!", "success")
        return redirect('/')
    else:
        flash("ایمیل یا رمز عبور نا معتبر", "error")
        return redirect('/login')


@app.route("/logout")
def logout():
    logout_user()
    return redirect('/login')


@app.route('/protected')
@login_required
def protect():
    user = current_user.get_id()
    print(user, '---------------')
    return "Hello, !"


@app.route('/add-post')
@login_required
def show_add_post():
    return render_template('addPost.html')


@app.route('/add-post', methods=['POST'])
@login_required
def add_post():
    title = request.form['title']
    body = request.form['body']

    if not title or not body:
        flash("Title and body are required.", "error")
        return redirect(url_for('add_post'))

    new_post = Post(
        user_id=int(current_user.get_id()),
        title=title,
        body=body
    )

    db.session.add(new_post)
    db.session.commit()

    flash("Post added successfully!", "success")
    return redirect("/")


@app.route('/all-post')
def show_all_post():
    posts = Post.query.all()
    return render_template('posts.html', posts=posts)


# @app.route('/all-post/<int:post_id>/<post_title>', methods=['GET'])
# def post_detail(post_id, post_title):
#     post = Post.query.get_or_404(post_id)
#     is_liked = False
#     if current_user.is_authenticated:
#         is_liked = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first() is not None
#     return render_template('post_detail.html', post=post, is_liked=is_liked)


# @app.route('/all-post/<int:post_id>/<post_title>', methods=['GET'])
# def post_detail(post_id, post_title):
#     post = Post.query.get_or_404(post_id)
#     is_liked = False
#     if current_user.is_authenticated:
#         is_liked = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first() is not None
#     return render_template('post_detail.html', post=post, is_liked=is_liked, user_authenticated=current_user.is_authenticated)


@app.route('/all-post/<int:post_id>/<post_title>', methods=['GET'])
def post_detail(post_id, post_title):
    post = Post.query.get_or_404(post_id)
    is_liked = False
    liked_comment_ids = []

    if current_user.is_authenticated:

        is_liked = Like.query.filter_by(
            user_id=current_user.id, post_id=post_id).first() is not None

        liked_comments = CommentLike.query.filter_by(user_id=current_user.id).join(
            Comment).filter(Comment.post_id == post_id).all()
        liked_comment_ids = [
            comment_like.comment_id for comment_like in liked_comments]

    return render_template('post_detail.html',
                           post=post,
                           is_liked=is_liked,
                           liked_comment_ids=liked_comment_ids,
                           user_authenticated=current_user.is_authenticated)


@app.route('/like-comment/<int:comment_id>', methods=['POST'])
@login_required
def toggle_comment_like(comment_id):

    comment = Comment.query.get_or_404(comment_id)

    comment_like = CommentLike.query.filter_by(
        comment_id=comment_id, user_id=current_user.id).first()

    if comment_like:

        db.session.delete(comment_like)
        db.session.commit()
        result = 'unliked'
    else:

        new_like = CommentLike(comment_id=comment_id, user_id=current_user.id)
        db.session.add(new_like)
        db.session.commit()
        result = 'liked'

    likes_count = CommentLike.query.filter_by(comment_id=comment_id).count()

    return jsonify({'result': result, 'likes_count': likes_count})


@app.route('/add-comment/<int:post_id>/<post_title>', methods=['POST'])
@login_required
def add_comment(post_id, post_title):
    post = Post.query.get_or_404(post_id)
    comment_body = request.form.get('comment_body')
    new_comment = Comment(
        post_id=post_id,
        user_id=int(current_user.get_id()),
        body=comment_body
    )
    db.session.add(new_comment)
    db.session.commit()
    flash('Comment added successfully!', 'success')
    return redirect("/all-post/{}/{}".format(post_id, post_title))


@app.route('/like/<int:post_id>', methods=['POST'])
@login_required
def toggle_like(post_id):
    post = Post.query.get_or_404(post_id)
    like = Like.query.filter_by(
        user_id=current_user.id, post_id=post_id).first()

    if like:
        db.session.delete(like)
        db.session.commit()
        liked = False
    else:
        new_like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(new_like)
        db.session.commit()
        liked = True

    likes_count = Like.query.filter_by(post_id=post_id).count()

    return jsonify({
        'result': 'liked' if liked else 'unliked',
        'likes_count': likes_count
    })


@app.route('/login/oauth')
def oath():
    google = oauth.create_client('google')
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/authorize')
def authorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    resp = google.get('userinfo', token=token)
    user_info = resp.json()

    user_email = user_info['email']
    user_name = user_info.get('name', user_email.split('@')[0])

    existing_user = User.query.filter_by(email=user_email).first()

    if existing_user:

        login_user(existing_user)
        # flash('Login successful via Google!', 'success')
    else:

        new_user = User(
            username=user_name,
            email=user_email,
            password='will be random '
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('Account created and logged in via Google!', 'success')

    return redirect('/')


@app.route('/my-posts')
@login_required
def show_my_posts():

    posts = Post.query.filter_by(user_id=current_user.id).all()
    return render_template('my_posts.html', posts=posts)


@app.route('/my-post/<int:post_id>/<post_title>', methods=['GET'])
@login_required
def my_post_detail(post_id, post_title):
    post = Post.query.get_or_404(post_id)

    if post.user_id != current_user.id:
        flash("You do not have permission to remove this post.", "error")
        return redirect('/my-posts')

    return render_template('my_post_detail.html', post=post)


@app.route('/remove-post/<int:post_id>')
@login_required
def remove_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        flash("You do not have permission to remove this post.", "error")
        return redirect('/my-posts')
    db.session.delete(post)
    db.session.commit()
    flash("Post removed successfully!", "success")
    return redirect('/my-posts')


@app.route('/edit-post/<int:post_id>')
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        flash("You do not have permission to remove this post.", "error")
        return redirect('/my-posts')

    return render_template('edit_post.html', post=post)


@app.route('/edit-post/<int:post_id>', methods=['POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)

    if post.user_id != current_user.id:
        flash("You do not have permission to edit this post.", "error")
        return redirect('/my-posts')

    new_title = request.form['title']
    new_body = request.form['body']

    post.title = new_title
    post.body = new_body

    try:
        db.session.commit()
        flash("Post updated successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash("An error occurred while updating the post. Please try again.", "error")
        print(f"Error updating post: {e}")

    return redirect('/my-posts')


# -------------------------------------------/
# mail

# -------------------------------------------/


@app.route('/user/profile')
@login_required
def profile():

    user = User.query.get(current_user.id)
    return render_template('profile.html', user=user)


@app.route('/user/profile/edit', methods=['GET'])
@login_required
def edit_profile():

    user = User.query.get(current_user.id)

    return render_template('edit_profile.html', user=user)


@app.route('/user/profile/edit', methods=['POST'])
@login_required
def edit_profile_post():

    user = User.query.get_or_404(current_user.id)

    username = request.form['username']
    password = request.form['password']

    user.username = username

    if password:
        user.password = generate_password_hash(
            password, method='pbkdf2:sha256')

    db.session.commit()
    flash('Profile updated successfully!', 'success')
    return redirect('/user/profile')


if __name__ == '__main__':
    app.run(debug=True)
