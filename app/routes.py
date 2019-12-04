from flask import Flask, render_template, url_for, flash, redirect, request, session, logging
from app.models import admin_users, users, modules, posts, replies
from app.forms import RegistrationForm, AdminLoginForm, LoginForm, PostForm, ReplyForm, DeletePostForm, FilterPostForm, DeleteReplyForm, CreateAdminForm
from app import app, db, bcrypt
import flask_login
from flask_login import UserMixin, login_user, current_user, login_required
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import desc

login_manager = flask_login.LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return users.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
def home():

    get_modules = modules.query.order_by(modules.modulename).all()
    return render_template('home.html', modules = get_modules)

@app.route('/board', methods=['GET', 'POST'])
@login_required
def board():

    page = request.args.get('page', 1, type=int)
    module_name = request.args.get('module')

    get_posts = posts.query.filter_by(modulename=module_name).order_by(desc(posts.id)).paginate(page=page, per_page=5)

    return render_template('board.html', module=module_name, posts=get_posts)

@app.route('/post', methods=['GET', 'POST'])
@login_required
def post():

    form = ReplyForm()
    if form.validate_on_submit():

        now = datetime.now()
        date_time = now.strftime("%H:%M, %d/%m/%Y")

        module_name = request.args.get('module')
        post_id = request.args.get('post_id')

        addreply = replies(post_id = post_id, content = form.reply_content.data, time = date_time)
        db.session.add(addreply)
        db.session.commit()

        flash('Reply created successfully.', 'success')
        return redirect('/post?module={}&post_id={}'.format(module_name, post_id))

    post_id = request.args.get('post_id')
    module_name = request.args.get('module')
    page = request.args.get('page', 1, type=int)

    get_posts = posts.query.filter_by(id=post_id).all()
    get_replies = replies.query.filter_by(post_id=post_id).order_by(desc(replies.id)).paginate(page=page, per_page=5)

    return render_template('post.html', form=form, module=module_name, post_id=post_id, posts=get_posts, replies=get_replies)

@app.route('/create-post', methods=['GET', 'POST'])
@login_required
def create_post():

    form = PostForm()
    if form.validate_on_submit():

        now = datetime.now()
        date_time = now.strftime("%H:%M, %d/%m/%Y")

        module_name = request.args.get('module')

        addpost = posts(modulename = module_name, title = form.post_title.data, content = form.post_content.data, time = date_time)
        db.session.add(addpost)
        db.session.commit()

        flash('Post created successfully.', 'success')
        return redirect('/board?module={}'.format(module_name))

    module_name = request.args.get('module')
    return render_template('create-post.html', form=form, module_name=module_name)

@app.route('/register', methods=['GET', 'POST'])
def register():

    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegistrationForm()
    if form.validate_on_submit():

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        adduser = users(username = form.username.data, email = form.email.data, password = hashed_password)
        db.session.add(adduser)
        db.session.commit()

        flash('Account created for {}, you can now log-in.'.format(form.username.data), 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():

    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():

        user = users.query.filter_by(username=form.username.data).first()

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            flash('You have been successfully logged-in.', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():

    flask_login.logout_user()
    flash('You have been logged out.', 'primary')
    return redirect(url_for('home'))

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():

    if 'logged' in session:
        return render_template('admin_panel.html')

    form = AdminLoginForm()
    if form.validate_on_submit():

        admin_user = admin_users.query.filter_by(username=form.username.data, password=form.password.data).first()

        if admin_user:
            session['logged'] = 'logged'
            flash('You have been successfully logged-in.', 'success')
            return redirect(url_for('admin_panel'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')

    return render_template('admin_login.html', form=form)

@app.route('/admin_panel')
def admin_panel():
    if 'logged' in session:
        return render_template('admin_panel.html')
    else:
        flash('Please login to access this page.', 'danger')
        return redirect(url_for('admin_login'))

@app.route('/admin_posts', methods=['GET', 'POST'])
def admin_posts():
    if 'logged' in session:

        page = request.args.get('page', 1, type=int)
        filter = request.args.get('filter')

        if filter:
            filter = request.args.get('filter')
        else:
            filter = "Show All"

        if filter == "Show All":
            get_posts = posts.query.paginate(page=page, per_page=10)
        else:
            get_posts = posts.query.filter_by(modulename=filter).paginate(page=page, per_page=10)

        form = DeletePostForm()
        form2 = FilterPostForm()

        if form.validate_on_submit():

            post_id = form.post_id.data
            post = posts.query.filter_by(id=post_id).first()

            if post:
                return redirect(url_for('delete_confirm', post_id=post_id))
            else:
                flash('No post found with that ID.', 'danger')
                return redirect('admin_posts')

        if form2.validate_on_submit():
            return redirect(url_for('admin_posts', filter=form2.filter.data))

        return render_template('admin_posts.html', posts=get_posts, form=form, form2=form2, filter=filter)
    else:
        flash('Please login to access this page.', 'danger')
        return redirect(url_for('admin_login'))

@app.route('/admin_replies', methods=['GET', 'POST'])
def admin_replies():
    if 'logged' in session:

        page = request.args.get('page', 1, type=int)

        form = DeleteReplyForm()

        get_replies = replies.query.paginate(page=page, per_page=10)

        if form.validate_on_submit():
            reply_id = form.reply_id.data
            reply = replies.query.filter_by(id=reply_id).first()

            if reply:
                return redirect(url_for('delete_confirm_replies', reply_id=reply_id))
            else:
                flash('No reply found with that ID.', 'danger')
                return redirect('admin_replies')


        return render_template('admin_replies.html', form=form, replies=get_replies)
    else:
        flash('Please login to access this page.', 'danger')
        return redirect(url_for('admin_login'))

@app.route('/admin_users_list')
def admin_users_list():
    if 'logged' in session:

        page = request.args.get('page', 1, type=int)

        get_users = users.query.paginate(page=page, per_page=10)

        return render_template('admin_users_list.html', users=get_users)
    else:
        flash('Please login to access this page.', 'danger')
        return redirect(url_for('admin_login'))

@app.route('/admin_admin_users')
def admin_admin_users():
    if 'logged' in session:

        page = request.args.get('page', 1, type=int)

        get_users = admin_users.query.paginate(page=page, per_page=10)

        return render_template('admin_admin_users.html', users=get_users)
    else:
        flash('Please login to access this page.', 'danger')
        return redirect(url_for('admin_login'))

@app.route('/admin_logout')
def admin_logout():
    session.pop('logged', None)
    flash('You have been logged out as an Administrator.', 'primary')
    return redirect(url_for('home'))

@app.route('/delete_confirm')
def delete_confirm():

    if 'logged' in session:
        post_id = request.args.get('post_id')
        post = posts.query.filter_by(id=post_id).first()

        return render_template('delete_confirm.html', post=post, post_id=post_id)
    else:
        flash('Please login to access this page.', 'danger')
        return redirect(url_for('admin_login'))

@app.route('/delete_post')
def delete_post():

    if 'logged' in session:
        post_id = request.args.get('post_id')
        deleted_post = posts.query.filter_by(id=post_id).first()

        if deleted_post:
            db.session.delete(deleted_post)
            db.session.commit()

            flash('Post deleted!', 'success')
            return redirect(url_for('admin_posts'))
        else:
            flash('No post found with ID of: {}'.format(post_id), 'danger')
            return redirect(url_for('admin_posts'))
    else:
        flash('Please login to access this page.', 'danger')
        return redirect(url_for('admin_login'))

@app.route('/delete_confirm_replies')
def delete_confirm_replies():

    if 'logged' in session:
        reply_id = request.args.get('reply_id')
        reply = replies.query.filter_by(id=reply_id).first()

        return render_template('delete_confirm_replies.html', reply=reply, reply_id=reply_id)
    else:
        flash('Please login to access this page.', 'danger')
        return redirect(url_for('admin_login'))

@app.route('/delete_reply')
def delete_reply():

    if 'logged' in session:
        reply_id = request.args.get('reply_id')
        deleted_reply = replies.query.filter_by(id=reply_id).first()

        if deleted_reply:
            db.session.delete(deleted_reply)
            db.session.commit()

            flash('Reply deleted!', 'success')
            return redirect(url_for('admin_replies'))
        else:
            flash('No reply found with ID of: {}'.format(reply_id), 'danger')
            return redirect(url_for('admin_replies'))
    else:
        flash('Please login to access this page.', 'danger')
        return redirect(url_for('admin_login'))

@app.route('/admin_create_admin', methods=['GET', 'POST'])
def admin_create_admin():
    if 'logged' in session:
        form = CreateAdminForm()
        if form.validate_on_submit():

            adduser = admin_users(username = form.username.data, password = form.password.data)
            db.session.add(adduser)
            db.session.commit()

            flash('Admin account created for {}, they can now log-in.'.format(form.username.data), 'success')
            return redirect(url_for('admin_admin_users'))

        return render_template('admin_create_admin.html', form=form)
    else:
        flash('Please login to access this page.', 'danger')
        return redirect(url_for('admin_login'))

@app.route('/delete_confirm_admins')
def delete_confirm_admins():

    if 'logged' in session:
        user_id = request.args.get('user_id')
        user = admin_users.query.filter_by(id=user_id).first()

        return render_template('delete_confirm_admins.html', user=user, user_id=user_id)
    else:
        flash('Please login to access this page.', 'danger')
        return redirect(url_for('admin_login'))

@app.route('/delete_admin')
def delete_admin():
    if 'logged' in session:
        user_id = request.args.get('user_id')
        deleted_user = admin_users.query.filter_by(id=user_id).first()

        if deleted_user:
            db.session.delete(deleted_user)
            db.session.commit()

            flash('User deleted!', 'success')
            return redirect(url_for('admin_admin_users'))
        else:
            flash('No user found.', 'danger')
            return redirect(url_for('admin_admin_users'))
    else:
        flash('Please login to access this page.', 'danger')
        return redirect(url_for('admin_login'))

@app.route('/admin_create_user', methods=['GET', 'POST'])
def admin_create_user():

    if 'logged' in session:
        form = RegistrationForm()
        if form.validate_on_submit():

            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

            adduser = users(username = form.username.data, email = form.email.data, password = hashed_password)
            db.session.add(adduser)
            db.session.commit()

            flash('Account created for {}, they can now log-in.'.format(form.username.data), 'success')
            return redirect(url_for('admin_users_list'))

        return render_template('admin_create_user.html', form=form)
    else:
        flash('Please login to access this page.', 'danger')
        return redirect(url_for('admin_login'))

@app.route('/delete_confirm_users')
def delete_confirm_users():

    if 'logged' in session:
        user_id = request.args.get('user_id')
        user = users.query.filter_by(id=user_id).first()

        return render_template('delete_confirm_users.html', user=user, user_id=user_id)
    else:
        flash('Please login to access this page.', 'danger')
        return redirect(url_for('admin_login'))

@app.route('/delete_user')
def delete_user():
    if 'logged' in session:
        user_id = request.args.get('user_id')
        deleted_user = users.query.filter_by(id=user_id).first()

        if deleted_user:
            db.session.delete(deleted_user)
            db.session.commit()

            flash('User deleted!', 'success')
            return redirect(url_for('admin_users_list'))
        else:
            flash('No user found.', 'danger')
            return redirect(url_for('admin_users_list'))
    else:
        flash('Please login to access this page.', 'danger')
        return redirect(url_for('admin_login'))

@app.errorhandler(404)
def not_found(e):
    redirect('/home')
    return render_template("404.html")

@login_manager.unauthorized_handler
def unauthorized_handler():
    return redirect(url_for('login'))
