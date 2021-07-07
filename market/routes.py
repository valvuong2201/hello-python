from market import app, db
from flask import render_template, redirect, url_for, flash
from market.models import Item, User
from market.forms import RegisterForm, LoginForm
from flask_login import login_user, logout_user, login_required

@app.route('/')
@app.route('/home')
@login_required
def hello_world():
    items = Item.query.all()
    return render_template('home.html', items=items)


@app.route('/register', methods=['GET', 'POST'])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        user_to_create = User(
            username=form.username.data,
            email_address=form.email_address.data,
            password=form.password1.data
        )
        db.session.add(user_to_create)
        db.session.commit()
        login_user(user_to_create)
        flash('Account created successfully')
        return redirect(url_for('hello_world'))
    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(f'there was an error with creating user: {err_msg}')
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password_correction(password=form.password.data):
            login_user(user)
            flash(f'Success! You are logged in as {user.username}')
            return redirect(url_for('hello_world'))
        else:
            flash('Username and password are not match! Please try again')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout_page():
    logout_user()
    flash('You have been logged out!')
    return redirect(url_for('hello_world'))