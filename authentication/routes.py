from flask import Blueprint, render_template, request, redirect, flash, url_for
from werkzeug.security import check_password_hash
from marvel_inventory.models import User, db
from marvel_inventory.forms import UserLoginForm
from flask_login import login_user, logout_user, current_user, login_required

auth = Blueprint('auth', __name__, template_folder = 'auth_templates')
# adding signup java route
@auth.route('/signup', methods = ['GET', 'POST'])
def signup():
    form = UserLoginForm()

    try:
        if request.method == 'POST' and form.validate_on_submit():
            # when submitted it will transfer this data
            email = form.email.data
            password = form.password.data
            display(email, password)
            user = User(email, password = password)
            # this one is kind of obvious
            db.session.add(user)
            db.session.commit()
            flash {email}, "created")

            return redirect(url_for('site.home'))
    except: #?
    return render_template('signup.html', form = form)

@auth.route('/signin', methods = ['GET', 'POST'])
def signin():
        form = UserLoginForm()
        try:
            if request.method == 'POST' and form.validate_on_submit():
                email = form.email.data
                password = form.password.data

                display(email, password)

                logged_user = User.query.filter(User.email == email).first()
                print(logged_user.email)
                if logged_user and check_password_hash(logged_user.password, password):
                    login_user(logged_user)
                    flash('success')
                    return redirect(url_for('site.home'))
                else:
                    flash('failed')
                    return redirect(url_for('auth.signin'))
        except:
            raise Exception('Invalid Form Data: Please Check Your Form')
#  if everything is correct and goes through it moves you to sigin
        return render_template('signin.html', form = form)
