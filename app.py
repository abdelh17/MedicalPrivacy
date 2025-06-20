import os
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session

from auth import authenticate_user, register_user, get_user_role
from db import setup_db, get_db
from medical_data import write_to_chart, read_chart, read_access_logs

app = Flask(__name__)
app.secret_key = os.urandom(24)  # sign session cookies to prevent tampering. needed to access session information

## Helper ##
# makes sure that the user is logged in before accessing certain routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function

## Routes ##
@app.route('/')
def index():
    if 'user_email' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if authenticate_user(email, password):
            session['user_email'] = email
            session['user_role'] = get_user_role(email)  # store user email and role in session
            flash('Login successful!', 'success')  # success message
            return redirect(url_for('dashboard'))  # redirect to dashboard if login is successful
        else:
            flash('Invalid email or password', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        success, message = register_user(email, password, role)
        if success:
            flash(message, 'success')
            return redirect(url_for('login'))
        else:
            flash(message, 'error')

    return render_template('register.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html',
                           user_email=session['user_email'],
                           user_role=session['user_role'])


@app.route('/write_note', methods=['GET', 'POST'])
@login_required
def write_note_route():
    if session['user_role'] != 'doctor':
        flash('Access denied. Only doctors can write to charts.', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        patient_email = request.form['patient_email']
        content = request.form['content']

        success, message = write_to_chart(session['user_email'], patient_email, content)
        flash(message, 'success' if success else 'error')
        return redirect(url_for('dashboard'))

    return render_template('write_note.html')


@app.route('/view_chart', methods=['GET', 'POST'])
@login_required
def view_chart():
    if request.method == 'POST':
        password = request.form['password']
        patient_email = request.form.get('patient_email') if session[
                                                                 'user_role'] != 'patient' else None  # needed if the user is a doctor

        chart_data = read_chart(session['user_email'], password, patient_email)
        return render_template('view_chart.html', chart_data=chart_data)

    return render_template('view_chart_form.html', user_role=session['user_role'])


@app.route('/access_logs', methods=['GET', 'POST'])
@login_required
def access_logs():
    if session['user_role'] not in ['patient', 'hospital']:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        if session['user_role'] == 'patient':
            patient_email = session['user_email']
        else:
            patient_email = request.form['patient_email']

        logs = read_access_logs(patient_email, session['user_email'])
        return render_template('access_logs.html', logs=logs, patient_email=patient_email)

    return render_template('access_logs_form.html', user_role=session['user_role'])


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

## Initialization ##
if __name__ == '__main__':
    setup_db()
    conn = get_db()
    cursor = conn.cursor()
    if not cursor.execute("SELECT email FROM users WHERE email='hospital@system.com'").fetchone():
        register_user("hospital@system.com", "adminpass", "hospital")
    conn.close()
    app.run(debug=True)
