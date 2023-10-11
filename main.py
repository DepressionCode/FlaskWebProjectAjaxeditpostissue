from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, jsonify
from datetime import datetime
from pymysql.err import IntegrityError
from werkzeug.utils import secure_filename
import pymysql
import re
import os
import hashlib
import random
import uuid
import json
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'jfif', 'gif'}
app = Flask(__name__)

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'your secret key'
app.config["UPLOAD_FOLDER"] = "./static/Images/"
app.config['UPLOAD_FOLDER2'] = "./static/post_images/"

UPLOAD_FOLDER = app.config['UPLOAD_FOLDER']
UPLOAD_FOLDER2 = app.config['UPLOAD_FOLDER2']

if not os.path.exists(UPLOAD_FOLDER2):
    os.makedirs(UPLOAD_FOLDER2)

# Make the WSGI interface available at the top level so wfastcgi can get it.
wsgi_app = app.wsgi_app

def create_connection():
    # Connect to the database
    return pymysql.connect(host='10.0.0.17',
                                 user='johvu',
                                 password='AISLE',
                                 database='johvu',
                                 charset='utf8mb4',
                                 cursorclass=pymysql.cursors.DictCursor)


@app.route('/check_email_format', methods=['POST'])
def check_email_format():
    email = request.form['email']
    if re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify(valid=True)
    else:
        return jsonify(valid=False)


@app.route('/', methods=['GET', 'POST'])
def login():
    # Connect to the database
    with create_connection() as connection:
        # Output message if something goes wrong...
        msg = ''
        # Check if "username" and "password" POST requests exist (user submitted form)
        if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
            # Create variables for easy access
            email = request.form['email']
            password = request.form['password']
            encrypted_password = hashlib.sha256(password.encode()).hexdigest()
            # Check if account exists using MySQL
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM tblusers WHERE email = %s AND password = %s', (email, encrypted_password,))
                # Fetch one record and return result
                account = cursor.fetchone()
            # If account exists in accounts table in out database
            if account:
                # Create session data, we can access this data in other routes
                session['loggedin'] = True
                session['user_id'] = account['user_id']
                session['role_id'] = account['role_id']
                session['email'] = account['email']
                session['user_name'] = account['user_name']
                # Redirect to your_feed page
                return redirect(url_for('your_feed'))
            else:
                # Account doesnt exist or username/password incorrect
                msg = 'Incorrect email/password!'
        # Show the login form with message (if any)
        return render_template('login.html', msg=msg)


# http://localhost:5000/python/logout - this will be the logout page
@app.route('/pythonlogin/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('user_id', None)
   session.pop('user_name', None)
   # Redirect to login page
   return redirect(url_for('login'))


def is_valid_password(password):
    errors = []

    if len(password) < 8:
        errors.append('Password must be at least 8 characters long!')
    if not re.search(r'[A-Z]', password):
        errors.append('Password must have at least one capital letter!')
    if not re.search(r'[0-9]', password):
        errors.append('Password must have at least one number!')

    return errors


@app.route('/pythonlogin/register', methods=['GET', 'POST'])
def register():
    with create_connection() as connection:
        # Initialize messages
        msg = ""
        msg2 = ""
        msg3 = ""

        if request.method == 'POST' and 'user_name' in request.form and 'password' in request.form and 'email' in request.form:
            username = request.form['user_name']
            password = request.form['password']
            email = request.form['email']
            encrypted_password = hashlib.sha256(password.encode()).hexdigest()

            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM tblusers WHERE email = %s', (email,))
                account = cursor.fetchone()

                # Check for duplicate email
                if account:
                    msg = 'Cannot use the same email!'
                # Validate email format
                elif not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
                    msg2 = 'Invalid email address!'
                # Validate username format
                elif not re.match(r'^[A-Za-z0-9]+$', username):
                    msg=('Username must contain only letters and numbers!')
                else:
                    password_errors = is_valid_password(password)
                    if password_errors:
                        msg = ' & '.join(password_errors)
                    elif not username or not password or not email:
                        msg = 'Please fill out the form!'
                    else:
                        cursor.execute('INSERT INTO tblusers(`user_name`, `password`, `email`) VALUES(%s, %s, %s)', (username, encrypted_password, email))
                        connection.commit()
                        msg3 = 'You have successfully registered!'

        elif request.method == 'POST':
            msg = 'Please fill out the form!'

        return render_template('register.html', msg=msg, msg2=msg2, msg3=msg3)
    

# http://localhost:5000/pythinlogin/profile - this will be the profile page, only accessible for loggedin users
@app.route('/pythonlogin/profile')
def profile():
    # Check if user is loggedin
    if 'loggedin' in session:
        # Connect to the database
        with create_connection() as connection:
            # We need all the account info for the user so we can display it on the profile page
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM tblusers WHERE user_id = %s', (session['user_id'],))
                # Fetch one record and return result
                account = cursor.fetchone()
                if account['role_id'] == 0:
                    # Show the profile page with account info
                    return render_template('profile.html', account=account)
                elif account['role_id'] == 1:
                    cursor.execute('SELECT * FROM tblusers WHERE role_id = 1')
                    x = cursor.fetchall()
                    count_admins = len(x)
                    print(len(x))
                    cursor.execute('SELECT * FROM tblusers')
                    accounts = cursor.fetchall()
                    return render_template('admin.html', account=account, accounts=accounts, count_admins=count_admins)
                elif account['role_id'] == 2:
                    cursor.execute('SELECT * FROM tblusers')
                    accounts = cursor.fetchall()
                    return render_template('super_admin.html', account=account, accounts=accounts)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


@app.route('/pythonlogin/delete_users', methods=['GET', 'POST'])
def delete():
    user_id = request.args.get('user_id')

    # Ensure that the user is logged in and the user_id matches the logged-in user
    if 'loggedin' not in session or str(session['user_id']) != user_id:
        return "Unauthorized", 401

    # Connect to the database
    with create_connection() as connection:
        with connection.cursor() as cursor:

            if request.method == "POST":
                
                # Fetch the role of the user
                role_sql = '''
                SELECT role_id from tblusers
                WHERE user_id = %s
                '''
                cursor.execute(role_sql, (user_id,))
                role = cursor.fetchone()

                # Ensure the user is not an admin or super admin (assuming 1 is for admin and 2 for super admin)
                if role['role_id'] in [1, 2]:
                    return "You do not have permission to delete this user."

                # Your DELETE logic
                avatar = request.form['avatar']
                if avatar:
                    # Assuming the filename is the avatar name
                    image_path = os.path.join(app.config['UPLOAD_FOLDER'], avatar)

                    if os.path.exists(image_path):
                        os.remove(image_path)
                
                del_sql = '''
                DELETE FROM tblusers WHERE user_id = %s
                ''' 
                cursor.execute(del_sql, (user_id,))
                connection.commit()

                # Log out the user
                session.pop('loggedin', None)
                session.pop('user_id', None)
                session.pop('username', None)

                return redirect('/')

            # Logic for fetching the user to be deleted
            user_sql = '''
            SELECT * from tblusers
            WHERE user_id = %s
            '''
            cursor.execute(user_sql, (user_id,))
            user = cursor.fetchone()

        return render_template('delete_users.html', user=user)


def is_valid_password(password):
    errors = []
    if not any(char.isdigit() for char in password):
        errors.append("Password should contain at least one number.")
    if not any(char.isupper() for char in password):
        errors.append("Password should contain at least one capital letter.")
    if len(password) < 8:
        errors.append("Password should be at least 8 characters long.")
    return errors


@app.route('/static/Images/blank-user.jpg')
def default_image():
    return send_file('./static/Images/blank-user.jpg', mimetype='image/jpg')


@app.route('/pythonlogin/update_users', methods=['GET', 'POST'])
def update():
    user_id = request.args.get('user_id')
    error_messages = []

    # Connect to the database
    with create_connection() as connection:
        
        # Fetching existing user details first
        with connection.cursor() as cursor:
            user_sql = '''
            SELECT * from tblusers
            WHERE
            user_id = %s
            '''
            val = request.args.get('user_id')
            cursor.execute(user_sql, val)
            user = cursor.fetchone()
            
        current_password = user['password']  # Fetch the current password
        
        if request.method == "POST":
            username = request.form['user_name']
            new_password = request.form['new_password']
            email = request.form['email']

            # Handling profile avatar upload 
            if 'avatar' in request.files:
                avatar = request.files['avatar']
                if avatar:
                    dir_path = r'./static/Images/'
                    img_folder = []
                    user_w_img = []
                    number = None

                    for path in os.listdir(dir_path):
                        if os.path.isfile(os.path.join(dir_path, path)):
                            img_folder.append(path.strip('.'))
                    
                    for obj in img_folder:
                        obj = obj.split(".")
                        del obj[-1]
                        number = obj[0]
                        obj = "".join(obj)
                        user_w_img.append(obj[1:])

                    num = str(random.randint(1,9))
                    while num == str(number):
                        num = str(random.randint(1,9))
                    
                    if avatar.filename.split('.')[-1] in ALLOWED_EXTENSIONS:
                        file = num + "." + str(session['user_id'])
                        filename = os.path.join(app.config["UPLOAD_FOLDER"], "%s.%s" % (file, avatar.filename.split('.')[-1]))
                        
                        if str(session['user_id']) not in user_w_img:
                            avatar.save(filename)
                        else:
                            os.remove(dir_path + img_folder[user_w_img.index(str(session['user_id']))])
                            avatar.save(filename)

                        filename = filename.split("/")
                        filename = filename[-1]
                        with connection.cursor() as cursor:
                            cursor.execute("UPDATE tblusers SET avatar = %s WHERE user_id = %s", (filename, session['user_id']))
                    else:
                        error_messages.append('File extention is not valid! It should be in the format of .png, .jpg, .jpeg, jfif or .gif.')

            # Begin new update validation code
            # Checking for username
            if not username:
                error_messages.append('Username cannot be blank!')
            elif not re.match(r'^[A-Za-z0-9]+$', username):
                error_messages.append('Username must contain only letters and numbers!')

            # Checking for email
            if not email:
                error_messages.append('Email address cannot be blank!')
            elif not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
                error_messages.append('Invalid email address!')

            # Checking for password
            if new_password:
                password_errors = is_valid_password(new_password)
                if password_errors:
                    error_messages.extend(password_errors)
                else:
                    current_password = hashlib.sha256(new_password.encode()).hexdigest()  # Update current_password if new password is valid

            if error_messages:
                flash(' | '.join(error_messages), 'update')
            else:
                with connection.cursor() as cursor:
                    user_sql = "UPDATE tblusers SET user_name=%s, email=%s, password=%s WHERE user_id = %s"
                    cursor.execute(user_sql, (username, email, current_password, user_id))  # Use current_password here
                    connection.commit()
                    return redirect('/pythonlogin/profile')

        return render_template('update_users.html', user=user)


@app.route('/pythonlogin/make_admin',methods=['POST'])
def make_admin():
    # Connect to the database
    with create_connection() as connection:
        with connection.cursor() as cursor:
            user_id = request.form['user_id']
            if user_id and request.method=="POST":
                sql='''
                UPDATE tblusers SET role_id = 1 WHERE user_id = %s
                '''
                val= (user_id,)  # Ensure it's a tuple
                cursor.execute(sql,val)
                connection.commit()
                return redirect('/pythonlogin/profile')


@app.route('/pythonlogin/make_user',methods=['POST'])
def make_user():
    # Connect to the database
    with create_connection() as connection:
        with connection.cursor() as cursor:
            user_id = request.form['user_id']
            if user_id and request.method=="POST":
                sql='''
                UPDATE tblusers SET role_id = 0 WHERE user_id = %s
                '''
                val= (user_id,)  # Ensure it's a tuple
                cursor.execute(sql,val)
                connection.commit()
                return redirect('/pythonlogin/profile')


def format_date(date):
    if date is None:
        return None

    date_now = datetime.now()
    d = str(date)
    date_in_db = datetime.strptime(d, '%Y-%m-%d %H:%M:%S')

    # Calculate time difference
    diff = date_now - date_in_db

    # Get difference in minutes
    diff_minutes = diff.total_seconds() / 60
    if diff_minutes < 60:
        date = str(int(diff_minutes)) + " minutes ago"
    elif 60 <= diff_minutes < 60 * 24:
        # Change it to hours if difference is 60 minutes or more
        diff_hours = diff_minutes / 60
        date = str(int(diff_hours)) + " hours ago"
    elif 60 * 24 <= diff_minutes < 60 * 24 * 365:
        # Change it to days if difference is 24 hours or more
        diff_days = diff_minutes / 60 / 24
        date = str(int(diff_days)) + " days ago"
    else:
        # Change it to years if difference is 365 days or more
        diff_years = diff_minutes / 60 / 24 / 365
        date = str(int(diff_years)) + " years ago"
    return date


# http://localhost:5000/pythinlogin/your_feed - this will be the your_feed page, only accessible for loggedin users
@app.route('/pythonlogin/your_feed')
def your_feed():
    # Check if user is loggedin
    if 'loggedin' in session:

        # Get all messages and accounts from database
        with create_connection() as connection:
            with connection.cursor() as cursor:
                # Fetch posts with likes and dislikes count
                cursor.execute("""
                    SELECT
                        tblboard.*,
                        tblusers.user_name AS user_name,
                        tblusers.avatar AS user_avatar,  -- Fetching the avatar
                        COALESCE(SUM(tblpostlikes.likes), 0) as likes_count,
                        COALESCE(SUM(tblpostlikes.dislikes), 0) as dislikes_count
                    FROM
                        tblboard
                    LEFT JOIN tblusers
                        ON tblboard.user_id = tblusers.user_id
                    LEFT JOIN tblpostlikes
                        ON tblboard.board_id = tblpostlikes.board_id
                    GROUP BY
                        tblboard.board_id,
                        tblusers.user_id
                    ORDER BY tblboard.date DESC
                """)
                posts = cursor.fetchall()

                for post in posts:
                    image_data = post.get('image')  # get the image data from the post
                    try:
                        post['image'] = json.loads(image_data) if image_data else []
                    except json.JSONDecodeError:
                        post['image'] = [image_data] if image_data else []
                    cursor.execute("""
                        SELECT
                            tblcomments.comment_id,
                            tblcomments.comment,
                            tblcomments.comment_date,
                            tblcomments.comment_date_edited,
                            tblusers.user_name AS user_name,
                            tblcomments.user_id AS user_id,
                            COALESCE(SUM(tblcommentpostlikes.comment_likes), 0) as comment_likes_count,
                            COALESCE(SUM(tblcommentpostlikes.comment_dislikes), 0) as comment_dislikes_count
                        FROM
                            tblcomments
                        LEFT JOIN tblusers
                            ON tblcomments.user_id = tblusers.user_id
                        LEFT JOIN tblcommentpostlikes
                            ON tblcomments.comment_id = tblcommentpostlikes.comment_id
                        WHERE
                            tblcomments.board_id = %s
                        GROUP BY
                            tblcomments.comment_id,
                            tblusers.user_id
                    """, (post["board_id"],))
                    comments = cursor.fetchall()

                    for comment in comments:
                        # Set the can_delete flag for each comment
                        comment['can_delete'] = comment['user_id'] == session["user_id"]

                        # Format the comment's date
                        p = format_date(comment['comment_date'])
                        comment['comment_date'] = p

                        p = format_date(comment['comment_date_edited'])
                        comment['comment_date_edited'] = p

                        # Fetch likes and dislikes for comments
                        cursor.execute("""
                            SELECT
                                SUM(comment_likes) AS comment_likes_count,
                                SUM(comment_dislikes) AS comment_dislikes_count
                            FROM
                                tblcommentpostlikes
                            WHERE
                                tblcommentpostlikes.comment_id = %s
                        """, (comment["comment_id"],))
                        comment_likes_dislikes = cursor.fetchone()
                        comment["comment_likes"] = comment_likes_dislikes["comment_likes_count"] or 0
                        comment["comment_dislikes"] = comment_likes_dislikes["comment_dislikes_count"] or 0

                    post["comments"] = comments

                    # Fetch likes and dislikes for posts
                    cursor.execute("""
                        SELECT
                            SUM(likes) AS likes_count,
                            SUM(dislikes) AS dislikes_count
                        FROM
                            tblpostlikes
                        WHERE
                            tblpostlikes.board_id = %s
                    """, (post["board_id"],))
                    likes_dislikes = cursor.fetchone()
                    post["likes"] = likes_dislikes["likes_count"] or 0
                    post["dislikes"] = likes_dislikes["dislikes_count"] or 0

                    p = format_date(post['date'])
                    post['date'] = p
                    p = format_date(post['date_edited'])
                    post['date_edited'] = p

                # Fetch users
                cursor.execute("SELECT * FROM tblusers")
                accounts = cursor.fetchall()

                # Fetch the current user's data
                cursor.execute("SELECT * FROM tblusers WHERE user_id = %s", (session["user_id"],))
                user = cursor.fetchone()

        post = {}  # Initialize post as an empty dictionary

        # User is loggedin show them the your_feed page
        return render_template("your_feed.html", tblboard=posts, accounts=accounts, data=user, post=post, username=session['user_name'])
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


@app.route("/pythonlogin/your_posts", methods=["GET", "POST"])
def your_posts():
    if 'loggedin' in session:
        if request.method == "POST":
            print("POST request received")
            title = request.form["title"]
            date_now = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
            brag = request.form["brag"]
            user_id = session["user_id"]
            
            images = request.files.getlist('image')
            image_filenames = []

            # Check if the list is not empty and process images
            if len(images) > 5:
                msg5 = "You can upload a maximum of 5 images."
                flash(msg5)
                return redirect(url_for('your_posts'))

            # Check if any images are provided
            if images and images[0].filename:

                for image in images:
                    print(f"Processing image {image.filename}")
                    if image and str(image.filename.split('.')[-1]) in ALLOWED_EXTENSIONS:
                        unique_filename = str(uuid.uuid4()) + "." + image.filename.split('.')[-1]
                        image.save(os.path.join(UPLOAD_FOLDER2, unique_filename))
                        image_filenames.append(unique_filename)
                    else:
                        msg4 = 'File extension is not valid! It should be in the format of .png, .jpg, .jpeg, jfif, or .gif.'
                        flash(msg4)
                        return redirect(url_for('your_posts'))

            # Insert post into the database
            try:
                with create_connection() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute("INSERT INTO tblboard (title, date, brag, user_id, image) VALUES (%s, %s, %s, %s, %s)", (title, date_now, brag, user_id, json.dumps(image_filenames)))
                        connection.commit()
                        print("Post inserted into database")
            except Exception as e:
                print(f"Error inserting post into database: {e}")

        # Get all messages and accounts from database
        with create_connection() as connection:
            with connection.cursor() as cursor:
                # Fetch ONLY the logged-in user's posts with likes and dislikes count
                cursor.execute("""
                    SELECT
                        tblboard.*,
                        tblusers.user_name AS user_name,
                        tblusers.avatar AS user_avatar,  -- Fetching the avatar
                        COALESCE(SUM(tblpostlikes.likes), 0) as likes_count,
                        COALESCE(SUM(tblpostlikes.dislikes), 0) as dislikes_count
                    FROM
                        tblboard
                    LEFT JOIN tblusers
                        ON tblboard.user_id = tblusers.user_id
                    LEFT JOIN tblpostlikes
                        ON tblboard.board_id = tblpostlikes.board_id
                    WHERE
                        tblboard.user_id = %s  -- Filter by logged-in user's ID
                    GROUP BY
                        tblboard.board_id,
                        tblusers.user_id
                    ORDER BY tblboard.date DESC
                """, (session["user_id"],))  # Pass in the logged-in user's ID
                posts = cursor.fetchall()

                for post in posts:
                    image_data = post.get('image')  # get the image data from the post
                    try:
                        post['image'] = json.loads(image_data) if image_data else []
                    except json.JSONDecodeError:
                        post['image'] = [image_data] if image_data else []
                    cursor.execute("""
                        SELECT
                            tblcomments.comment_id,
                            tblcomments.comment,
                            tblcomments.comment_date,
                            tblcomments.comment_date_edited,
                            tblusers.user_name AS user_name,
                            tblcomments.user_id AS user_id,
                            COALESCE(SUM(tblcommentpostlikes.comment_likes), 0) as comment_likes_count,
                            COALESCE(SUM(tblcommentpostlikes.comment_dislikes), 0) as comment_dislikes_count
                        FROM
                            tblcomments
                        LEFT JOIN tblusers
                            ON tblcomments.user_id = tblusers.user_id
                        LEFT JOIN tblcommentpostlikes
                            ON tblcomments.comment_id = tblcommentpostlikes.comment_id
                        WHERE
                            tblcomments.board_id = %s
                        GROUP BY
                            tblcomments.comment_id,
                            tblusers.user_id
                    """, (post["board_id"],))
                    comments = cursor.fetchall()

                    for comment in comments:
                        # Set the can_delete flag for each comment
                        comment['can_delete'] = comment['user_id'] == session["user_id"]

                        # Format the comment's date
                        p = format_date(comment['comment_date'])
                        comment['comment_date'] = p

                        p = format_date(comment['comment_date_edited'])
                        comment['comment_date_edited'] = p

                        # Fetch likes and dislikes for comments
                        cursor.execute("""
                            SELECT
                                SUM(comment_likes) AS comment_likes_count,
                                SUM(comment_dislikes) AS comment_dislikes_count
                            FROM
                                tblcommentpostlikes
                            WHERE
                                tblcommentpostlikes.comment_id = %s
                        """, (comment["comment_id"],))
                        comment_likes_dislikes = cursor.fetchone()
                        comment["comment_likes"] = comment_likes_dislikes["comment_likes_count"] or 0
                        comment["comment_dislikes"] = comment_likes_dislikes["comment_dislikes_count"] or 0

                    post["comments"] = comments

                    # Fetch likes and dislikes for posts
                    cursor.execute("""
                        SELECT
                            SUM(likes) AS likes_count,
                            SUM(dislikes) AS dislikes_count
                        FROM
                            tblpostlikes
                        WHERE
                            tblpostlikes.board_id = %s
                    """, (post["board_id"],))
                    likes_dislikes = cursor.fetchone()
                    post["likes"] = likes_dislikes["likes_count"] or 0
                    post["dislikes"] = likes_dislikes["dislikes_count"] or 0

                    p = format_date(post['date'])
                    post['date'] = p
                    p = format_date(post['date_edited'])
                    post['date_edited'] = p

                # Fetch users
                cursor.execute("SELECT * FROM tblusers")
                accounts = cursor.fetchall()

                # Fetch the current user's data
                cursor.execute("SELECT * FROM tblusers WHERE user_id = %s", (session["user_id"],))
                user = cursor.fetchone()

        post = {}  # Initialize post as an empty dictionary

        # User is loggedin show them the your_feed page
        return render_template("your_posts.html", tblboard=posts, accounts=accounts, data=user, post=post, username=session['user_name'])
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


@app.route('/pythonlogin/edit_post', methods=['POST'])
def edit_post():
    board_id = request.form['board_id']
    date_edited = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    title = request.form['title']
    brag = request.form['brag']
    images = request.files.getlist('image')

    if not board_id or not title or not brag:
        return "Invalid input", 400

    image_filenames = []

    with create_connection() as connection:
        with connection.cursor() as cursor:
            # Before saving new images, delete the old ones
            cursor.execute("SELECT image FROM tblboard WHERE board_id = %s", (board_id,))
            result = cursor.fetchone()
            old_image_filenames = json.loads(result["image"]) if result and result["image"] else []

            for old_image_filename in old_image_filenames:
                old_image_filepath = os.path.join(app.config["UPLOAD_FOLDER2"], old_image_filename)
                if os.path.exists(old_image_filepath):
                    os.remove(old_image_filepath)

            for image in images:
                print(image)
                if str(image.filename.split('.')[-1]) in ALLOWED_EXTENSIONS:
                    unique_filename = str(uuid.uuid4()) + "." + image.filename.split('.')[-1]
                    image.save(os.path.join(app.config["UPLOAD_FOLDER2"], unique_filename))
                    image_filenames.append(unique_filename)
                else:
                    return "Invalid image format", 400

            image_filenames_string = json.dumps(image_filenames)

            cursor.execute("UPDATE tblboard SET title=%s, date_edited=%s, brag=%s, image=%s WHERE board_id=%s", (title, date_edited, brag, image_filenames_string, board_id))
            connection.commit()

            # fetch the updated post
            cursor.execute("SELECT * FROM tblboard WHERE board_id = %s", (board_id,))
            post = cursor.fetchone()
            p = format_date(post['date'])
            post['date'] = p
            p = format_date(post['date_edited'])
            post['date_edited'] = p

            # fetch the current user's account information
            cursor.execute("SELECT * FROM tblusers WHERE user_id = %s", (session['user_id'],))
            account = cursor.fetchone()

    with create_connection() as connection:
        with connection.cursor() as cursor:
            # fetch the updated tblboard data
            cursor.execute("SELECT * FROM tblboard")
            tblboard = cursor.fetchall()

    return jsonify(status="success", message="Post updated successfully", image_filenames=image_filenames)


@app.route("/pythonlogin/delete_post", methods=['POST'])
def delete_post():
    print('benis')
    board_id = request.form.get('board_id')
    print(board_id)

    # Connect to the database
    with create_connection() as connection:
        with connection.cursor() as cursor:
            # Fetch the post
            board_sql = '''
            SELECT * from tblboard
            WHERE
            board_id = %s
            '''
            cursor.execute(board_sql, (board_id,))
            post = cursor.fetchone()

            page = request.form['page']

            # Check if the post exists
            if post is None:
                print("Post not found.")
                return redirect(f'/pythonlogin/your_{page}')

            # Check if the user is allowed to delete the post
            if session['user_id'] != post['user_id'] and session['role_id'] != 1:
                print("You are not authorized to delete this post.")
                return redirect(f'/pythonlogin/your_{page}')

            if request.method == "POST":
                image_filenames = []
                # Ensure the post's image field isn't empty or None before decoding
                if post["image"]:
                    try:
                        image_filenames = json.loads(post["image"])
                    except json.JSONDecodeError:
                        print("Error decoding image data.")
                        return redirect(f'/pythonlogin/your_{page}')
                
                # Only attempt to delete image files if they exist
                if image_filenames:
                    for image_filename in image_filenames:
                        image_filepath = os.path.join(app.config["UPLOAD_FOLDER2"], image_filename)
                        if os.path.exists(image_filepath):
                            os.remove(image_filepath)

                # Delete likes/dislikes associated with the post
                del_likes_sql = '''
                DELETE FROM tblpostlikes WHERE board_id = %s
                '''
                cursor.execute(del_likes_sql, (board_id,))

                # Then, delete the post itself
                del_sql = '''
                DELETE FROM tblboard WHERE board_id = %s
                '''
                cursor.execute(del_sql, (board_id,))

                connection.commit()

                print("Post successfully deleted.",page)
                return jsonify('hello')
                #return redirect(f'/pythonlogin/your_{page}')
            
            # Fetch the current user's account information
            cursor.execute("SELECT * FROM tblusers WHERE user_id = %s", (session['user_id'],))
            account = cursor.fetchone()

            # Fetch the updated tblboard data
            cursor.execute("SELECT * FROM tblboard")
            tblboard = cursor.fetchall()

    return render_template(
        f'your_{page}.html',
        post=post,
        user_id=session['user_id'],
        role_id=session['role_id'],
        author_id=post['user_id'] if post else None,
        tblboard=tblboard
    )


@app.route("/pythonlogin/like_post", methods=["GET"])
def like_post():
    board_id = request.args.get("board_id")
    like = request.args.get("like", "false")  # default to "false" if "like" argument is not provided
    like = True if like.lower() == 'true' else False
    user_id = session["user_id"]

    if board_id is None:
        return "Invalid request: board_id is required", 400

    with create_connection() as connection:
        with connection.cursor() as cursor:
            # Check if a like or dislike already exists from this user
            cursor.execute(
                "SELECT * FROM tblpostlikes WHERE user_id = %s AND board_id = %s",
                (user_id, board_id)
            )
            existing_like = cursor.fetchone()

            if existing_like:
                if (existing_like["likes"] == 1 and like) or (existing_like["dislikes"] == 1 and not like):
                    # Remove like/dislike if the same button is clicked again
                    cursor.execute(
                        "DELETE FROM tblpostlikes WHERE user_id = %s AND board_id = %s",
                        (user_id, board_id)
                    )
                else:
                    # Update like to dislike or vice versa
                    cursor.execute(
                        "UPDATE tblpostlikes SET likes = %s, dislikes = %s WHERE user_id = %s AND board_id = %s",
                        (1 if like else 0, 0 if like else 1, user_id, board_id)
                    )
            else:
                print('interesting')
                try:
                    cursor.execute(
                        "INSERT INTO tblpostlikes (board_id, user_id, likes, dislikes) VALUES (%s, %s, %s, %s)",
                        (board_id, user_id, 1 if like else 0, 0 if like else 1)
                    )
                    print("INSERT INTO tblpostlikes (board_id, user_id, likes, dislikes) VALUES (%s, %s, %s, %s)" % (board_id, user_id, 1 if like else 0, 0 if like else 1))
                except IntegrityError:
                    cursor.execute(
                        "UPDATE tblpostlikes SET likes = %s, dislikes = %s WHERE user_id = %s AND board_id = %s",
                        (1 if like else 0, 0 if like else 1, user_id, board_id)
                    )
            
            connection.commit()

            # Fetch the updated like and dislike counts for this post
            cursor.execute("SELECT SUM(likes) as likes_count, SUM(dislikes) as dislikes_count FROM tblpostlikes WHERE board_id = %s", (board_id,))
            counts = cursor.fetchone()
        likes_count = 0 if counts["likes_count"] is None else int(counts["likes_count"])
        dislikes_count = 0 if counts["dislikes_count"] is None else int(counts["dislikes_count"])

    return jsonify({"likes": likes_count, "dislikes": dislikes_count})


@app.route('/pythonlogin/add_comment', methods=['POST'])
def add_comment():
    connection = create_connection()  # Initialize the connection variable

    try:
        comment = request.form['comment']
        comment_id = request.form.get('comment_id')
        comment_date = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
        board_id = request.form['board_id']
        user_id = session['user_id']

        with connection.cursor() as cursor:
            cursor.execute("INSERT INTO tblcomments (comment, comment_id, comment_date, board_id, user_id) VALUES (%s, %s, %s, %s, %s)", (comment, comment_id, comment_date, board_id, user_id))
            connection.commit()

            # Fetch the comment that was just inserted, along with the user's name
            cursor.execute("""
                SELECT
                    tblcomments.*,
                    tblusers.user_name AS user_name,
                    tblusers.user_id AS user_id
                FROM
                    tblcomments
                LEFT JOIN tblusers
                    ON tblcomments.user_id = tblusers.user_id
                WHERE
                    tblcomments.comment_id = %s
            """, (cursor.lastrowid,))
            new_comment = cursor.fetchone()

            # Format the new comment's date
            p = format_date(new_comment['comment_date'])
            new_comment['comment_date'] = p

        # Return the new comment as JSON
        return jsonify(new_comment)

    finally:
        if connection:
            connection.close()


@app.route('/pythonlogin/delete_comment', methods=['POST'])
def delete_comment():
    print(request.form)  # let's print the entire form data
    comment_id = request.form.get('comment_id')

    print(comment_id)

    app.logger.info(f"Received delete_comment request. comment_id: {comment_id}")

    if not comment_id:
        app.logger.error("Invalid input: comment_id is missing")
        return "Invalid input", 400

    with create_connection() as connection:
        with connection.cursor() as cursor:
            # Fetch the comment to check if it exists and get the associated board_id
            cursor.execute("SELECT * FROM tblcomments WHERE comment_id = %s", (comment_id))
            comment = cursor.fetchone()

            if not comment:
                return "Comment not found", 404

            # Check if the user is authorized to delete the comment
            if session['user_id'] != comment['user_id']:
                return "Unauthorized", 403

            # Delete the comment
            cursor.execute("DELETE FROM tblcomments WHERE comment_id = %s", (comment_id))
            connection.commit()

    return "Comment successfully deleted"


@app.route('/pythonlogin/edit_comment', methods=['POST'])
def edit_comment():
    comment_id = request.form.get('comment_id')
    comment_date_edited = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    new_comment = request.form.get('new_comment')  # Changed variable name to new_comment
    print(new_comment)

    print(comment_id)

    app.logger.info(f"Received edit_comment request. comment_id: {comment_id}, comment: {new_comment}")  # Changed variable name to new_comment

    if not comment_id or not new_comment:  # Changed variable name to new_comment
        app.logger.error("Invalid input: comment_id or comment is missing")
        return "Invalid input", 400

    with create_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("UPDATE tblcomments SET comment = %s, comment_date_edited = %s WHERE comment_id = %s", (new_comment, comment_date_edited, comment_id))
            connection.commit()

            # Fetch the updated comment
            cursor.execute("SELECT * FROM tblcomments WHERE comment_id = %s", comment_id)
            updated_comment = cursor.fetchone()

            # Format the updated comment's date
            p = format_date(updated_comment['comment_date'])
            updated_comment['comment_date'] = p

            # Format the updated comment's date
            p = format_date(updated_comment['comment_date_edited'])
            updated_comment['comment_date_edited'] = p

            cursor.execute('SELECT * FROM tblusers WHERE user_id = %s', updated_comment['user_id'])
            user = cursor.fetchone()
            updated_comment['user_id'] = user['user_name']

    return jsonify(updated_comment)


@app.route("/pythonlogin/like_comment", methods=["GET"])
def like_comment():
    comment_id = request.args.get("comment_id")
    comment_like = request.args.get("comment_like", "false")  # default to "false" if "like" argument is not provided
    comment_like = True if comment_like.lower() == 'true' else False
    user_id = session["user_id"]

    print(f"comment_id: '{comment_id}'")

    if comment_id is None:
        return "Invalid request: comment_id is required", 400

    with create_connection() as connection:
        with connection.cursor() as cursor:
            # Check if a like or dislike already exists from this user
            cursor.execute(
                "SELECT * FROM tblcommentpostlikes WHERE user_id = %s AND comment_id = %s",
                (user_id, comment_id)
            )
            comment_existing_like = cursor.fetchone()

            if comment_existing_like:
                if (comment_existing_like["comment_likes"] == 1 and comment_like) or (comment_existing_like["comment_dislikes"] == 1 and not comment_like):
                    # Remove like/dislike if the same button is clicked again
                    cursor.execute(
                        "DELETE FROM tblcommentpostlikes WHERE user_id = %s AND comment_id = %s",
                        (user_id, comment_id)
                    )
                else:
                    # Update like to dislike or vice versa
                    cursor.execute(
                        "UPDATE tblcommentpostlikes SET comment_likes = %s, comment_dislikes = %s WHERE user_id = %s AND comment_id = %s",
                        (1 if comment_like else 0, 0 if comment_like else 1, user_id, comment_id)
                    )
            else:
                print('interesting')
                try:
                    cursor.execute(
                        "INSERT INTO tblcommentpostlikes (comment_id, user_id, comment_likes, comment_dislikes) VALUES (%s, %s, %s, %s)",
                        (comment_id, user_id, 1 if comment_like else 0, 0 if comment_like else 1)
                    )
                    print("INSERT INTO tblcommentpostlikes (comment_id, user_id, comment_likes, comment_dislikes) VALUES (%s, %s, %s, %s)" % (comment_id, user_id, 1 if comment_like else 0, 0 if comment_like else 1))
                except IntegrityError:
                    cursor.execute(
                        "UPDATE tblcommentpostlikes SET comment_likes = %s, comment_dislikes = %s WHERE user_id = %s AND comment_id = %s",
                        (1 if comment_like else 0, 0 if comment_like else 1, user_id, comment_id)
                    )
            
            connection.commit()

            # Fetch the updated like and dislike counts for this comment
            cursor.execute("SELECT SUM(comment_likes) as comment_likes_count, SUM(comment_dislikes) as comment_dislikes_count FROM tblcommentpostlikes WHERE comment_id = %s", (comment_id,))
            counts = cursor.fetchone()
        comment_likes_count = 0 if counts["comment_likes_count"] is None else int(counts["comment_likes_count"])
        comment_dislikes_count = 0 if counts["comment_dislikes_count"] is None else int(counts["comment_dislikes_count"])

    return jsonify({"comment_likes": comment_likes_count, "comment_dislikes": comment_dislikes_count})


if __name__ == '__main__':
    import os
    HOST = os.environ.get('SERVER_HOST', 'localhost')
    try:
        PORT = int(os.environ.get('SERVER_PORT', '5555'))
    except ValueError:
        PORT = 5555
    app.run(HOST, PORT,debug=False)