from flask import Flask, request, redirect, render_template, session, send_file, url_for
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.binary import Binary
from bson.objectid import ObjectId
from io import BytesIO
import datetime
from encryption import encrypt_data, decrypt_data

app = Flask(__name__)
app.secret_key = 'your_secret_key'

client = MongoClient("mongodb+srv://root:root@cluster0.kyp2eal.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client['auth_demo']
users = db['users']
uploads = db['uploads']
activities = db['activities']

@app.route('/')
def root():
    if 'email' in session:
        return redirect('/dashboard')
    return redirect('/login')

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        return redirect('/login')
    
    user_email = session['email']
    
    # Calculate dashboard stats
    user_files = list(uploads.find({'email': user_email}))
    file_count = len(user_files)
    
    # Calculate total storage used
    storage_bytes = sum(len(file.get('content', b'')) for file in user_files)
    if storage_bytes < 1024:
        storage_used = f"{storage_bytes} bytes"
    elif storage_bytes < 1024 * 1024:
        storage_used = f"{storage_bytes / 1024:.1f} KB"
    else:
        storage_used = f"{storage_bytes / (1024 * 1024):.1f} MB"
    
    # Get recent activities
    recent_activities_db = list(activities.find({'email': user_email}).sort('timestamp', -1).limit(5))
    recent_activities = []
    
    for activity in recent_activities_db:
        recent_activities.append({
            'type': activity['type'],
            'description': activity['description'],
            'time': activity['timestamp'].strftime("%Y-%m-%d %H:%M")
        })
    
    # Get last activity date
    last_activity_date = "No activity yet"
    if recent_activities_db:
        last_activity_date = recent_activities_db[0]['timestamp'].strftime("%Y-%m-%d")
    
    return render_template('dashboard.html', 
                           email=user_email, 
                           file_count=file_count,
                           storage_used=storage_used,
                           last_activity_date=last_activity_date,
                           recent_activities=recent_activities)

@app.route('/files')
def home():
    if 'email' not in session:
        return redirect('/login')
    
    user_files = uploads.find({'email': session['email']})
    return render_template('home.html', email=session['email'], msg='', files=user_files)

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST':
        user = users.find_one({'email': request.form['email']})
        if user and check_password_hash(user['password'], request.form['password']):
            session['email'] = user['email']
            return redirect('/dashboard')
        msg = 'Invalid credentials.'
    return render_template('login.html', msg=msg)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    msg = ''
    if request.method == 'POST':
        if users.find_one({'email': request.form['email']}):
            msg = 'Email already registered.'
        else:
            hash_pw = generate_password_hash(request.form['password'])
            users.insert_one({'email': request.form['email'], 'password': hash_pw})
            msg = 'Signup successful. Go to login.'
    return render_template('signup.html', msg=msg)

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect('/login')

@app.route('/upload-page')
def upload_page():
    if 'email' not in session:
        return redirect('/login')
    return redirect('/files')  # Redirects to the files page which has the upload form

@app.route('/upload', methods=['POST'])
def upload():
    msg = ''
    if 'email' not in session:
        return redirect('/login')

    uploaded_file = request.files['file']
    if uploaded_file and uploaded_file.filename:
        content = uploaded_file.read()
        try:
            encrypted = encrypt_data(content)
        except ValueError:
            msg = "File too large for RSA encryption (limit ~190 bytes)."
        else:
            # Insert file
            file_id = uploads.insert_one({
                'email': session['email'],
                'filename': uploaded_file.filename,
                'content': Binary(encrypted),
                'content_type': uploaded_file.content_type,
                'upload_date': datetime.datetime.now()
            }).inserted_id
            
            # Record activity
            activities.insert_one({
                'email': session['email'],
                'type': 'upload',
                'description': f"Uploaded file: {uploaded_file.filename}",
                'file_id': file_id,
                'timestamp': datetime.datetime.now()
            })
            
            msg = 'File uploaded and encrypted successfully.'
    else:
        msg = 'No file selected.'

    user_files = uploads.find({'email': session['email']})
    return render_template('home.html', email=session['email'], msg=msg, files=user_files)

@app.route('/download/<file_id>')
def download(file_id):
    if 'email' not in session:
        return redirect('/login')

    file_doc = uploads.find_one({'_id': ObjectId(file_id), 'email': session['email']})
    if file_doc:
        # Record activity
        activities.insert_one({
            'email': session['email'],
            'type': 'download',
            'description': f"Downloaded file: {file_doc['filename']}",
            'file_id': file_doc['_id'],
            'timestamp': datetime.datetime.now()
        })
        
        decrypted = decrypt_data(file_doc['content'])
        return send_file(BytesIO(decrypted), download_name=file_doc['filename'], as_attachment=True, mimetype=file_doc['content_type'])

    return "File not found or unauthorized", 404

@app.route('/delete/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    if 'email' not in session:
        return "Unauthorized", 401

    file_doc = uploads.find_one({'_id': ObjectId(file_id), 'email': session['email']})
    if file_doc:
        filename = file_doc['filename']
        
        # Delete the file
        uploads.delete_one({'_id': ObjectId(file_id)})
        
        # Record activity
        activities.insert_one({
            'email': session['email'],
            'type': 'delete',
            'description': f"Deleted file: {filename}",
            'timestamp': datetime.datetime.now()
        })
        
        return "File deleted successfully."

    return "File not found or unauthorized", 404

if __name__ == '__main__':
    app.run(debug=True)