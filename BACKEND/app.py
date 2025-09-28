from flask import Flask, redirect, session, url_for, render_template, request, flash, send_file, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
from datetime import datetime, timedelta, timezone
from pymongo import MongoClient
from bson import ObjectId
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import json
from bson import json_util
from io import BytesIO
import os
import paypalrestsdk



# Initialize Flask app
app = Flask(__name__)

# Generate a random secret key for session security
app.secret_key = os.urandom(16) 

load_dotenv()  # Loads environment variables from a .env file

# MongoDB connection setup
client = MongoClient(os.getenv('MONGODB_URL'))  # Connect to MongoDB using the URL from environment variable
db = client.passbox  # Reference to the 'passbox' database

PAYPAL_CLIENT_ID = os.getenv('PAYPAL_CLIENT_ID')
PAYPAL_SECRET = os.getenv('PAYPAL_SECRET')
PAYPAL_MODE = "sandbox"  

paypalrestsdk.configure({
    "mode": PAYPAL_MODE,
    "client_id": PAYPAL_CLIENT_ID,
    "client_secret": PAYPAL_SECRET
})


# Set the duration of the session to 15 minutes
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

# Function to check if a user is logged in by verifying the session
def is_logged_in():
    return 'user_id' in session  # Returns True if 'user_id' exists in session

# Redirects user to login or home based on session.
@app.route('/')
def homepage():
    if is_logged_in():
        session.permanent = True
        return redirect(url_for('home')) 
    return redirect(url_for('login'))



# Handle user registration. Collects username, email, and password; hashes password, and stores in DB.
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':  # Handle form submission
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        password_confirm = request.form['password_confirm']
        
         # Hash the password before saving it
        password_hash = generate_password_hash(password) 

        # Check if the username or email already exist in the database
        if db.users.find_one({"username": username}):
            flash('Username already taken!', 'danger')  # Display flash message if username is already in use
            return redirect(url_for('register'))
        
        if db.users.find_one({"email": email}):
            flash('Email already taken!', 'danger')
            return redirect(url_for('register'))
        
        if password != password_confirm:
            flash('Error: the two passwords do not match.', 'danger')
            return redirect(url_for('register'))
        
        salt = os.urandom(16)  # Generate a 16-byte random salt
        enc_psw = derive_key_from_password(password, salt)  # Encrypt password using derived key

        # Generate a random secret for 2FA (Two-Factor Authentication)
        secret = pyotp.random_base32()  # Random base32 secret
        encrypted_seed = Fernet(enc_psw).encrypt(secret.encode())  # Encrypt the 2FA seed with the encrypted password

        # Insert the user into the database, storing encrypted data
        db.users.insert_one({
            'username': username,
            'email': email,
            'password': password_hash,
            '2fa_seed': encrypted_seed.decode(),
            'salt': salt.hex(),  # Save the salt for future use
            'data_key': enc_psw.decode()
        })
        
        user = db.users.find_one({'username': username})
        session['user_id'] = str(user['_id'])  # Store the user ID in the session
        
        return redirect(url_for('confirm_2fa'))

    return render_template('register.html')  # Render the registration page if GET request



# Handle 2FA confirmation. Generates and displays QR code for 2FA setup.
@app.route('/confirm_2fa', methods=['GET', 'POST'])
def confirm_2fa():
    if not is_logged_in():
        flash('Session expired!', 'danger')  # Show an error message if the session has expired
        return redirect(url_for('login'))  # Redirect to login page if session is expired

    user_id = session.get('user_id')  # Get the user ID from the session
    user = db.users.find_one({'_id': ObjectId(user_id)})
    
    seed = Fernet(user['data_key'].encode()).decrypt(user['2fa_seed'].encode()).decode()  # Decrypt the 2FA seed
    totp = pyotp.TOTP(seed)  # Create a TOTP (Time-based One-Time Password) object
    
    qr_url = totp.provisioning_uri(name=user['username'], issuer_name="Passbox")  # Generate the QR code URL

    # Get the 2FA code from the user input
    if request.method == 'POST':
        code = request.form['code']  

        if totp.verify(code):  # Verify if the provided 2FA code is correct
            return redirect(url_for('login'))  # Redirect to the login page
        else:
           flash('Error: code incorrect or expired', 'danger') 

    return render_template('confirm_2fa.html', qr_url=qr_url)  # Render the 2FA confirmation page with the QR code URL



# Handle user login. Verifies credentials and redirects to 2FA verification if successful.
@app.route('/login', methods=['POST', 'GET'])
def login():
    if is_logged_in():
        flash('You are already logged in!')  # Display a message if the user is already logged in
        return redirect(url_for('home'))  # Redirect to home page

    if request.method == 'POST':  # Handle the login form submission
        username = request.form['username']
        password = request.form['password']

        user = db.users.find_one({"username": username})  # Find the user in the database

        if user and check_password_hash(user['password'], password):  # Verify the password
            session['user_id'] = str(user['_id'])  # Store the user ID in the session
            return redirect(url_for('verify_2fa'))
        else:
            flash('Incorrect username or password!', 'danger')  

    return render_template('login.html')



# Handle the 2FA verification. Verifies the code entered by the user
@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if not is_logged_in():
        flash('Session expired!', 'danger')
        return redirect(url_for('login'))  

    user_id = session.get('user_id')
    user = db.users.find_one({'_id': ObjectId(user_id)})

    # Get the 2FA code from the user input
    if request.method == 'POST':
        code = request.form['code']  
        
        encrypted_seed = user['2fa_seed']  # Extract the encrypted 2FA seed

        seed = Fernet(user['data_key'].encode()).decrypt(encrypted_seed.encode()).decode()  # Decrypt the 2FA seed
        totp = pyotp.TOTP(seed)  # Create a TOTP object using the decrypted seed

        if totp.verify(code):
            return redirect(url_for('home'))
        else:
           flash('Error: code incorrect or expired') 

    return render_template('verify_2fa.html')



# Derives a cryptographic key from the given password and salt using PBKDF2
def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Hash algorithm for key derivation
        length=32,  # Length of the derived key
        salt=salt,  # The salt used for key derivation
        iterations=100000,  # Number of iterations for the key derivation
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))  # Derive the key and encode it
    return key



# Handle the home page route. If not logged in, redirects to login.
@app.route('/home', methods=['GET', 'POST'])
def home():
    if not is_logged_in():
        flash('Session expired!', 'danger')
        return redirect(url_for('login'))

    user_id = session.get('user_id')  # Get the user ID from the session
    user = db.users.find_one({'_id': ObjectId(user_id)})  # Fetch user data from the database
    
    return render_template('home.html', user=user)  # Render the home page with user data



# Handle the vaults list route. Displays user collections.
@app.route('/vaults_list', methods=['GET', 'POST'])
def vaults_list():
    if not is_logged_in():
        flash('Session expired!', 'danger')
        return redirect(url_for('login'))
    
    user_id = session.get('user_id')
    user = db.users.find_one({'_id': ObjectId(user_id)})
    username=user['username']
    # Get the user-specific password databases
    collections = db.list_collection_names()  # Get all collection names
    user_collections = [col for col in collections if user_id in col]  # Filter collections by user ID
    username = user['username']  # Get the username

    return render_template('vaults_list.html', username=username, user_collections=user_collections)  # Render the vaults_list page


# Handle collection deletion. Ensures the user owns the collection.
@app.route('/delete_collection/<collection_name>', methods=['POST', 'GET'])
def delete_collection(collection_name):

    # Verify that the collection belongs to the current user
    user_id = session.get('user_id') 
    user = db.users.find_one({'_id': ObjectId(user_id)}) 
    
    if user_id not in collection_name:  # Check if the collection belongs to the user
        return redirect(url_for('vaults_list'))  # Redirect to the vaults_list page

    # Delete the collection from the database
    try:
        db.drop_collection(collection_name)  # Drop the collection from the database
    except Exception as e:
        return redirect(url_for('vaults_list'))

    return redirect(url_for('vaults_list'))  # Redirect back to the vaults_list



# Decrypts and returns data to the frontend for a given encrypted field.
@app.route('/data', methods=['POST'])
def handle_data():
    user_id = session.get('user_id')  # Get the user ID from the session
    user = db.users.find_one({'_id': ObjectId(user_id)})  # Fetch user data from the database

    data = request.get_json()  # Get the JSON data from the client

    # Decrypt the encrypted field using the user's key
    decrypted_field = Fernet(user['data_key'].encode()).decrypt(data['encrypted_field'].encode()).decode()  # Decrypt password
    return jsonify({'success': True, 'decrypted_field': decrypted_field})  # Return decrypted data



# Displays the contents of a collection with optional search filters.
@app.route('/vault_view/<collection_name>', methods=['GET', 'POST'])
def vault_view(collection_name):
    if not is_logged_in():
        flash('Session expired!', 'danger')
        return redirect(url_for('login'))
    
    if collection_name not in db.list_collection_names():  # Check if the collection is valid
        return redirect(url_for('vaults_list'))  # Redirect to vaults_list page

    # Get query parameters for filtering the collection
    title = request.args.get('title', '')
    username = request.args.get('username', '')
    email = request.args.get('email', '')
    category = request.args.get('category', '')

    # Build the MongoDB query based on filters
    query = {}
    # Case-insensitive searches
    if title:
        query['title'] = {'$regex': title, '$options': 'i'}  
    if username:
        query['username'] = {'$regex': username, '$options': 'i'} 
    if email:
        query['email'] = {'$regex': email, '$options': 'i'}
    if category:
        query['category'] = {'$regex': category, '$options': 'i'}

    credentials = list(db[collection_name].find())  # Fetch all credentials in the collection
    credentials_count = len(credentials)  # Count the number of credentials

    return render_template('vault_view.html', collection_name=collection_name, credentials=credentials, credentials_count=credentials_count)


# Generates an OTP using TOTP and returns it along with a provisioning URL (for seed field in vault_view.html).
@app.route('/generate_otp', methods=['POST'])
def generate_otp():
    try:
        data = request.get_json()  # Get the JSON data from the client
        if not data or 'seed' not in data or 'cred_id' not in data or 'coll_name' not in data:
            return jsonify({"error": "Data not provided"}), 400  # Check if the necessary data is provided

        seed = data['seed']  # Get the seed for OTP generation
        collection_name = data['coll_name']  # Get the collection name
        cred_id = data['cred_id']  # Get the credential ID

        if not seed:
            return jsonify({"error": "Invalid Seed!"}), 400  # Handle missing or invalid seed

        user_id = session.get('user_id')
        cred = db[collection_name].find_one({'_id': ObjectId(cred_id)})  # Find the credential by ID
        user = db.users.find_one({'_id': ObjectId(user_id)}) 

        if not user or 'data_key' not in user:
            return jsonify({"error": "User key not found"}), 404  # Handle missing user key

        totp = pyotp.TOTP(seed)  # Create a TOTP object using the seed
        otp = totp.now()  # Generate the OTP
        time_remaining = totp.interval - (int(datetime.now().timestamp()) % totp.interval)  # Calculate time remaining
        qr_url = totp.provisioning_uri(name=f"{cred['username']}", issuer_name="Passbox")  # Generate QR code URL

        # Encrypt the seed and update the database
        encrypted_seed = Fernet(user['data_key'].encode()).encrypt(seed.encode())  # Encrypt the seed
        db[collection_name].update_one(
            {'_id': ObjectId(cred_id)},
            {'$set': {'2fa_seed': encrypted_seed.decode()}}  # Update the credential with the encrypted seed
        )

        return jsonify({
            "otp": otp,
            "time_remaining": time_remaining,
            "qr_url": qr_url
        })  # Return OTP, remaining time, and QR URL

    except Exception as e:
        app.logger.error(f"Error in generating OTP: {e}")  # Log error if OTP generation fails
        return jsonify({"error": "Error in generating the OTP. Please try again."}), 500  # Return error message



# Modify the details of a credential in a MongoDB collection.
@app.route('/modify_credential/<collection_name>/<cred_id>', methods=['GET', 'POST'])
def modify_credential(collection_name, cred_id):
    
    user_id = session.get('user_id')  
    user = db.users.find_one({'_id': ObjectId(user_id)})

    # Retrieve the credential
    credentials = db[collection_name].find_one({'_id': ObjectId(cred_id)})
    if not credentials:
        return redirect(url_for('vault_view', collection_name=collection_name)) 

    if request.method == 'POST':  # Handle form submission for credential modification
        title = request.form.get('title')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        url = request.form.get('url')
        category = request.form.get('category')
        seed = request.form.get('2fa_seed')
        psw_due_date = request.form.get('psw_due_date')

        # Encrypt password or update fields based on form input
        if(seed):
            encrypted_seed = Fernet(user['data_key'].encode()).encrypt(seed.encode())  # Encrypt the 2FA seed
            db[collection_name].update_one(
                {'_id': ObjectId(cred_id)},
                {'$set': {
                    '2fa_seed': encrypted_seed.decode()  # Update the seed in the database
                }}
            )
        elif(psw_due_date):
            db[collection_name].update_one(
                {'_id': ObjectId(cred_id)},
                {'$set': {
                    'psw_due_date': psw_due_date  # Update the password due date
                }}
            )
        elif not any([psw_due_date, title, username, email, password, url, category]):
            db[collection_name].update_one(
                {'_id': ObjectId(cred_id)},
                {'$set': {
                    'psw_due_date': None  # Update the password due date
                }}
            )
        elif(title or username or email or password or url or category) :
            # Encrypt the password and update the credential
            encrypted_password = Fernet(user['data_key'].encode()).encrypt(password.encode())  # Encrypt password
            db[collection_name].update_one(
                {'_id': ObjectId(cred_id)},
                {'$set': {
                    'title': title,
                    'username': username,
                    'email': email,
                    'password': encrypted_password.decode(),  # Store the encrypted password as a string
                    'url': url,
                    'category': category
                }}
            )

    return redirect(url_for('vault_view', collection_name=collection_name))



# Allow  user to add new credentials to a specific collection in the database.
@app.route('/add_credentials/<collection_name>', methods=['GET', 'POST'])
def add_credentials(collection_name):

    user_id = session.get('user_id')
    user = db.users.find_one({'_id': ObjectId(user_id)})

    if request.method == 'POST':
        # Gather data from form fields
        title = request.form['title']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        url = request.form['url']
        category = request.form['category']

        # Encrypt the password
        encrypted_password = Fernet(user['data_key'].encode()).encrypt(password.encode())

        # Set a default seed and encrypt it
        seed = "no_seed"
        encrypted_seed = Fernet(user['data_key'].encode()).encrypt(seed.encode())

        # Check if the title is already in use
        if db[collection_name].find_one({'title': title}):
            flash('Error:  name already exists in this vault.')
            return redirect(url_for('vault_view', collection_name=collection_name))

        # Insert the new credential into the collection
        db[collection_name].insert_one({
            'title': title,
            'username': username,
            'email': email,
            'password': encrypted_password.decode(),  # Save the encrypted password as a string
            'url': url,
            'category': category,
            '2fa_seed': encrypted_seed.decode(),
            'psw_due_date': None
        })

    return redirect(url_for('vault_view', collection_name=collection_name))



@app.route('/delete_credential/<collection_name>/<cred_id>', methods=['GET', 'POST'])
def delete_credential(collection_name, cred_id):

    cred = db[collection_name].find_one({'_id': ObjectId(cred_id)})
    
    try:
        db[collection_name].delete_one({'_id': ObjectId(cred_id)})
    
    except Exception as e:
        return redirect(url_for('vault_view', collection_name=collection_name))

    return redirect(url_for('vault_view', collection_name=collection_name))




# Allow the user to export data from a collection. The data is encrypted using a password before being sent as a file.
@app.route('/export_collection/<collection_name>', methods=['POST'])
def export_collection(collection_name):

    # Retrieves the password provided by the user for encryption.
    user_password = request.form.get('export_password')

    if not user_password:
        return redirect(url_for('vaults_list'))
    
    user_id = session.get('user_id')
    user = db.users.find_one({'_id': ObjectId(user_id)})
    salt = user['salt']
    salt_bytes = bytes.fromhex(salt)

    data = list(db[collection_name].find())

    export_data = []
    for item in data:
        temp_item = item.copy()

        if 'password' in temp_item:
            # Decrypts passwords and account 2fa seed from the collection before exporting them.
            decrypted_password = Fernet(user['data_key'].encode()).decrypt(temp_item['password'].encode()).decode()
            decrypted_seed = Fernet(user['data_key'].encode()).decrypt(temp_item['2fa_seed'].encode()).decode()
            temp_item['password'] = decrypted_password
            temp_item['2fa_seed'] = decrypted_seed
        
        export_data.append(temp_item)
    
    # Encrypts the data and sends it as a downloadable file.
    file_key = derive_key_from_password(user_password, salt_bytes)
    json_data = json.dumps(export_data, default=json_util.default)
    encrypted_data = Fernet(file_key).encrypt(json_data.encode())
    
    file_io = BytesIO(encrypted_data)
    file_io.seek(0)

    return send_file(file_io, as_attachment=True, download_name=f"{collection_name.split('_')[1]}_salt-{salt}_backup.json", mimetype='application/octet-stream')



# Handle both creating a new collection or importing an existing collection.
@app.route('/create_or_import_collection', methods=['GET', 'POST'])
def create_or_import_collection():

    user_id = session.get('user_id')  # Ottieni l'ID dell'utente dalla sessione
    user = db.users.find_one({'_id': ObjectId(user_id)})
    salt=user['salt']
    salt_bytes = bytes.fromhex(salt)

    if request.method == 'POST':
        collection_name = request.form['collection_name']
        collection_password = request.form['collection_password']
        action = request.form['action']
        
        # Checks whether the collection already exists by also considering the user ID
        user_collection_name = f"{user_id}_{collection_name}"
        if user_collection_name in db.list_collection_names():
            flash('Error:  name of the vault already exists.', 'danger')
            return redirect(url_for('create_or_import_collection'))
        
        # Creating collection
        if action == 'create':
            # Creating the mongodb collection with an empty json document
            db.create_collection(user_collection_name) 
            return redirect(url_for('vaults_list'))

        # For importing, it decrypts the file, processes the data, and inserts it into the database.
        elif action == 'import':
            import_file = request.files.get('import_file')
 
            if not import_file:
                print("File not loaded correctly")
                return redirect(url_for('create_or_import_collection'))
            
            try:
                # derive key from user_password and try to decrypt file
                file_key=derive_key_from_password(collection_password, salt_bytes)
                encrypted_data = import_file.read()
                decrypted_data = Fernet(file_key).decrypt(encrypted_data).decode()
                collection_data = json.loads(decrypted_data, object_hook=json_util.object_hook)
                
                # Check if the collection already exists
                user_collection_name = f"{user_id}_{collection_name}"
                if user_collection_name in db.list_collection_names():
                    return redirect(url_for('create_or_import_collection'))
            
                import_data = []
                for item in collection_data:
                    temp_item = item.copy()
                    
                    if 'password' in temp_item:
                        # recrypt password and account 2fa seed before reinserting it into mongodb
                        encrypted_password = Fernet(user['data_key'].encode()).encrypt(temp_item['password'].encode())
                        encrypted_seed = Fernet(user['data_key'].encode()).encrypt(temp_item['2fa_seed'].encode())
                        temp_item['password'] = encrypted_password.decode()
                        temp_item['2fa_seed'] = encrypted_seed.decode()
    
                    # Add the modified version to the list
                    import_data.append(temp_item)

                # If the data is a list of documents, it is inserted with insert_many
                if isinstance(collection_data, list):
                    db[user_collection_name].insert_many(import_data)
                else:
                    # Otherwise, an individual document is entered
                    db[user_collection_name].insert_one(import_data)
                
                return redirect(url_for('vaults_list'))
            
            except Exception as e:
                print(f"Error during decryption: {e}")
                flash('Error:  password is wrong or file comes up empty.', 'danger')
                return redirect(url_for('create_or_import_collection'))

    return redirect(url_for('vaults_list'))



# Allow ows the user to make a PayPal donation to the project
@app.route('/donate', methods=['POST'])
def donate():
    amount = request.form.get('amount') # Gather donation amount from form fields

    
    # Create a PayPal payment with the specified amount and redirect the user to the PayPal approval page.
    payment = paypalrestsdk.Payment({
        "intent": "sale",
        "payer": {
            "payment_method": "paypal"
        },
        "redirect_urls": {
            "return_url": url_for('execute_payment', _external=True),
            "cancel_url": url_for('cancel_payment', _external=True)
        },
        "transactions": [{
            "amount": {
                "total": amount,
                "currency": "USD"
            },
            "description": "Donation for the project"
        }]
    })
    if payment.create():
        for link in payment.links:
            if link.rel == "approval_url":
                approval_url = link.href
                return redirect(approval_url)
    else:
        flash('Error in creating payment')
        return redirect(url_for('home'))

#Handle the execution of the PayPal payment after the user approves it.
@app.route('/payment/execute', methods=['GET'])
def execute_payment():
    payment_id = request.args.get('paymentId')
    payer_id = request.args.get('PayerID')

    payment = paypalrestsdk.Payment.find(payment_id)

    if payment.execute({"payer_id": payer_id}):
        return redirect(url_for('vaults_list'))
    else:
        return redirect(url_for('vaults_list'))

# Notice to user the payment cancellation and redirect to the homepage
@app.route('/payment/cancel', methods=['GET'])
def cancel_payment():
    flash('Error:  Payment cancelled')
    return redirect(url_for('home'))



# Allow users to submit feedback
@app.route('/submit-feedback', methods=['POST', 'GET'])
def submit_feedback():

    user_id = session.get('user_id')
    user = db.users.find_one({'_id': ObjectId(user_id)})
    username = user['username']

    feedback_message = request.form.get('feedback')  # get user feedback from frontend

    # Validate the feedback is not empty or too long.
    if not feedback_message or len(feedback_message) > 500:
        return redirect(url_for('home'))
    
    # Check if the user has submitted feedback in the last 30 days
    if not can_submit_feedback(user_id):
        return redirect(url_for('home'))

    # Save the feedback to the database.
    feedback_document = {
        "user_id": user_id,
        "message": feedback_message,
        "timestamp": datetime.now(timezone.utc) 
    }
     
    db.feedbacks.insert_one(feedback_document)

    return redirect(url_for('home'))

# Check if the user has submitted feedback in the last 30 days
def can_submit_feedback(id):

    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    recent_feedback = db.feedbacks.find_one({
        "user_id": id,
        "timestamp": {"$gte": thirty_days_ago}
    })
    return recent_feedback is None



#Allow users to view and update their profile information.
@app.route('/profile', methods=['GET', 'POST'])
def profile():

    user_id = session.get('user_id')
    user = db.users.find_one({'_id': ObjectId(user_id)})

    if not user:
        return jsonify({'error': 'Utente non trovato'}), 404

    # Allow user  changing username, email or password.
    if request.method == 'POST':
        new_username = request.form.get('username')
        new_email = request.form.get('email')
        new_password = request.form.get('password')

        # Check new username
        if not user['username'] and db.users.find_one({"username": new_username}):
            flash('Username already taken!', 'danger')
            return redirect(url_for('profile'))
        if new_username:
            db.users.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {'username': new_username}}
            )

        # Check new email
        if not user['email'] and db.users.find_one({"email": new_email}):
            flash('Email already taken!', 'danger')
            return redirect(url_for('profile'))
        if new_email:
            db.users.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {'email': new_email}}
            )

        # changing password
        if new_password:
            change_password(new_password)
        else:
            redirect(url_for('profile'))
    
    flash('The data has been updated. The changes will be active from the next login.', 'success')

    return redirect(url_for('home'))

# This function handles password changes for the user and all credentials in the database.
def change_password(new_password):

    user_id = session.get('user_id')
    user = db.users.find_one({'_id': ObjectId(user_id)})
    salt=user['salt']
    login_psw=session.get('password')


    if new_password=="":
        db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': { 
                'password': user['password']
            }}
        )
        new_password=login_psw
        return new_password
    
    new_enc_password = derive_key_from_password(new_password, salt.encode())

    # Iterates over all collections and updates the password encryption for each user credentials.
    for collection_name in db.list_collection_names():
        if session['user_id'] in collection_name:
            collection = db[collection_name]
        
            # Update all mongodb documents
            for document in collection.find():
                decrypted_password = Fernet(user['data_key'].encode()).decrypt(document['password'].encode()).decode()
                decrypted_cred_seed = Fernet(user['data_key'].encode()).decrypt(document['2fa_seed'].encode()).decode()

                encrypted_new_password = Fernet(new_enc_password).encrypt(decrypted_password.encode())
                encrypted_new_cred_seed = Fernet(new_enc_password).encrypt(decrypted_cred_seed.encode())

                collection.update_one(
                    {'_id': document['_id']},  # Search by id
                    {'$set': {
                        'password': encrypted_new_password.decode(),
                        '2fa_seed': encrypted_new_cred_seed.decode()
                    }} 
                )
    
    # Updating the 2fa seed of the user login
    decrypted_seed = Fernet(user['data_key'].encode()).decrypt(user['2fa_seed'].encode()).decode()
    encrypted_seed = Fernet(new_enc_password).encrypt(decrypted_seed.encode())

    # Hash the new user password before saving it
    new_password_hash = generate_password_hash(new_password)

    db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': { 
            'password': new_password_hash,
            '2fa_seed': encrypted_seed.decode(),
            'data_key': new_enc_password.decode()
        }}
    )

    return new_password_hash




@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
