from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo import MongoClient, DESCENDING
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import os
import requests
import json
import re
from flask_mail import Mail, Message
import pytz
from markupsafe import Markup
from functools import wraps
from dotenv import load_dotenv
import secrets
import logging
from apscheduler.schedulers.background import BackgroundScheduler

# Load environment variables from .env file if it exists
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
app.config['OPENROUTER_API_KEY'] = os.environ.get('OPENROUTER_API_KEY')

# Email configuration - Use environment variables for sensitive information
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'petitionsystem123@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'petitionsystem123@gmail.com')

# MongoDB setup - Use environment variables for connection details
mongo_uri = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/petition')
client = MongoClient(mongo_uri)
db = client.get_database()

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Initialize extensions
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'

mail = Mail(app)

# IST timezone 
ist_tz = pytz.timezone('Asia/Kolkata')

# Helper functions
def get_current_ist():
    return datetime.now(ist_tz)

def format_ist_date(dt):
    if dt:
        if dt.tzinfo is None:
            dt = pytz.UTC.localize(dt).astimezone(ist_tz)
        return dt.strftime('%d-%m-%Y %H:%M')
    return ""

def requires_roles(*roles):
    """Decorator to restrict access to specific roles"""
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                flash("You don't have permission to access this page.", "danger")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return wrapped
    return wrapper

def get_department_id(name):
    """Get department ID or create if not exists"""
    department = db.departments.find_one({"name": name})
    if not department:
        result = db.departments.insert_one({
            "name": name,
            "description": f"Department of {name}",
            "keywords": generate_department_keywords(name)
        })
        return result.inserted_id
    return department['_id']

def generate_department_keywords(department_name):
    """Generate keywords for a department using AI"""
    api_key = app.config['OPENROUTER_API_KEY']
    if not api_key:
        logger.warning("OPENROUTER_API_KEY not set, using default keywords")
        return default_department_keywords(department_name)
        
    try:
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "qwen/qwq-32b:free",
                "messages": [
                    {"role": "system", "content": "You are an AI that generates keywords for government departments."},
                    {"role": "user", "content": f"Generate 5-10 keywords related to the '{department_name}' department as a comma-separated list without explanations."}
                ]
            },
            timeout=10  # Add timeout to prevent hanging
        )
        if response.status_code == 200:
            content = response.json()["choices"][0]["message"]["content"]
            # Extract and clean keywords
            keywords = [k.strip().lower() for k in content.split(',')]
            return keywords[:10]  # Limit to 10 keywords max
    except Exception as e:
        logger.error(f"Error generating keywords: {e}")
    
    return default_department_keywords(department_name)

def default_department_keywords(department_name):
    """Fallback keywords if AI service fails"""
    default_keywords = {
        "Education": ["school", "education", "student", "teacher", "curriculum"],
        "Health": ["health", "hospital", "doctor", "healthcare", "medical"],
        "Infrastructure": ["road", "bridge", "pavement", "construction", "infrastructure"],
        "Environment": ["pollution", "waste", "climate", "environment", "conservation"],
        "Public Safety": ["police", "crime", "safety", "emergency", "security"],
        "Housing": ["housing", "home", "rent", "shelter", "eviction"],
        "Social Welfare": ["welfare", "benefit", "aid", "support", "assistance"],
        "Transportation": ["transport", "bus", "train", "commuting", "traffic"],
        "General": ["general", "information", "service", "government", "public"]
    }
    return default_keywords.get(department_name, ["general", "service", "public"])

def extract_text_from_file(file_path):
    """Extract text from uploaded files based on file type"""
    file_ext = file_path.rsplit(".", 1)[-1].lower()
    
    try:
        # Text files
        if file_ext == "txt":
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()
        
        # PDF files
        elif file_ext == "pdf":
            try:
                import fitz  # PyMuPDF
                text = ""
                doc = fitz.open(file_path)
                for page in doc:
                    text += page.get_text() + "\n"
                return text
            except ImportError:
                logger.warning("PyMuPDF not installed. PDF text extraction unavailable.")
                return "PDF text extraction unavailable"
        
        # Image files
        elif file_ext in ["jpg", "jpeg", "png", "bmp"]:
            try:
                import pytesseract
                from PIL import Image
                return pytesseract.image_to_string(Image.open(file_path))
            except ImportError:
                logger.warning("Pytesseract not installed. Image text extraction unavailable.")
                return "Image text extraction unavailable"
            
        return ""
    except Exception as e:
        logger.error(f"Error extracting text: {e}")
        return ""

def detect_language(text):
    """Detect if text is Tamil or English"""
    if not text:
        return "en"
        
    # Check for Tamil characters
    tamil_chars = set("அஆஇஈஉஊஎஏஐஒஓஔகஙசஞடணதநபமயரலவழளறனஜஷஸஹ")
    text_chars = set(text)
    if len(tamil_chars.intersection(text_chars)) > 5:
        return "ta"
    return "en"

def analyze_petition(text, title, language='en'):
    """Analyze petition text to determine department, priority and tags"""
    try:
        api_key = app.config['OPENROUTER_API_KEY']
        
        # If no API key, use local analysis
        if not api_key:
            from utils import analyze_petition as utils_analyze
            return utils_analyze(text, title, language)
            
        # Translate Tamil to English if needed
        if language == 'ta':
            from googletrans import Translator
            try:
                translator = Translator()
                translated_title = translator.translate(title, dest='en').text
                translated_text = translator.translate(text[:1000], dest='en').text
            except Exception as e:
                logger.error(f"Translation error: {e}")
                translated_title = title
                translated_text = text[:1000]
        else:
            translated_title = title
            translated_text = text[:1000]

        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": "qwen/qwq-32b:free",
                "messages": [
                    {"role": "system", "content": "You are an AI that categorizes petitions."},
                    {"role": "user", "content": f"""
                    Analyze this petition and provide a JSON with:
                    1. department_name: One of [Education, Health, Infrastructure, Environment, Public Safety, Housing, Social Welfare, Transportation, General]
                    2. priority: low, normal, or high
                    3. tags: 3-5 relevant keywords as an array
                    4. analysis: Brief 1-2 sentence summary
                    
                    Title: {translated_title}
                    Content: {translated_text}
                    """}
                ],
                "response_format": {"type": "json_object"}
            },
            timeout=15  # Add timeout
        )
        
        if response.status_code == 200:
            content = response.json()["choices"][0]["message"]["content"]
            result = json.loads(content)
            
            return {
                "department_name": result.get("department_name", "General"),
                "priority": result.get("priority", "normal").capitalize(),
                "tags": result.get("tags", []),
                "analysis": result.get("analysis", "No analysis provided.")
            }
    except Exception as e:
        logger.error(f"AI analysis error: {e}")
    
    # Fallback to basic analysis
    combined_text = (text + " " + title).lower()
    departments = ["Education", "Health", "Infrastructure", "Environment", 
                  "Public Safety", "Housing", "Social Welfare", "Transportation"]
    
    # Try to match department by keywords
    for dept in departments:
        keywords = db.departments.find_one({"name": dept})
        if keywords and keywords.get("keywords"):
            if any(kw in combined_text for kw in keywords["keywords"]):
                return {
                    "department_name": dept,
                    "priority": "Normal",
                    "tags": [],
                    "analysis": "Automatic categorization based on keywords."
                }
    
    # Default values
    return {
        "department_name": "General",
        "priority": "Normal",
        "tags": [],
        "analysis": "No specific department identified."
    }

def send_reminder_email(petition, official_email):
    """Send reminder email to official"""
    try:
        subject = f"Reminder: Pending Petition #{petition['_id']}"
        
        # Get status name
        status = db.petition_statuses.find_one({"_id": petition['status_id']})
        status_name = status['name'] if status else "Unknown"
        
        body = f"""
        Dear Official,
        
        This is a reminder about a pending petition that requires your attention:
        
        Title: {petition['title']}
        Priority: {petition['priority']}
        Current Status: {status_name}
        Submitted: {format_ist_date(petition['upload_time'])}
        
        Please review this petition at your earliest convenience.
        
        Regards,
        Petition Management System
        """
        
        msg = Message(
            subject=subject,
            recipients=[official_email],
            body=body
        )
        mail.send(msg)
        logger.info(f"Sent reminder email to {official_email} for petition {petition['_id']}")
        return True
    except Exception as e:
        logger.error(f"Email error: {e}")
        return False

def automate_reminders():
    """Automated task to send reminders for pending petitions"""
    try:
        logger.info("Running automated reminders task")
        now = get_current_ist()
        three_days_ago = now - timedelta(days=3)
        
        # Find petitions that are pending for more than 3 days
        query = {
            "status_id": 1,  # Pending
            "upload_time": {"$lt": three_days_ago},
            "$or": [
                {"last_reminder": {"$lt": three_days_ago}},
                {"last_reminder": None}
            ]
        }
        
        pending_petitions = list(db.petitions.find(query))
        sent_count = 0
        
        for petition in pending_petitions:
            dept_name = petition.get("department_name")
            if dept_name:
                officials = list(db.users.find({"role": "official", "department": dept_name}))
                
                for official in officials:
                    if official.get("email"):
                        if send_reminder_email(petition, official["email"]):
                            sent_count += 1
                
                # Update last reminder time
                db.petitions.update_one(
                    {"_id": petition["_id"]},
                    {"$set": {"last_reminder": now}}
                )
        
        logger.info(f"Automated reminders: sent {sent_count} emails for {len(pending_petitions)} petitions")
    except Exception as e:
        logger.error(f"Error in automated reminders: {e}")

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.email = user_data['email']
        self.name = user_data.get('name', '')
        self.role = user_data.get('role', 'user')
        self.department = user_data.get('department', '')

@app.template_filter('nl2br')
def nl2br_filter(text):
    """Convert newlines to HTML line breaks"""
    if not text:
        return ""
    return Markup(text.replace('\n', '<br>'))

@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({"_id": ObjectId(user_id)})
    return User(user_data) if user_data else None

# Jinja filters
@app.template_filter('format_date')
def format_date_filter(date):
    return format_ist_date(date)

# Make the current year available in all templates
@app.context_processor
def inject_now():
    return {'now': datetime.now(ist_tz)}

# Initialize database with default values
def initialize_app_data():
    # Initialize petition statuses
    statuses = [
        (1, "Pending", "Petition received"),
        (2, "In Progress", "Being processed"),
        (3, "Under Review", "Additional review needed"),
        (4, "Awaiting Response", "Waiting for petitioner"),
        (5, "Resolved", "Petition resolved"),
        (6, "Rejected", "Petition rejected")
    ]
    
    for id, name, desc in statuses:
        if not db.petition_statuses.find_one({"_id": id}):
            db.petition_statuses.insert_one({
                "_id": id,
                "name": name,
                "description": desc
            })
    
    # Initialize departments
    departments = ["General", "Health", "Education", "Infrastructure", "Environment", 
                 "Public Safety", "Housing", "Social Welfare", "Transportation"]
    
    for name in departments:
        if not db.departments.find_one({"name": name}):
            db.departments.insert_one({
                "name": name,
                "description": f"{name} Department",
                "keywords": default_department_keywords(name)
            })
    
    # Create admin user
    if not db.users.find_one({"email": "admin@petition-system.com"}):
        db.users.insert_one({
            "email": "admin@petition-system.com",
            "password": generate_password_hash("admin123"),
            "name": "Admin",
            "role": "admin",
            "verified": True
        })

# ROUTES
@app.route('/')
def home():
    return redirect(url_for('dashboard') if current_user.is_authenticated else url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Redirect if already logged in
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        aadhar_no = request.form.get('aadhar_no')
        dob = request.form.get('dob')
        location = request.form.get('location')
        
        # Validate required fields
        if not all([email, password, name, aadhar_no, dob, location]):
            flash("All fields are required", "danger")
            return render_template('register.html')
            
        # Check if email already exists
        if db.users.find_one({"email": email}):
            flash("Email already registered", "danger")
            return render_template('register.html')
        
        # Create user record
        user_data = {
            "email": email,
            "password": generate_password_hash(password),
            "name": name,
            "role": "user",
            "registration_time": get_current_ist(),
            "verified": True  # Auto-verify for demo
        }
        user_id = db.users.insert_one(user_data).inserted_id
        
        # Create verification record
        verification_data = {
            "user_id": user_id,
            "name": name,
            "aadhar_no": aadhar_no,
            "dob": dob,
            "location": location,
            "verified_at": get_current_ist()
        }
        db.verifications.insert_one(verification_data)
        
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Clear session - improved logout functionality
    if current_user.is_authenticated:
        logout_user()
        flash("You've been logged out.", "info")
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("Email and password are required.", "danger")
            return render_template('login.html')

        user_data = db.users.find_one({"email": email})
        if not user_data:
            flash("Invalid email or password.", "danger")
            return render_template('login.html')
        
        # Security improvement - avoid detailed error messages
        try:
            # Check if the hash has the expected format
            stored_password = user_data.get('password', '')
            if not stored_password or '$' not in stored_password:
                flash("Invalid email or password.", "danger")
                return render_template('login.html')
                
            # Proceed with password verification
            if not check_password_hash(stored_password, password):
                flash("Invalid email or password.", "danger")
                return render_template('login.html')
                
            login_user(User(user_data))
            
            # Get next parameter or default to dashboard
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('dashboard')
                
            return redirect(next_page)
        except Exception:
            flash("Authentication error. Please try again.", "danger")
            return render_template('login.html')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for('login'))

@app.route("/dashboard")
@login_required
def dashboard():
    # Get petition statuses mapping
    petition_statuses = {s['_id']: s['name'] for s in db.petition_statuses.find()}
    
    # Get relevant petitions based on user role
    if current_user.role == 'official':
        department = db.departments.find_one({"name": current_user.department})
        query = {"department_id": department['_id']} if department else {}
    elif current_user.role == 'admin':
        query = {}
    else:
        query = {"user_id": ObjectId(current_user.id)}
    
    # Pagination
    page = int(request.args.get('page', 1))
    per_page = 10
    skip = (page - 1) * per_page
    
    # Get petitions with pagination
    petitions = list(db.petitions.find(query).sort("upload_time", -1).skip(skip).limit(per_page))
    total = db.petitions.count_documents(query)
    total_pages = (total + per_page - 1) // per_page
    
    # Get analytics data
    stats = {
        'total_petitions': total,
        'pending_count': db.petitions.count_documents({"status_id": 1}),
        'in_progress_count': db.petitions.count_documents({"status_id": 2}),
        'resolved_count': db.petitions.count_documents({"status_id": 5}),
        'high_priority_count': db.petitions.count_documents({"priority": "High"}),
    }
    
    return render_template('dashboard.html',
                          petitions=petitions,
                          petition_statuses=petition_statuses,
                          stats=stats,
                          page=page,
                          total_pages=total_pages)


@app.route("/delete_petition/<petition_id>", methods=["POST"])
@login_required
def delete_petition(petition_id):
    try:
        petition_obj_id = ObjectId(petition_id)
        petition = db.petitions.find_one({"_id": petition_obj_id})
        
        if not petition:
            flash("Petition not found.", "danger")
            return redirect(url_for("dashboard"))
        
        # Check permissions - only owner or admin can delete
        is_owner = str(petition.get('user_id', '')) == current_user.id
        is_admin = current_user.role == 'admin'
        
        if not (is_owner or is_admin):
            flash("You don't have permission to delete this petition.", "danger")
            return redirect(url_for("view_petition", petition_id=petition_id))
        
        # Delete associated comments
        db.comments.delete_many({"petition_id": petition_obj_id})
        
        # Delete associated status updates
        db.status_updates.delete_many({"petition_id": petition_obj_id})
        
        # Delete associated notifications
        db.notifications.delete_many({"petition_id": petition_obj_id})
        
        # Delete the file if it exists
        if petition.get('file_name'):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], petition['file_name'])
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # Delete the petition
        db.petitions.delete_one({"_id": petition_obj_id})
        
        flash("Petition deleted successfully.", "success")
        return redirect(url_for("dashboard"))
    except Exception as e:
        logger.error(f"Error deleting petition: {e}")
        flash("An error occurred while deleting the petition.", "danger")
        return redirect(url_for("view_petition", petition_id=petition_id))
    
@app.route("/upload_petition", methods=["GET", "POST"])
@login_required
def upload_petition():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content_text = request.form.get("content_text", "").strip()
        is_public = request.form.get("is_public") == "on"
        file = request.files.get('file')

        # Enhanced verification
        errors = []

        # Title validation
        if not title:
            errors.append("Title is required")
        elif len(title) < 5:
            errors.append("Title must be at least 5 characters long")
        elif len(title) > 100:
            errors.append("Title must not exceed 100 characters")

        # Content or file validation
        has_file = file and file.filename
        if not content_text and not has_file:
            errors.append("Either petition content or a file is required")
        if content_text and len(content_text) < 10:
            errors.append("Petition content must be at least 10 characters long")
        if content_text and len(content_text) > 5000:
            errors.append("Petition content must not exceed 5000 characters")

        # File validation
        allowed_extensions = {'pdf', 'txt', 'jpg', 'jpeg', 'png'}
        if has_file:
            filename = secure_filename(file.filename)
            if not filename:
                errors.append("Invalid file name")
            elif '.' not in filename or filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
                errors.append("File type not allowed. Use PDF, TXT, JPG, or PNG")

        # If errors, render form with errors and preserved data
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("petition_form.html",
                                 departments=list(db.departments.find()),
                                 form_data={
                                     "title": title,
                                     "content_text": content_text,
                                     "is_public": is_public
                                 })

        # Proceed with upload if verification passed
        file_name = None
        if has_file:
            filename = secure_filename(file.filename)
            unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            file_name = unique_filename
            if not content_text:
                content_text = extract_text_from_file(file_path)

        # Detect language and analyze petition
        language = detect_language(content_text)
        analysis = analyze_petition(content_text, title, language)

        # Get department ID
        department_id = get_department_id(analysis["department_name"])

        # Create petition
        petition_data = {
            "title": title,
            "content_text": content_text,
            "file_name": file_name,
            "is_public": is_public,
            "language": language,
            "priority": analysis["priority"],
            "department_id": department_id,
            "department_name": analysis["department_name"],
            "status_id": 1,  # Initially 'Pending'
            "upload_time": get_current_ist(),
            "user_id": ObjectId(current_user.id),
            "user_name": current_user.name,
            "verified": True,
            "tags": analysis["tags"],
            "analysis": analysis["analysis"],
            "last_reminder": None
        }

        result = db.petitions.insert_one(petition_data)
        petition_id = result.inserted_id

        # Notify department officials
        officials = list(db.users.find({"role": "official", "department": analysis["department_name"]}))
        for official in officials:
            db.notifications.insert_one({
                "user_id": official["_id"],
                "petition_id": petition_id,
                "message": f"New {analysis['priority']} priority petition: {title}",
                "timestamp": get_current_ist(),
                "is_read": False
            })

        flash(f"Petition submitted successfully as {analysis['priority']} priority for {analysis['department_name']} department.", "success")
        return redirect(url_for('view_petition', petition_id=petition_id))

    departments = list(db.departments.find())
    return render_template("petition_form.html", departments=departments, form_data={})

@app.route("/petitions")
@login_required
def view_petitions():
    # Get filters
    status_filter = request.args.get('status')
    priority_filter = request.args.get('priority')
    department_filter = request.args.get('department')
    search_query = request.args.get('search', '')
    
    # Build query
    query = {}
    
    # Add filters if provided
    if status_filter:
        query["status_id"] = int(status_filter)
    
    if priority_filter:
        query["priority"] = priority_filter
    
    if department_filter:
        department = db.departments.find_one({"name": department_filter})
        if department:
            query["department_id"] = department["_id"]
    
    # Add search
    if search_query:
        query["$or"] = [
            {"title": {"$regex": search_query, "$options": "i"}},
            {"content_text": {"$regex": search_query, "$options": "i"}},
            {"tags": {"$in": [search_query.lower()]}}
        ]
    
    # For regular users, only show their petitions or public ones
    if current_user.role == 'user':
        query = {"$and": [query, {"$or": [{"user_id": ObjectId(current_user.id)}, {"is_public": True}]}]}
    elif current_user.role == 'official':
        # Officials can only view petitions assigned to their department
        department = db.departments.find_one({"name": current_user.department})
        if department:
            query["department_id"] = department["_id"]
    
    # Pagination
    page = int(request.args.get('page', 1))
    per_page = 10
    skip = (page - 1) * per_page
    
    # Get petitions
    petitions = list(db.petitions.find(query).sort("upload_time", -1).skip(skip).limit(per_page))
    total = db.petitions.count_documents(query)
    total_pages = (total + per_page - 1) // per_page
    
    # Get statuses and departments for filters
    statuses = list(db.petition_statuses.find())  # Retrieve statuses from database
    departments = list(db.departments.find())
    
    # Create petition_statuses dictionary AFTER retrieving statuses
    petition_statuses = {s['_id']: s['name'] for s in statuses}
    
    return render_template('petitions.html',
                          petitions=petitions,
                          statuses=statuses,
                          departments=departments,
                          status_filter=status_filter,
                          priority_filter=priority_filter,
                          department_filter=department_filter,
                          search_query=search_query,
                          page=page,
                          total_pages=total_pages,
                          petition_statuses=petition_statuses)

@app.route('/petition/<petition_id>')
@login_required
def view_petition(petition_id):
    try:
        petition = db.petitions.find_one({"_id": ObjectId(petition_id)})
        
        if not petition:
            flash("Petition not found", "danger")
            return redirect(url_for('dashboard'))
        
        # Check if user has permission to view
        is_owner = str(petition.get('user_id', '')) == current_user.id
        is_public = petition.get('is_public', False)
        
        if not is_owner and not is_public and current_user.role == 'user':
            flash("You don't have permission to view this petition", "danger")
            return redirect(url_for('dashboard'))
        
        # Officials can only view petitions in their department
        if current_user.role == 'official':
            if petition.get('department_name') != current_user.department:
                flash("This petition is not assigned to your department", "danger")
                return redirect(url_for('dashboard'))
        
        # Get related data
        status = db.petition_statuses.find_one({"_id": petition['status_id']})
        department = None
        if 'department_id' in petition:
            department = db.departments.find_one({"_id": petition['department_id']})
        
        # Get comments and updates
        comments = list(db.comments.find({"petition_id": ObjectId(petition_id)}).sort("timestamp", -1))
        updates = list(db.status_updates.find({"petition_id": ObjectId(petition_id)}).sort("timestamp", -1))
        
        # Get petition statuses for officials/admin
        petition_statuses = {}
        if current_user.role in ['official', 'admin']:
            for s in db.petition_statuses.find():
                petition_statuses[s['_id']] = s['name']
        
        # Get similar petitions
        similar_petitions = []
        if petition.get('tags'):
            similar_query = {
                "_id": {"$ne": ObjectId(petition_id)},
                "tags": {"$in": petition['tags']},
            }
            
            # Apply permission filtering for similar petitions too
            if current_user.role == 'user':
                similar_query["$or"] = [{"is_public": True}, {"user_id": ObjectId(current_user.id)}]
            elif current_user.role == 'official':
                department = db.departments.find_one({"name": current_user.department})
                if department:
                    similar_query["department_id"] = department["_id"]
                    
            similar_petitions = list(db.petitions.find(similar_query).limit(3))
        
        return render_template('petition_detail.html',
                              petition=petition,
                              status=status,
                              department=department,
                              comments=comments,
                              updates=updates,
                              petition_statuses=petition_statuses,
                              similar_petitions=similar_petitions)
        
    except Exception as e:
        logger.error(f"Error viewing petition: {str(e)}")
        flash(f"Error viewing petition. Please try again.", "danger")
        return redirect(url_for('dashboard'))

@app.route("/add_comment/<petition_id>", methods=["POST"])
@login_required
def add_comment(petition_id):
    try:
        comment_text = request.form.get("comment_text")
        if not comment_text:
            flash("Comment cannot be empty.", "danger")
            return redirect(url_for("view_petition", petition_id=petition_id))
        
        petition_obj_id = ObjectId(petition_id)
        petition = db.petitions.find_one({"_id": petition_obj_id})
        
        if not petition:
            flash("Petition not found.", "danger")
            return redirect(url_for("dashboard"))
        
        # Check permission
        is_owner = str(petition.get('user_id', '')) == current_user.id
        is_public = petition.get('is_public', False)
        can_comment = is_owner or is_public or current_user.role in ['official', 'admin']
        
        if not can_comment:
            flash("You don't have permission to comment on this petition.", "danger")
            return redirect(url_for("dashboard"))
        
        # Add comment
        comment_data = {
            "petition_id": petition_obj_id,
            "user_id": ObjectId(current_user.id),
            "user_name": current_user.name,
            "text": comment_text,
            "timestamp": get_current_ist()
        }
        db.comments.insert_one(comment_data)
        
        # Notify petition owner
        if str(petition.get("user_id", '')) != current_user.id:
            db.notifications.insert_one({
                "user_id": petition["user_id"],
                "petition_id": petition_obj_id,
                "message": f"New comment on your petition: {petition['title']}",
                "timestamp": get_current_ist(),
                "is_read": False
            })
            
        flash("Comment added successfully.", "success")
        return redirect(url_for("view_petition", petition_id=petition_id))
    except Exception as e:
        logger.error(f"Error adding comment: {e}")
        flash("An error occurred.", "danger")
        return redirect(url_for("view_petition", petition_id=petition_id))

@app.route("/update_status/<petition_id>", methods=["POST"])
@login_required
def update_status(petition_id):
    try:
        # Check permissions
        if current_user.role not in ['official', 'admin']:
            flash("Permission denied.", "danger")
            return redirect(url_for("view_petition", petition_id=petition_id))
        
        petition_obj_id = ObjectId(petition_id)
        petition = db.petitions.find_one({"_id": petition_obj_id})
        
        if not petition:
            flash("Petition not found.", "danger")
            return redirect(url_for("dashboard"))
        
        # Check department permission for officials
        if current_user.role == 'official' and petition.get("department_name"):
            if current_user.department != petition.get("department_name"):
                flash("You can only update petitions for your department.", "danger")
                return redirect(url_for("view_petition", petition_id=petition_id))
        
        # Get form data
        new_status_id = int(request.form.get("status_id"))
        notes = request.form.get("notes", "")
        old_status_id = petition["status_id"]
        
        # Update petition
        update_data = {"status_id": new_status_id}
        if new_status_id == 5:  # Resolved
            update_data["resolution_time"] = get_current_ist()
            update_data["resolution_notes"] = notes
        
        db.petitions.update_one({"_id": petition_obj_id}, {"$set": update_data})
        
        # Record status update
        db.status_updates.insert_one({
            "petition_id": petition_obj_id,
            "old_status_id": old_status_id,
            "new_status_id": new_status_id,
            "notes": notes,
            "updated_by": ObjectId(current_user.id),
            "updated_by_name": current_user.name,
            "timestamp": get_current_ist()
        })
        
        # Notify the petition owner
        status = db.petition_statuses.find_one({"_id": new_status_id})
        status_name = status["name"] if status else "Unknown"
        
        db.notifications.insert_one({
            "user_id": petition["user_id"],
            "petition_id": petition_obj_id,
            "message": f"Your petition '{petition['title']}' is now {status_name}",
            "timestamp": get_current_ist(),
            "is_read": False
        })
        
        flash("Status updated successfully.", "success")
        return redirect(url_for("view_petition", petition_id=petition_id))
    except Exception as e:
        logger.error(f"Error updating status: {e}")
        flash(f"Error updating status.", "danger")
        return redirect(url_for("view_petition", petition_id=petition_id))

@app.route('/admin/fix-passwords', methods=['GET'])
@login_required
@requires_roles('admin')
def fix_passwords():
    # Set a default password for all users with invalid password hashes
    default_password = "changeme123"
    result = db.users.update_many(
        {"$or": [
            {"password": {"$exists": False}},
            {"password": ""},
            {"password": {"$not": {"$regex": "pbkdf2:sha256:.*"}}}
        ]},
        {"$set": {"password": generate_password_hash(default_password)}}
    )
    
    flash(f"Fixed {result.modified_count} user accounts. Default password set to '{default_password}'", "success")
    return redirect(url_for("admin_manage"))

@app.route("/admin/manage", methods=["GET", "POST"])
@login_required
@requires_roles('admin')
def admin_manage():
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "add_department":
            name = request.form.get("name")
            description = request.form.get("description", "")
            
            if name and not db.departments.find_one({"name": name}):
                keywords = generate_department_keywords(name)
                db.departments.insert_one({
                    "name": name,
                    "description": description,
                    "keywords": keywords
                })
                flash(f"Department '{name}' added with {len(keywords)} keywords.", "success")
            else:
                flash("Department name required or already exists.", "danger")
        
        elif action == "add_user":
            email = request.form.get("email")
            name = request.form.get("name")
            password = request.form.get("password")
            role = request.form.get("role")
            department = request.form.get("department") if role == "official" else None
            
            if email and not db.users.find_one({"email": email}):
                db.users.insert_one({
                    "email": email,
                    "name": name,
                    "password": generate_password_hash(password),
                    "role": role,
                    "department": department,
                    "verified": True
                })
                flash(f"User '{email}' added as {role}.", "success")
            else:
                flash("Email required or already exists.", "danger")
    
    # Get data for the template
    departments = list(db.departments.find().sort("name", 1))
    officials = list(db.users.find({"role": "official"}).sort("name", 1))
    
    # Get analytics data
    department_counts = []
    for dept in departments:
        count = db.petitions.count_documents({"department_id": dept["_id"]})
        department_counts.append({"name": dept["name"], "count": count})
    
    status_counts = []
    for status in db.petition_statuses.find():
        count = db.petitions.count_documents({"status_id": status["_id"]})
        status_counts.append({"name": status["name"], "count": count})
    
    # Monthly petition counts for chart
    monthly_counts = []
    now = get_current_ist()
    for i in range(6):  # Last 6 months
        month_start = now.replace(day=1) - timedelta(days=30*i)
        month_end = (month_start + timedelta(days=31)).replace(day=1)
        count = db.petitions.count_documents({
            "upload_time": {"$gte": month_start, "$lt": month_end}
    })
    monthly_counts.append({
        "month": month_start.strftime("%b %Y"),
        "count": count
    })
    monthly_counts.reverse()
    
    return render_template(
        "admin_manage.html",
        departments=departments,
        officials=officials,
        department_counts=department_counts,
        status_counts=status_counts,
        monthly_counts=monthly_counts
    )

@app.route("/notifications")
@login_required
def view_notifications():
    notifications = list(db.notifications.find(
        {"user_id": ObjectId(current_user.id)}
    ).sort("timestamp", -1).limit(20))
    
    # Mark all as read
    db.notifications.update_many(
        {"user_id": ObjectId(current_user.id), "is_read": False},
        {"$set": {"is_read": True}}
    )
    
    return render_template("notifications.html", notifications=notifications)

@app.route('/api/notifications/count')
@login_required
def get_notification_count():
    """API endpoint to get the number of unread notifications"""
    unread_count = db.notifications.count_documents({
        "user_id": ObjectId(current_user.id),
        "is_read": False
    })
    return jsonify({"count": unread_count})

@app.route('/api/search')
@login_required
def api_search():
    """API endpoint for searching petitions"""
    query = request.args.get('query', '')
    
    if not query or len(query) < 3:
        return jsonify({"results": []})
    
    # Search in title, content and tags
    search_query = {
        "$or": [
            {"title": {"$regex": query, "$options": "i"}},
            {"content_text": {"$regex": query, "$options": "i"}},
            {"tags": {"$in": [query.lower()]}}
        ]
    }
    
    # Limit access based on user role
    if current_user.role == 'user':
        search_query = {"$and": [
            search_query,
            {"$or": [{"user_id": ObjectId(current_user.id)}, {"is_public": True}]}
        ]}
    elif current_user.role == 'official':
        department = db.departments.find_one({"name": current_user.department})
        if department:
            search_query["department_id"] = department["_id"]
    
    results = list(db.petitions.find(search_query).limit(10))
    
    # Format results for JSON response
    formatted_results = []
    for p in results:
        status = db.petition_statuses.find_one({"_id": p.get("status_id")})
        formatted_results.append({
            "id": str(p["_id"]),
            "title": p["title"],
            "status": status["name"] if status else "Unknown",
            "priority": p["priority"],
            "date": format_ist_date(p["upload_time"])
        })
    
    return jsonify({"results": formatted_results})

# Schedule task to send reminders for pending petitions
@app.route('/send_reminders')
@login_required
@requires_roles('admin')
def send_reminders():
    """Manually trigger reminders for pending petitions"""
    try:
        automate_reminders()
        return jsonify({"success": True, "message": "Reminders sent successfully"})
    except Exception as e:
        logger.error(f"Error in manual reminders: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# API route for React integration
@app.route('/api/petitions')
@login_required
def api_petitions():
    """API endpoint for React to fetch petitions"""
    try:
        # Get filters
        status_filter = request.args.get('status')
        priority_filter = request.args.get('priority')
        department_filter = request.args.get('department')
        search_query = request.args.get('search', '')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        
        # Build query
        query = {}
        
        # Add filters if provided
        if status_filter:
            query["status_id"] = int(status_filter)
        
        if priority_filter:
            query["priority"] = priority_filter
        
        if department_filter:
            department = db.departments.find_one({"name": department_filter})
            if department:
                query["department_id"] = department["_id"]
        
        # Add search
        if search_query:
            query["$or"] = [
                {"title": {"$regex": search_query, "$options": "i"}},
                {"content_text": {"$regex": search_query, "$options": "i"}},
                {"tags": {"$in": [search_query.lower()]}}
            ]
        
        # Apply permissions
        if current_user.role == 'user':
            query = {"$and": [query, {"$or": [{"user_id": ObjectId(current_user.id)}, {"is_public": True}]}]}
        elif current_user.role == 'official':
            department = db.departments.find_one({"name": current_user.department})
            if department:
                query["department_id"] = department["_id"]
        
        # Get total count for pagination
        total = db.petitions.count_documents(query)
        
        # Get petitions with pagination
        skip = (page - 1) * per_page
        petitions_cursor = db.petitions.find(query).sort("upload_time", -1).skip(skip).limit(per_page)
        
        # Format data for API response
        petitions_data = []
        for p in petitions_cursor:
            status = db.petition_statuses.find_one({"_id": p.get("status_id", 1)})
            petitions_data.append({
                "id": str(p["_id"]),
                "title": p["title"],
                "department": p.get("department_name", ""),
                "status": status["name"] if status else "Unknown",
                "status_id": p.get("status_id", 1),
                "priority": p.get("priority", "Normal"),
                "upload_date": format_ist_date(p.get("upload_time")),
                "is_public": p.get("is_public", False),
                "tags": p.get("tags", [])
            })
        
        # Return JSON response
        return jsonify({
            "petitions": petitions_data,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
            "current_page": page
        })
    
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({"error": "An error occurred"}), 500

@app.route('/api/petition/<petition_id>')
@login_required
def api_petition_detail(petition_id):
    """API endpoint for React to fetch petition details"""
    try:
        petition = db.petitions.find_one({"_id": ObjectId(petition_id)})
        
        if not petition:
            return jsonify({"error": "Petition not found"}), 404
        
        # Check if user has permission to view
        is_owner = str(petition.get('user_id', '')) == current_user.id
        is_public = petition.get('is_public', False)
        
        if not is_owner and not is_public and current_user.role == 'user':
            return jsonify({"error": "Permission denied"}), 403
        
        # Officials can only view petitions in their department
        if current_user.role == 'official':
            if petition.get('department_name') != current_user.department:
                return jsonify({"error": "Permission denied"}), 403
        
        # Get related data
        status = db.petition_statuses.find_one({"_id": petition['status_id']})
        department = None
        if 'department_id' in petition:
            department = db.departments.find_one({"_id": petition['department_id']})
        
        # Get comments and updates
        comments = list(db.comments.find({"petition_id": ObjectId(petition_id)}).sort("timestamp", -1))
        comments_data = [{
            "id": str(c["_id"]),
            "user_name": c.get("user_name", "Unknown"),
            "text": c.get("text", ""),
            "timestamp": format_ist_date(c.get("timestamp"))
        } for c in comments]
        
        updates = list(db.status_updates.find({"petition_id": ObjectId(petition_id)}).sort("timestamp", -1))
        updates_data = []
        for u in updates:
            old_status = db.petition_statuses.find_one({"_id": u.get("old_status_id", 1)})
            new_status = db.petition_statuses.find_one({"_id": u.get("new_status_id", 1)})
            updates_data.append({
                "id": str(u["_id"]),
                "old_status": old_status["name"] if old_status else "Unknown",
                "new_status": new_status["name"] if new_status else "Unknown",
                "notes": u.get("notes", ""),
                "updated_by": u.get("updated_by_name", "Unknown"),
                "timestamp": format_ist_date(u.get("timestamp"))
            })
        
        # Format petition data for API
        petition_data = {
            "id": str(petition["_id"]),
            "title": petition.get("title", ""),
            "content": petition.get("content_text", ""),
            "file_name": petition.get("file_name"),
            "department": petition.get("department_name", ""),
            "priority": petition.get("priority", "Normal"),
            "status": status["name"] if status else "Unknown",
            "status_id": petition.get("status_id", 1),
            "upload_date": format_ist_date(petition.get("upload_time")),
            "is_public": petition.get("is_public", False),
            "tags": petition.get("tags", []),
            "analysis": petition.get("analysis", ""),
            "uploader": petition.get("user_name", "Unknown"),
            "comments": comments_data,
            "updates": updates_data,
            "can_edit": is_owner or current_user.role == "admin",
            "can_update_status": current_user.role in ["official", "admin"]
        }
        
        return jsonify(petition_data)
        
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({"error": "An error occurred"}), 500

@app.route('/api/statuses')
@login_required
def api_statuses():
    """API endpoint for React to fetch statuses"""
    try:
        statuses = list(db.petition_statuses.find())
        statuses_data = [{
            "id": s["_id"],
            "name": s["name"],
            "description": s.get("description", "")
        } for s in statuses]
        
        return jsonify(statuses_data)
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({"error": "An error occurred"}), 500

@app.route('/api/departments')
@login_required
def api_departments():
    """API endpoint for React to fetch departments"""
    try:
        departments = list(db.departments.find())
        departments_data = [{
            "id": str(d["_id"]),
            "name": d["name"],
            "description": d.get("description", "")
        } for d in departments]
        
        return jsonify(departments_data)
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({"error": "An error occurred"}), 500

@app.route('/api/add_comment', methods=["POST"])
@login_required
def api_add_comment():
    """API endpoint for React to add comments"""
    try:
        data = request.json
        petition_id = data.get('petition_id')
        comment_text = data.get('comment_text')
        
        if not petition_id or not comment_text:
            return jsonify({"error": "Petition ID and comment text are required"}), 400
        
        petition_obj_id = ObjectId(petition_id)
        petition = db.petitions.find_one({"_id": petition_obj_id})
        
        if not petition:
            return jsonify({"error": "Petition not found"}), 404
        
        # Check permission
        is_owner = str(petition.get('user_id', '')) == current_user.id
        is_public = petition.get('is_public', False)
        can_comment = is_owner or is_public or current_user.role in ['official', 'admin']
        
        if not can_comment:
            return jsonify({"error": "Permission denied"}), 403
        
        # Add comment
        comment_data = {
            "petition_id": petition_obj_id,
            "user_id": ObjectId(current_user.id),
            "user_name": current_user.name,
            "text": comment_text,
            "timestamp": get_current_ist()
        }
        result = db.comments.insert_one(comment_data)
        
        # Notify petition owner
        if str(petition.get("user_id", '')) != current_user.id:
            db.notifications.insert_one({
                "user_id": petition["user_id"],
                "petition_id": petition_obj_id,
                "message": f"New comment on your petition: {petition['title']}",
                "timestamp": get_current_ist(),
                "is_read": False
            })
        
        return jsonify({"success": True, "comment_id": str(result.inserted_id)})
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({"error": "An error occurred"}), 500

@app.route('/api/update_status', methods=["POST"])
@login_required
def api_update_status():
    """API endpoint for React to update petition status"""
    try:
        if current_user.role not in ['official', 'admin']:
            return jsonify({"error": "Permission denied"}), 403
        
        data = request.json
        petition_id = data.get('petition_id')
        new_status_id = data.get('status_id')
        notes = data.get('notes', '')
        
        if not petition_id or not new_status_id:
            return jsonify({"error": "Petition ID and status ID are required"}), 400
        
        petition_obj_id = ObjectId(petition_id)
        petition = db.petitions.find_one({"_id": petition_obj_id})
        
        if not petition:
            return jsonify({"error": "Petition not found"}), 404
        
        # Check department permission for officials
        if current_user.role == 'official' and petition.get("department_name"):
            if current_user.department != petition.get("department_name"):
                return jsonify({"error": "You can only update petitions for your department"}), 403
        
        # Convert to integer
        try:
            new_status_id = int(new_status_id)
        except ValueError:
            return jsonify({"error": "Invalid status ID"}), 400
            
        old_status_id = petition["status_id"]
        
        # Update petition
        update_data = {"status_id": new_status_id}
        if new_status_id == 5:  # Resolved
            update_data["resolution_time"] = get_current_ist()
            update_data["resolution_notes"] = notes
        
        db.petitions.update_one({"_id": petition_obj_id}, {"$set": update_data})
        
        # Record status update
        db.status_updates.insert_one({
            "petition_id": petition_obj_id,
            "old_status_id": old_status_id,
            "new_status_id": new_status_id,
            "notes": notes,
            "updated_by": ObjectId(current_user.id),
            "updated_by_name": current_user.name,
            "timestamp": get_current_ist()
        })
        
        # Notify the petition owner
        status = db.petition_statuses.find_one({"_id": new_status_id})
        status_name = status["name"] if status else "Unknown"
        
        db.notifications.insert_one({
            "user_id": petition["user_id"],
            "petition_id": petition_obj_id,
            "message": f"Your petition '{petition['title']}' is now {status_name}",
            "timestamp": get_current_ist(),
            "is_read": False
        })
        
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({"error": "An error occurred"}), 500

# Create scheduler for automated reminders
scheduler = BackgroundScheduler()
scheduler.add_job(automate_reminders, 'interval', hours=24)  # Run daily

# Starting the app
if __name__ == '__main__':
    initialize_app_data()
    scheduler.start()  # Start the scheduler
    try:
        app.run(debug=False)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()