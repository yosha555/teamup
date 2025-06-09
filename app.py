from flask import Flask, render_template, url_for, request, flash, session, redirect, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, join_room, leave_room, emit
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import random
from string import ascii_uppercase
import json
import os
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.secret_key = "jfbrpijbrejcsdcere"
app.config["SQLALCHEMY_DATABASE_URI"]= "sqlite:///users.sqlite3"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

socketio = SocketIO(app)

UPLOAD_FOLDER = "uploaded_task_files"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    public_key = db.Column(db.Text, nullable=False)   # PEM format
    private_key = db.Column(db.Text, nullable=False)  # PEM format (only for testing – not recommended in production)

    rooms = db.relationship('Room', secondary='user_room', back_populates='members')
    sent_messages = db.relationship('Message', backref='sender', lazy=True)
    received_messages = db.relationship('EncryptedMessage', back_populates='recipient')

    def __repr__(self):
        return f"<User {self.email}>"


class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(10), unique=True, nullable=False)

    members = db.relationship('User', secondary='user_room', back_populates='rooms')
    messages = db.relationship('Message', backref='room', lazy=True)

    def __repr__(self):
        return f"<Room {self.name}>"


user_room = db.Table("user_room",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
    db.Column("room_id", db.Integer, db.ForeignKey("room.id"), primary_key=True)
)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    encrypted_copies = db.relationship('EncryptedMessage', back_populates='message', lazy=True)

    def __repr__(self):
        return f"<Message {self.id} from {self.sender_id}>"
    
    
class EncryptedMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)

    message = db.relationship('Message', back_populates='encrypted_copies')
    recipient = db.relationship('User', back_populates='received_messages')

    def __repr__(self):
        return f"<EncryptedMessage msg={self.message_id} to={self.recipient_id}>"


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    due_date = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(50), nullable=False, default='not started')  # Enum-like values
    files = db.relationship('TaskFile', backref='task', lazy=True)

    assigned_to = db.relationship("User", backref="assigned_tasks")
    room = db.relationship('Room')


class TaskFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)  # Path on disk or cloud
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<TaskFile {self.filename} for Task {self.task_id}>"





@app.route("/")
def home():
    return render_template("home.html")

# Signup route
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("pwd")
        public_key = request.form.get("publicKey")
        private_key = request.form.get("privateKey")

        # Basic validation
        if not all([name, email, password, public_key, private_key]):
            flash("Please fill in all fields.")
            return render_template("signup.html")

        # Check for existing user
        if User.query.filter_by(email=email).first():
            flash("User already exists.")
            return render_template("signup.html")

        # Hash password
        hashed_password = generate_password_hash(password)

        # Save user
        user = User(
            name=name,
            email=email,
            password=hashed_password,
            public_key=public_key,
            private_key=private_key, 
        )

        db.session.add(user)
        db.session.commit()

        session["email"] = email
        return redirect(url_for("rooms"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("pwd")

        user = User.query.filter_by(email=email).first()
        if user:
            # Check hashed password
            if check_password_hash(user.password, password):
                session["email"] = user.email
                return redirect(url_for("rooms"))
            else:
                flash("Incorrect password", "error")
        else:
            flash("User does not exist", "error")
    return render_template("login.html")


@app.route("/rooms", methods=["GET","POST"])
def rooms():
    if "email" not in session:
        return redirect(url_for("login"))
    
    user = User.query.filter_by(email=session["email"]).first()

    return render_template("rooms.html", user=user)


def generate_code(length=6):
    while True:
        code = ''.join(random.choices(ascii_uppercase, k=length))
        if not Room.query.filter_by(code=code).first():
            return code
        

def encrypt_message_for_user(public_key_pem, message):
    rsa_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted).decode()

@app.route("/create_room", methods=["GET", "POST"])
def create_room():
    if "email" not in session:
        return redirect(url_for("login"))

    user = User.query.filter_by(email=session["email"]).first()

    if request.method == "POST":
        room_name = request.form["name"]
        room_code = generate_code()

        # Create and add user to the room
        new_room = Room(name=room_name, code=room_code)
        user.rooms.append(new_room)
        db.session.add(new_room)
        db.session.commit()

        flash(f"Room '{room_name}' created!")
        return redirect(url_for("rooms"))

    return redirect(url_for("rooms"))


@app.route("/join_room", methods=["POST","GET"])
def join_room_route():

    if "email" not in session:
        return redirect(url_for("login"))
    
    if request.method == "POST":
        user = User.query.filter_by(email=session["email"]).first()
        room_name = request.form["name"]
        room_code = request.form["code"]

        room = Room.query.filter_by(name=room_name, code=room_code).first()

        if not room:
            flash("Room does not exist")
        else:
            # Add user to room only if they are not already a member
            if room not in user.rooms:
                socketio.emit("refresh_room", {"room_code": room.code}, room=room.code)
                user.rooms.append(room)
                db.session.commit()

    return redirect(url_for("rooms"))


@app.route("/room/<code>")
def view_room(code):

    if "email" not in session:
        return redirect(url_for("login"))
    user = User.query.filter_by(email=session["email"]).first()
    room = Room.query.filter_by(code=code).first_or_404()

    if room not in user.rooms:
        return redirect(url_for("rooms"))
    
    members = [
    {
        "id": member.id,
        "name": member.name,
        "public_key": member.public_key
    }
    for member in room.members if member.id != user.id
]
    tasks = Task.query.filter_by(room_id=room.id).all()
    
    return render_template("view_room.html", user=user, room=room, members_json=members, tasks=tasks)


@app.route("/leave_room/<code>", methods=["POST"])
def leave_room_route(code):
    if "email" not in session:
        return redirect(url_for("login"))
    
    user = User.query.filter_by(email=session["email"]).first()
    room = Room.query.filter_by(code=code).first_or_404()

    if room in user.rooms:
        user.rooms.remove(room)
        db.session.commit()
        flash(f"You have left the room '{room.name}'.")

    return redirect(url_for("rooms"))



@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()

    room_id = data.get("room_id")
    encrypted_messages = data.get("messages")

    if not room_id or not encrypted_messages:
        return jsonify({"error": "Invalid data"}), 400

    # Get current user
    user = User.query.filter_by(email=session.get("email")).first()
    if not user:
        return jsonify({"error": "User not found"}), 401

    # Create and save the base Message
    new_message = Message(
        sender_id=user.id,
        room_id=room_id,
        timestamp=datetime.now()
    )
    db.session.add(new_message)
    db.session.flush()  # to get new_message.id before commit

    # Save each encrypted message and emit to the recipient
    for user_id_str, encrypted_content in encrypted_messages.items():
        try:
            recipient_id = int(user_id_str) if user_id_str != "self" else user.id

        except ValueError:
            print(f"Skipping invalid key: {user_id_str}")
            continue  # skip invalid keys

        # Save to DB
        encrypted_entry = EncryptedMessage(
            message_id=new_message.id,
            recipient_id=recipient_id,
            encrypted_content=encrypted_content
        )
        db.session.add(encrypted_entry)
        print(f"message saved for: {recipient_id}")
        print(encrypted_content)

        # Emit via SocketIO to recipient's private room
        socketio.emit("new_message", {
            "sender_name": user.name,
            "timestamp": new_message.timestamp.isoformat(),
            "encrypted_content": encrypted_content,
            "recipient_id": recipient_id,
        }, room=f"user_{recipient_id}")

    db.session.commit()

    return jsonify({"status": "ok", "message_id": new_message.id})


@app.route("/get_messages/<int:room_id>")
def get_messages(room_id):
    print(room_id)
    user = User.query.filter_by(email=session["email"]).first()
    if not user:
        return jsonify({"error": "User not found"}), 401


    encrypted_messages = (
        EncryptedMessage.query
        .join(EncryptedMessage.message)  # use the back_populated relationship
        .filter(
            EncryptedMessage.recipient_id == user.id,
            Message.room_id == room_id
        )
        .order_by(Message.timestamp)
        .all()
    )

    result = []
    for em in encrypted_messages:
        result.append({
            "encrypted_content": em.encrypted_content,
            "timestamp": em.message.timestamp.isoformat(),
            "sender_name": em.message.sender.name,
            "recipient_id": em.recipient_id
        })

        print(f"message for: {em.recipient_id}")
        print(em.encrypted_content)

    return jsonify(result)


@app.route('/room/<room_code>/tasks')
def get_tasks(room_code):
    room = Room.query.filter_by(code=room_code).first_or_404()
    tasks = Task.query.filter_by(room_id=room.id).all()
    return render_template('tasks.html', tasks=tasks, room=room)


@app.route("/rooms/<room_code>/create_task", methods=["POST"])
def create_task(room_code):
    user = User.query.filter_by(email=session.get("email")).first()
    if not user:
        return redirect(url_for("login"))

    room = Room.query.filter_by(code=room_code).first_or_404()

    task_name = request.form.get("name")
    due_date = request.form.get("due_date")
    status = request.form.get("status")

    task = Task(
        room_id=room.id,
        assigned_to_id=user.id,
        name=task_name,
        due_date=datetime.strptime(due_date, "%Y-%m-%d") if due_date else None,
        status=status
    )

    db.session.add(task)
    db.session.commit()

    return redirect(url_for("view_room", code=room.code))


@app.route("/upload_task_file/<int:task_id>", methods=["POST"])
def upload_task_file(task_id):
    task = Task.query.get_or_404(task_id)
    room = Room.query.get_or_404(task.room_id)

    uploaded_file = request.files.get("file")
    if not uploaded_file:
        return "No file uploaded", 400

    filename = secure_filename(uploaded_file.filename)
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    uploaded_file.save(save_path)

    task_file = TaskFile(
        task_id=task.id,
        filename=filename,
        filepath=save_path
    )

    db.session.add(task_file)
    db.session.commit()

    return redirect(url_for("view_room", code=room.code))


@app.route("/download_task_file/<int:file_id>")
def download_task_file(file_id):
    task_file = TaskFile.query.get_or_404(file_id)
    return send_file(task_file.filepath, as_attachment=True)



@app.route("/update_task_status/<int:task_id>", methods=["POST"])
def update_task_status(task_id):
    task = Task.query.get_or_404(task_id)
    new_status = request.form.get("status")
    if new_status not in ["not started", "working on it", "stuck", "done"]:
        return "Invalid status", 400

    task.status = new_status
    db.session.commit()

    # Redirect back to the room page (you can adjust if needed)
    return redirect(url_for("view_room", code=task.room.code))


@app.route("/update_task_assignee/<int:task_id>", methods=["POST"])
def update_task_assignee(task_id):
    task = Task.query.get_or_404(task_id)
    new_user_id = request.form.get("assigned_to")

    new_user = User.query.get(new_user_id)
    if not new_user or new_user not in task.room.members:
        return "Invalid assignee", 400

    task.assigned_to_id = new_user.id  # 🔧 correct field
    db.session.commit()
    return redirect(url_for("view_room", code=task.room.code))



@app.route('/debug')
def debug():
    return render_template("debug.html")



@socketio.on("connect")
def handle_connect():
    if "email" not in session:
        return False  # Reject connection

    user = User.query.filter_by(email=session["email"]).first()
    if user:
        for room in user.rooms:
            join_room(room.code)
        join_room(f"user_{user.id}")  # Private room for personal messages
        print(f"{user.name} connected and re-joined rooms: {[room.code for room in user.rooms]}")
    else:
        return False




if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
