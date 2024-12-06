from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pytz  # Importação do pytz para manipular fusos horários
import os

# Configuração do aplicativo Flask
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(app.instance_path, "tarefas.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24)

# Inicialização do banco de dados
db = SQLAlchemy(app)

# Configuração do gerenciador de login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Modelo do Usuário
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    tasks = db.relationship('Task', backref='user', lazy=True)

# Modelo da Tarefa
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=None)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, title, description, user_id):
        self.title = title
        self.description = description
        self.user_id = user_id
        # Define o horário de criação usando o fuso horário de Brasília
        self.created_at = datetime.now(pytz.timezone('America/Sao_Paulo'))

# Carregar usuário
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Criação do banco de dados
with app.app_context():
    os.makedirs(app.instance_path, exist_ok=True)
    db.create_all()

# Rota de Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('home'))
        flash('Login inválido. Verifique seu nome de usuário e senha.', 'danger')
    return render_template('login.html')

# Rota de Registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if len(password) < 8:
            flash('A senha deve ter pelo menos 8 caracteres.', 'warning')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        if User.query.filter_by(username=username).first() is None:
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Conta criada com sucesso!', 'success')
            return redirect(url_for('login'))

        flash('Nome de usuário já existe. Por favor, escolha outro.', 'warning')
    return render_template('register.html')

# Rota de Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você foi desconectado!', 'info')
    return redirect(url_for('login'))

# Rota Principal (Home)
@app.route('/')
@login_required
def home():
    tasks = Task.query.filter_by(user_id=current_user.id).order_by(Task.created_at.desc()).all()
    return render_template('home.html', tasks=tasks)

# Rota de Criação de Tarefa
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        new_task = Task(title=title, description=description, user_id=current_user.id)
        db.session.add(new_task)
        db.session.commit()
        flash('Tarefa adicionada com sucesso!', 'success')
        return redirect(url_for('home'))
    return render_template('create.html')

# Rota de Atualização de Tarefa
@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    task = Task.query.get_or_404(id)
    if task.user_id != current_user.id:
        flash('Você não tem permissão para editar esta tarefa.', 'danger')
        return redirect(url_for('home'))
    if request.method == 'POST':
        task.title = request.form.get('title')
        task.description = request.form.get('description')
        db.session.commit()
        flash('Tarefa atualizada com sucesso!', 'warning')
        return redirect(url_for('home'))
    return render_template('update.html', task=task)

# Rota de Exclusão de Tarefa
@app.route('/delete/<int:id>')
@login_required
def delete(id):
    task = Task.query.get_or_404(id)
    if task.user_id != current_user.id:
        flash('Você não tem permissão para excluir esta tarefa.', 'danger')
        return redirect(url_for('home'))
    db.session.delete(task)
    db.session.commit()
    flash('Tarefa excluída com sucesso!', 'danger')
    return redirect(url_for('home'))

# Inicialização do servidor
if __name__ == '__main__':
    app.run(debug=True)
