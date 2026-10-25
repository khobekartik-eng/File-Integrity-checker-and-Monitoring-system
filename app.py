import os, hashlib
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'local-demo-change-this-secret')
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024
url = os.environ.get('DATABASE_URL', 'sqlite:///integrityx.db')
if url.startswith('postgres://'): url = url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
def stamp(): return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
def digest(stream):
    h=hashlib.sha256(); size=0
    while True:
        chunk=stream.read(1024*1024)
        if not chunk: break
        size += len(chunk); h.update(chunk)
    return h.hexdigest(), size
class User(db.Model):
    id=db.Column(db.Integer, primary_key=True); username=db.Column(db.String(80), unique=True, nullable=False); full_name=db.Column(db.String(160), nullable=False); password_hash=db.Column(db.String(255), nullable=False)
class Baseline(db.Model):
    id=db.Column(db.Integer, primary_key=True); user_id=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False); case_id=db.Column(db.String(100)); evidence_id=db.Column(db.String(100)); filename=db.Column(db.String(255), nullable=False); size=db.Column(db.Integer, nullable=False); sha256=db.Column(db.String(64), nullable=False); created=db.Column(db.String(40), nullable=False)
class Check(db.Model):
    id=db.Column(db.Integer, primary_key=True); user_id=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False); baseline_id=db.Column(db.Integer, nullable=False); filename=db.Column(db.String(255), nullable=False); size=db.Column(db.Integer, nullable=False); sha256=db.Column(db.String(64), nullable=False); result=db.Column(db.String(20), nullable=False); checked=db.Column(db.String(40), nullable=False)
class Audit(db.Model):
    id=db.Column(db.Integer, primary_key=True); username=db.Column(db.String(80), nullable=False); event=db.Column(db.String(40), nullable=False); at=db.Column(db.String(40), nullable=False)
with app.app_context(): db.create_all()
def logged(fn):
    @wraps(fn)
    def wrap(*a,**kw):
        if 'uid' not in session: return redirect(url_for('login'))
        return fn(*a,**kw)
    return wrap
@app.route('/')
def index(): return redirect(url_for('dashboard' if 'uid' in session else 'login'))
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method=='POST':
        name=request.form.get('name','').strip(); username=request.form.get('username','').strip(); password=request.form.get('password','')
        if not name or len(username)<3 or len(password)<10: flash('Name, username (3+ characters) and password (10+ characters) required.','error')
        elif User.query.filter(db.func.lower(User.username)==username.lower()).first(): flash('Username already exists.','error')
        else:
            db.session.add(User(username=username,full_name=name,password_hash=generate_password_hash(password))); db.session.add(Audit(username=username,event='REGISTER',at=stamp())); db.session.commit(); flash('Account created. Please sign in.','success'); return redirect(url_for('login'))
    return render_template('register.html')
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        username=request.form.get('username','').strip(); user=User.query.filter(db.func.lower(User.username)==username.lower()).first()
        if user and check_password_hash(user.password_hash,request.form.get('password','')):
            session.clear(); session['uid']=user.id; session['username']=user.username; session['name']=user.full_name; db.session.add(Audit(username=user.username,event='LOGIN',at=stamp())); db.session.commit(); return redirect(url_for('dashboard'))
        db.session.add(Audit(username=username or '(blank)',event='LOGIN_FAILED',at=stamp())); db.session.commit(); flash('Incorrect username or password.','error')
    return render_template('login.html')
@app.route('/logout')
def logout():
    if session.get('username'): db.session.add(Audit(username=session['username'],event='LOGOUT',at=stamp())); db.session.commit()
    session.clear(); return redirect(url_for('login'))
@app.route('/dashboard')
@logged
def dashboard():
    uid=session['uid']; baselines=Baseline.query.filter_by(user_id=uid).order_by(Baseline.id.desc()).all(); checks=Check.query.filter_by(user_id=uid).order_by(Check.id.desc()).limit(10).all()
    return render_template('dashboard.html',baselines=baselines,checks=checks,counts=[len(baselines),Check.query.filter_by(user_id=uid).count(),Check.query.filter_by(user_id=uid,result='MATCH').count(),Check.query.filter_by(user_id=uid,result='MISMATCH').count()])
@app.route('/baseline',methods=['GET','POST'])
@logged
def baseline():
    if request.method=='POST':
        f=request.files.get('file')
        if not f or not f.filename: flash('Choose a file first.','error'); return redirect(url_for('baseline'))
        h,size=digest(f.stream); b=Baseline(user_id=session['uid'],case_id=request.form.get('case_id','').strip(),evidence_id=request.form.get('evidence_id','').strip(),filename=secure_filename(f.filename) or 'file',size=size,sha256=h,created=stamp()); db.session.add(b); db.session.commit(); flash('Baseline saved. SHA-256: '+h,'success'); return redirect(url_for('dashboard'))
    return render_template('baseline.html')
@app.route('/verify',methods=['GET','POST'])
@logged
def verify():
    uid=session['uid']; baselines=Baseline.query.filter_by(user_id=uid).order_by(Baseline.id.desc()).all()
    if request.method=='POST':
        try: bid=int(request.form.get('baseline_id','0'))
        except ValueError: bid=0
        b=Baseline.query.filter_by(id=bid,user_id=uid).first(); f=request.files.get('file')
        if not b or not f or not f.filename: flash('Select a baseline and file.','error'); return redirect(url_for('verify'))
        h,size=digest(f.stream); result='MATCH' if h==b.sha256 else 'MISMATCH'; db.session.add(Check(user_id=uid,baseline_id=b.id,filename=secure_filename(f.filename) or 'file',size=size,sha256=h,result=result,checked=stamp())); db.session.commit(); flash(f'{result}: '+('file matches saved baseline.' if result=='MATCH' else 'file differs from saved baseline.'),'success' if result=='MATCH' else 'error'); return redirect(url_for('dashboard'))
    return render_template('verify.html',baselines=baselines)
@app.route('/duplicates',methods=['GET','POST'])
@logged
def duplicates():
    groups=[]; count=0
    if request.method=='POST':
        files=[f for f in request.files.getlist('files') if f and f.filename]; seen={}; count=len(files)
        for f in files:
            h,size=digest(f.stream); seen.setdefault((size,h),[]).append(secure_filename(f.filename) or 'file')
        groups=[{'size':k[0],'hash':k[1],'names':v} for k,v in seen.items() if len(v)>1]; flash(f'Checked {count} files; found {len(groups)} duplicate group(s).','success')
    return render_template('duplicates.html',groups=groups)
@app.errorhandler(413)
def too_large(e): flash('Upload limit is 20 MB per request in this demo.','error'); return redirect(request.referrer or url_for('dashboard'))
if __name__=='__main__': app.run(debug=True,port=int(os.environ.get('PORT','5000')))
