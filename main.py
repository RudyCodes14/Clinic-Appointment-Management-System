import os
import shutil
from datetime import datetime, timedelta, timezone
from typing import Optional
import bcrypt
import jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import FastAPI, Request, Form, Depends, HTTPException, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, String, select, DateTime, ForeignKey, Integer
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    sessionmaker,
    Session,
    relationship
)

# ==========================================
# SECURITY & JWT CONFIGURATION
# ==========================================
SECRET_KEY = "my_super_secret_key_for_development"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

UPLOAD_DIR = "Frontend/static/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8')[:72], hashed_password.encode('utf-8'))

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8')[:72], bcrypt.gensalt()).decode('utf-8')

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ==========================================
# DATABASE SETUP (Clinic Domain Models)
# ==========================================
engine = create_engine("sqlite:///clinic_management.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50))
    email: Mapped[str] = mapped_column(String(50), unique=True)
    hashed_password: Mapped[str] = mapped_column(String(100))
    role: Mapped[str] = mapped_column(String(20), default="patient") # patient, doctor, staff

    appointments: Mapped[list["Appointment"]] = relationship(back_populates="patient")

class Appointment(Base):
    __tablename__ = "appointments"
    id: Mapped[int] = mapped_column(primary_key=True)
    patient_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    doctor_name: Mapped[str] = mapped_column(String(50))
    appointment_date: Mapped[str] = mapped_column(String(30))  # Format: YYYY-MM-DDTHH:MM
    status: Mapped[str] = mapped_column(String(20), default="Scheduled") # Scheduled, Completed, Cancelled
    symptoms: Mapped[str] = mapped_column(String(500))
    
    patient: Mapped["User"] = relationship(back_populates="appointments")
    medical_records: Mapped[list["MedicalRecord"]] = relationship(back_populates="appointment", cascade="all, delete-orphan")

class MedicalRecord(Base):
    __tablename__ = "medical_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    appointment_id: Mapped[int] = mapped_column(ForeignKey("appointments.id"))
    diagnosis: Mapped[str] = mapped_column(String(1000))
    prescription: Mapped[str] = mapped_column(String(1000))
    attachment_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    appointment: Mapped["Appointment"] = relationship(back_populates="medical_records")

Base.metadata.create_all(bind=engine)


# ==========================================
# FASTAPI SETUP & DEPENDENCIES
# ==========================================
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/login", auto_error=False)
app.mount("/static", StaticFiles(directory="Frontend/static"), name="static")
templates = Jinja2Templates(directory="Frontend")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
    except jwt.InvalidTokenError:
        return None
    
    return db.scalars(select(User).where(User.email == email)).first()


# ==========================================
# AUTHENTICATION ROUTES
# ==========================================

@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    return templates.TemplateResponse(request=request, name="signup.html")

@app.post("/signup")
def signup_post(
    request: Request, 
    name: str = Form(...), 
    email: str = Form(...), 
    password: str = Form(...), 
    role: str = Form("patient"),
    db: Session = Depends(get_db)
):
    existing_user = db.scalars(select(User).where(User.email == email)).first()
    if existing_user:
        return templates.TemplateResponse(request=request, name="signup.html", context={"error": "Email already registered."})
    
    new_user = User(name=name, email=email, hashed_password=get_password_hash(password), role=role)
    db.add(new_user)
    db.commit()
    
    access_token = create_access_token(data={"sub": new_user.email})
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html")

@app.post("/login")
def login_post(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.scalars(select(User).where(User.email == email)).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(request=request, name="login.html", context={"error": "Invalid email or password."})
    
    access_token = create_access_token(data={"sub": user.email})
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response


# ==========================================
# CORE CLINIC APPOINTMENT MANAGEMENT ROUTES
# ==========================================

@app.get("/")
def home():
    return RedirectResponse(url="/dashboard", status_code=303)

# 1. INDEX: Dashboard View (Lists appointments cleanly to prevent double bookings)
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_index(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
        
    if current_user.role in ["doctor", "staff"]:
        appointments = db.scalars(select(Appointment).order_by(Appointment.appointment_date.asc())).all()
    else:
        appointments = db.scalars(select(Appointment).where(Appointment.patient_id == current_user.id).order_by(Appointment.appointment_date.asc())).all()
        
    return templates.TemplateResponse(
        request=request, 
        name="index.html", 
        context={"appointments": appointments, "current_user": current_user}
    )

# 2. CREATE: Book an Appointment
@app.get("/appointment/book", response_class=HTMLResponse)
def appointment_create_page(request: Request, current_user: User = Depends(get_current_user)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request=request, name="create.html", context={"current_user": current_user})

@app.post("/appointment/book")
def create_appointment(
    doctor_name: str = Form(...),
    appointment_date: str = Form(...),
    symptoms: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    
    # Conflict prevention: check if doctor is already booked at that exact hour timeframe
    conflict = db.scalars(
        select(Appointment).where(
            Appointment.doctor_name == doctor_name, 
            Appointment.appointment_date == appointment_date,
            Appointment.status == "Scheduled"
        )
    ).first()
    
    if conflict:
        return templates.TemplateResponse(
            request=None, # Fast API fall back
            name="create.html", 
            context={"error": f"Doctor {doctor_name} is already booked at this timeframe. Please choose another hour.", "current_user": current_user}
        )

    new_appt = Appointment(
        patient_id=current_user.id,
        doctor_name=doctor_name,
        appointment_date=appointment_date,
        symptoms=symptoms
    )
    db.add(new_appt)
    db.commit()
    return RedirectResponse(url="/dashboard", status_code=303)

# 3. DETAIL: View Appointment & Its Medical Record Data
@app.get("/appointment/{appt_id}", response_class=HTMLResponse)
def appointment_detail(appt_id: int, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
        
    appt = db.get(Appointment, appt_id)
    if not appt:
        raise HTTPException(status_code=404, detail="Appointment data not found")
        
    record = db.scalars(select(MedicalRecord).where(MedicalRecord.appointment_id == appt_id)).first()
    return templates.TemplateResponse(
        request=request, 
        name="detail.html", 
        context={"appointment": appt, "record": record, "current_user": current_user}
    )

# 4. UPDATE: Modify Status / Add Medical Records (Doctors/Staff Roles)
@app.get("/appointment/update/{appt_id}", response_class=HTMLResponse)
def appointment_update_page(appt_id: int, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user or current_user.role not in ["doctor", "staff"]:
        return RedirectResponse(url="/dashboard", status_code=303)
        
    appt = db.get(Appointment, appt_id)
    record = db.scalars(select(MedicalRecord).where(MedicalRecord.appointment_id == appt_id)).first()
    return templates.TemplateResponse(
        request=request, 
        name="update.html", 
        context={"appointment": appt, "record": record, "current_user": current_user}
    )

@app.post("/appointment/update/{appt_id}")
async def update_appointment_record(
    appt_id: int,
    status: str = Form(...),
    diagnosis: str = Form(""),
    prescription: str = Form(""),
    file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user or current_user.role not in ["doctor", "staff"]:
        return RedirectResponse(url="/login", status_code=303)
        
    appt = db.get(Appointment, appt_id)
    if not appt:
        raise HTTPException(status_code=404, detail="Appointment not found")
        
    appt.status = status
    
    # Check or create medical record information
    record = db.scalars(select(MedicalRecord).where(MedicalRecord.appointment_id == appt_id)).first()
    if not record:
        record = MedicalRecord(appointment_id=appt_id, diagnosis=diagnosis, prescription=prescription)
        db.add(record)
    else:
        record.diagnosis = diagnosis
        record.prescription = prescription

    if file and file.filename:
        file_ext = os.path.splitext(file.filename)[1]
        filename = f"rec_{appt_id}_{int(datetime.now().timestamp())}{file_ext}"
        filepath = os.path.join(UPLOAD_DIR, filename)
        with open(filepath, "wb") as buf:
            shutil.copyfileobj(file.file, buf)
        record.attachment_path = f"uploads/{filename}"

    db.commit()
    return RedirectResponse(url=f"/appointment/{appt_id}", status_code=303)

# 5. DELETE / CANCEL Route
@app.post("/appointment/cancel/{appt_id}")
def cancel_appointment(appt_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
        
    appt = db.get(Appointment, appt_id)
    if appt:
        appt.status = "Cancelled"
        db.commit()
    return RedirectResponse(url="/dashboard", status_code=303)