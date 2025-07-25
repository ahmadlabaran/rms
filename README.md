# RMS - Result Management System

This is a project for managing academic results in a university setting. It's built with Django and includes a web interface for different types of users to manage student grades and academic records. The project also includes a REST API for external integration.

## What This Project Does

This system helps manage student results in a university. Different people have different roles:

- **Students** can view their results
- **Lecturers** can enter grades for their courses
- **HODs** (Head of Department) can approve results for their department
- **Faculty Deans** can manage their entire faculty
- **Exam Officers** handle result processing
- **DAAA** and **Senate** do final approvals
- **Super Admin** manages the whole system

The basic flow is: Lecturer enters grades → Exam Officer checks → HOD approves → Faculty Dean approves → DAAA → Senate → Results published.

## Technical Details

- **Framework:** Django 5.2.4 with Django REST Framework
- **Database:** SQLite (for development)
- **Frontend:** HTML templates with Bootstrap
- **Authentication:** Django's built-in auth system

## 🚀 Quick Start 

You'll need Python installed on your computer.

### 🚀 Quick Setup
This repository includes a complete database with sample data, so you can run it immediately:

```bash
# Clone this repository
git clone https://github.com/ahmadlabaran/rms.git
cd rms

# Create a virtual environment
python -m venv venv

# Activate it (Windows)
venv\Scripts\activate
# Or on Mac/Linux
source venv/bin/activate

# Install required packages
pip install -r requirements.txt

# Run migrations (already applied, but just in case)
python manage.py migrate

# Run the server immediately
python manage.py runserver
```

Then go to `http://127.0.0.1:8000` in your browser.

### 🎯 Ready-to-Use Features
- **Complete database** with all tables and sample data
- **All migrations applied** - no setup needed
- **Multiple user roles** with different dashboards
- **REST API** ready for integration
- **Web interface** for all user types

### 🔑 Test Accounts
The database includes test accounts for all roles:
- Super Admin, Faculty Deans, HODs, Lecturers, Students, etc.
- Check the admin panel or create new accounts as needed

## API Usage

The project includes some REST API endpoints that can be used by other applications:

### Basic Authentication
```http
POST /api/external/authenticate/
{
    "username": "your_username",
    "password": "your_password"
}
```

### Getting Data
```http
GET /api/students/
Authorization: Token your_token_here
```

This is useful if you want to integrate with other systems or build a mobile app.

## Project Structure

```
rms/
├── rms/                    # Django project settings
├── accounts/               # Main application
│   ├── models.py          # Database models
│   ├── views.py           # API views and web interfaces
│   ├── urls.py            # URL routing
│   ├── serializers.py     # API serializers
│   ├── permissions.py     # Role-based permissions
│   └── templates/         # Web interface templates
├── manage.py              # Django management script
```

## Notes

This is a student project for learning Django and web development. It simulates a real university result management system but is built for educational purposes.

The project demonstrates:
- Django web framework usage
- Database design and relationships
- User authentication and permissions
- REST API development
- HTML/CSS frontend development

## Author

Ahmad Labaran - Computer Science Student
- GitHub: [@ahmadlabaran](https://github.com/ahmadlabaran)
- Email: ahmadlabaran032@gmail.com

