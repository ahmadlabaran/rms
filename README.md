# RMS - Result Management System

This is a student project for managing academic results in a university setting. It's built with Django and includes a web interface for different types of users to manage student grades and academic records.

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

## What's Built So Far

- Database models for students, courses, results, etc.
- Web pages for different user types
- Login system with different permissions
- Grade calculation (CA + Exam = Total grade)
- Basic approval workflow
- Some API endpoints for external access

## Technical Details

- **Framework:** Django 5.2.4 with Django REST Framework
- **Database:** SQLite (for development)
- **Frontend:** HTML templates with Bootstrap
- **Authentication:** Django's built-in auth system

## How to Run This Project

You'll need Python installed on your computer.

### Setup Steps
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
pip install django djangorestframework django-cors-headers

# Set up the database
python manage.py migrate

# Run the server
python manage.py runserver
```

Then go to `http://127.0.0.1:8000` in your browser.

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

