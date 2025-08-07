# RMS - Result Management System

This is a web application built for managing student results in universities. It's basically a digital version of how academic results are processed and approved in Nigerian universities.

## What This Does

The system handles the entire process of managing student grades from when lecturers enter scores to when results are finally published. 

**Different user types have different permissions:**
- **Students** can view their results and download PDF copies
- **Lecturers** enter CA and exam scores for their courses
- **Exam Officers** handle result processing and validation
- **Faculty Deans** approve results for their entire faculty
- **DAAA** (Deputy Academic Affairs) does final approval before publication
- **Senate** has the ultimate authority to approve results
- **HODs** (Head of Department) manage courses and lecturers but are not in the approval chain
- **Super Admin** manages users and system settings

**The approval flow goes like this:**
Lecturer enters grades → Exam Officer processes → Faculty Dean approves → DAAA approves → Senate approves → Results get published

Note: HODs have administrative functions for managing their departments but are not part of the result approval workflow.

Each step has to be completed before moving to the next one, which prevents results from being published without proper approval.
## Main Features

**For Students:**
- View results by academic session and level
- Download PDF transcripts
- Track CGPA and academic progress
- Submit complaints about results

**For Lecturers:**
- Enter CA and exam scores for assigned courses
- Automatic total score calculation
- Bulk upload results via CSV
- View teaching assignments and course enrollments

**For Administrators:**
- Multi-level approval workflow
- Bulk approval and rejection
- Comprehensive result history tracking
- Advanced filtering and search capabilities
- Duplicate prevention for result publication
- Real-time status tracking

## Technical Stuff

- **Django 5.2.4** for the backend
- **Django REST Framework** for API endpoints
- **SQLite** database (easy for development)
- **Bootstrap** for the frontend styling
- **ReportLab** for PDF generation

## Getting Started

You need Python installed on your computer first.

### Quick Setup
The good news is I've included a complete database with sample data, so you can run this right away without setting up anything:

```bash
# Clone the repository
git clone https://github.com/ahmadlabaran/rms.git
cd rms

# Set up virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run database migrations (probably already done, but just in case)
python manage.py migrate

# Start the development server
python manage.py runserver
```

Open your browser and go to `http://127.0.0.1:8000`

### What You Get Out of the Box
- Complete database with sample data already loaded
- Test accounts for all user roles
- All database tables and relationships set up
- Working web interface for every user type
- REST API endpoints ready to use

### Test Accounts
I've created test accounts for all the different roles. You can either:
- Check the Django admin panel to see existing accounts
- Create new accounts through the super admin interface
- Use the existing sample data to test different workflows

## API Endpoints

I also built some REST API endpoints if you want to integrate this with other systems or maybe build a mobile app:

### Authentication
```http
POST /api/external/authenticate/
{
    "username": "your_username",
    "password": "your_password"
}
```

### Getting Student Data
```http
GET /api/students/
Authorization: Token your_token_here
```

The API uses token-based authentication and returns JSON responses.

## How the Code is Organized

```
rms/
├── rms/                    # Main Django project settings
├── accounts/               # The main app where everything happens
│   ├── models.py          # Database models (Student, Course, Result, etc.)
│   ├── views.py           # All the views for web pages and API
│   ├── urls.py            # URL patterns and routing
│   ├── serializers.py     # API serializers for JSON responses
│   ├── permissions.py     # Role-based access control
│   ├── templates/         # HTML templates for the web interface
│   └── workflow_service.py # Business logic for result approval workflow
├── manage.py              # Django's command-line utility
└── requirements.txt       # Python dependencies
```

## About This Project

I built this as a learning project while studying computer science. It's based on how result management actually works in Nigerian universities, but I designed it to be flexible enough for other institutions too.

What I learned building this:
- Django framework and how to structure a real web application
- Database design with proper relationships between models
- User authentication and role-based permissions
- Building REST APIs with Django REST Framework
- Frontend development with HTML, CSS, and Bootstrap
- PDF generation for result transcripts
- Workflow management and business logic implementation

The system handles real-world scenarios like preventing duplicate publications, maintaining approval history, and ensuring proper authorization at each step.

## Contact

Ahmad Labaran
Computer Science Student
GitHub: [@ahmadlabaran](https://github.com/ahmadlabaran)
Email: ahmadlabaran032@gmail.com

