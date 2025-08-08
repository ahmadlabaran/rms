# RMS - Result Management System

A comprehensive web application designed for managing student results in universities. The system provides a digital implementation of academic result processing and approval workflows commonly used in Nigerian universities.

## Overview

The system manages the complete lifecycle of student grade processing, from initial score entry by lecturers through multiple approval stages to final result publication.

**User Roles and Permissions:**
- **Students** can view their results and download PDF transcripts
- **Lecturers** enter CA and exam scores for assigned courses
- **Exam Officers** handle result processing and validation
- **Faculty Deans** approve results for their entire faculty
- **DAAA** (Deputy Academic Affairs) provides final approval before publication
- **Senate** has ultimate authority to approve results for publication
- **HODs** (Head of Department) manage courses and lecturers but are not in the approval workflow
- **Super Admin** manages users and system settings

**Result Approval Workflow:**
Lecturer enters grades → Exam Officer processes → Faculty Dean approves → DAAA approves → Results published

Note: HODs have administrative functions for department management but are not part of the result approval chain.

The system enforces sequential approval, ensuring results cannot be published without completing all required approval stages.
## Key Features

**Student Features:**
- View results by academic session and level
- Download PDF transcripts
- Track CGPA and academic progress
- Submit complaints about results

**Lecturer Features:**
- Enter CA and exam scores for assigned courses
- Automatic total score calculation
- Bulk upload results via CSV
- View teaching assignments and course enrollments

**Administrative Features:**
- Multi-level approval workflow
- Bulk approval and rejection capabilities
- Comprehensive result history tracking
- Advanced filtering and search capabilities
- Duplicate prevention for result publication
- Real-time status tracking

## Technical Stack

The application is built using:
- **Django 5.2.5** - Web framework and backend
- **Django REST Framework** - API endpoints
- **SQLite** - Database (suitable for development)
- **Bootstrap** - Frontend styling and responsive design
- **ReportLab** - PDF generation for transcripts

## Getting Started

Python 3.8 or higher is required to run this application.

### Quick Setup
The repository includes a complete database with sample data, allowing immediate execution without additional setup:

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

# Run database migrations (may already be applied)
python manage.py migrate

# Start the development server
python manage.py runserver
```

Open a web browser and navigate to `http://127.0.0.1:8000`

### Included Features
- Complete database with sample data pre-loaded
- Test accounts for all user roles
- All database tables and relationships configured
- Functional web interface for every user type
- REST API endpoints ready for use

### Test Accounts
The repository includes test accounts for all user roles. Users can:
- Access the Django admin panel to view existing accounts
- Create new accounts through the super admin interface
- Use the existing sample data to test different workflows

## Project Structure

```
rms/
├── rms/                    # Django project configuration
├── accounts/               # Main application module
│   ├── models.py          # Database models (Student, Course, Result, etc.)
│   ├── views.py           # Views for web pages and API endpoints
│   ├── urls.py            # URL patterns and routing configuration
│   ├── serializers.py     # API serializers for JSON responses
│   ├── permissions.py     # Role-based access control
│   ├── templates/         # HTML templates for web interface
│   └── workflow_service.py # Business logic for result approval workflow
├── manage.py              # Django management command-line utility
└── requirements.txt       # Python package dependencies
```

### Technologies Demonstrated
- Django framework and web application architecture
- Database design with proper relational models
- User authentication and role-based permission systems
- REST API development with Django REST Framework
- Frontend development using HTML, CSS, and Bootstrap
- PDF generation for official transcripts
- Workflow management and business logic implementation

The system addresses real-world requirements including duplicate publication prevention, comprehensive approval history tracking, and proper authorization enforcement at each workflow stage.

## Repository Information

**Repository:** https://github.com/ahmadlabaran/rms.git
**Author:** Ahmad Labaran
**Contact:** ahmadlabaran032@gmail.com

