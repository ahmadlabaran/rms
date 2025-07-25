# RMS Setup Guide

## 🚀 Quick Start (Recommended)

This repository is ready to run immediately with a complete database and sample data.

### Prerequisites
- Python 3.8+ installed on your system
- Git installed

### Step-by-Step Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/ahmadlabaran/rms.git
   cd rms
   ```

2. **Create and activate virtual environment**
   ```bash
   # Create virtual environment
   python -m venv venv
   
   # Activate it
   # On Windows:
   venv\Scripts\activate
   # On Mac/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run migrations (optional - already applied)**
   ```bash
   python manage.py migrate
   ```

5. **Start the server**
   ```bash
   python manage.py runserver
   ```

6. **Access the application**
   Open your browser and go to: `http://127.0.0.1:8000/`

## 🎯 What's Included

- ✅ Complete Django project setup
- ✅ Database with sample data (`rms_database.sqlite3`)
- ✅ All migrations applied
- ✅ Multiple user roles with test accounts
- ✅ REST API endpoints
- ✅ Web interface for all user types

## 🔑 Test Accounts

The database includes test accounts for all roles:
- Super Admin
- Faculty Deans
- HODs (Head of Department)
- Lecturers
- Students
- Exam Officers
- DAAA
- Senate

Check the admin panel or create new accounts as needed.

## 🌐 Available URLs

- **Main Application:** http://127.0.0.1:8000/
- **Admin Panel:** http://127.0.0.1:8000/admin/
- **API Documentation:** http://127.0.0.1:8000/api/external/docs/
- **Login:** http://127.0.0.1:8000/api/login/

## 🛠️ Development

### Project Structure
```
rms/
├── RMS/                    # Django project settings
├── accounts/               # Main application
│   ├── models.py          # Database models
│   ├── views.py           # API views and web interfaces
│   ├── urls.py            # URL routing
│   ├── serializers.py     # API serializers
│   ├── permissions.py     # Role-based permissions
│   └── templates/         # Web interface templates
├── requirements.txt       # Python dependencies
├── manage.py              # Django management script
└── rms_database.sqlite3   # Database with sample data
```

### Key Features
- Multi-role user management
- Result approval workflow
- Permission delegation system
- REST API for external integration
- Comprehensive notification system

## 🔧 Troubleshooting

### Common Issues

1. **Virtual environment activation fails**
   - Make sure you're in the project directory
   - Try using the full path to activate script

2. **Dependencies installation fails**
   - Update pip: `python -m pip install --upgrade pip`
   - Try installing packages individually

3. **Server won't start**
   - Check if port 8000 is available
   - Try a different port: `python manage.py runserver 8080`

### Getting Help

If you encounter issues:
1. Check the Django documentation
2. Review the project documentation in `RMS_PROJECT_DOCUMENTATION.txt`
3. Contact the developer: ahmadlabaran032@gmail.com

## 📝 License

This is an educational project for learning Django and web development.

## 👨‍💻 Author

Ahmad Labaran - Computer Science Student
- GitHub: [@ahmadlabaran](https://github.com/ahmadlabaran)
- Email: ahmadlabaran032@gmail.com
