# RMS Universal API Integration Guide

## Overview
The RMS (Result Management System) provides a **universal REST API** that can integrate with **ANY existing website** regardless of technology stack (PHP, Node.js, Python, Java, .NET, etc.).

## Quick Start

### 1. Authentication
First, authenticate your existing website users with RMS:

```http
POST /api/external/authenticate/
Content-Type: application/json

{
    "username": "user123",
    "password": "password123"
}
```

**Response:**
```json
{
    "status": "success",
    "data": {
        "token": "abc123def456...",
        "user": {
            "id": 1,
            "username": "user123",
            "email": "user@school.edu",
            "roles": [...]
        },
        "expires_in": 86400,
        "api_base_url": "http://localhost:8000/api/"
    }
}
```

### 2. Use the Token
Include the token in all subsequent API requests:

```http
GET /api/students/
Authorization: Token abc123def456...
```

## Integration Examples

### PHP Integration
```php
<?php
// 1. Authenticate user with RMS
function authenticateWithRMS($username, $password) {
    $data = json_encode([
        'username' => $username,
        'password' => $password
    ]);
    
    $ch = curl_init('http://localhost:8000/api/external/authenticate/');
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($response, true);
}

// 2. Make API calls
function getRMSData($endpoint, $token) {
    $ch = curl_init("http://localhost:8000/api/$endpoint/");
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Authorization: Token $token",
        "Content-Type: application/json"
    ]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($response, true);
}

// Usage in your PHP website
session_start();
if ($_POST['login']) {
    $rms_auth = authenticateWithRMS($_POST['username'], $_POST['password']);
    if ($rms_auth['status'] === 'success') {
        $_SESSION['rms_token'] = $rms_auth['data']['token'];
        $_SESSION['user_data'] = $rms_auth['data']['user'];
        // User is now logged into both systems
    }
}

// Get student results
if (isset($_SESSION['rms_token'])) {
    $students = getRMSData('students', $_SESSION['rms_token']);
    $results = getRMSData('results', $_SESSION['rms_token']);
}
?>
```

### JavaScript/Node.js Integration
```javascript
// 1. Authenticate with RMS
async function authenticateWithRMS(username, password) {
    const response = await fetch('http://localhost:8000/api/external/authenticate/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password })
    });
    
    return await response.json();
}

// 2. Make authenticated API calls
async function callRMSAPI(endpoint, token, method = 'GET', data = null) {
    const options = {
        method,
        headers: {
            'Authorization': `Token ${token}`,
            'Content-Type': 'application/json'
        }
    };
    
    if (data) {
        options.body = JSON.stringify(data);
    }
    
    const response = await fetch(`http://localhost:8000/api/${endpoint}/`, options);
    return await response.json();
}

// Usage in your website
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    const auth = await authenticateWithRMS(username, password);
    
    if (auth.status === 'success') {
        localStorage.setItem('rms_token', auth.data.token);
        localStorage.setItem('user_data', JSON.stringify(auth.data.user));
        
        // Load RMS data
        const students = await callRMSAPI('students', auth.data.token);
        displayStudents(students.data);
    }
});
```

### Python Integration
```python
import requests
import json

class RMSIntegration:
    def __init__(self, base_url="http://localhost:8000/api/"):
        self.base_url = base_url
        self.token = None
    
    def authenticate(self, username, password):
        response = requests.post(
            f"{self.base_url}external/authenticate/",
            json={"username": username, "password": password}
        )
        
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                self.token = data['data']['token']
                return data['data']['user']
        return None
    
    def api_call(self, endpoint, method='GET', data=None):
        headers = {
            'Authorization': f'Token {self.token}',
            'Content-Type': 'application/json'
        }
        
        url = f"{self.base_url}{endpoint}/"
        
        if method == 'GET':
            response = requests.get(url, headers=headers)
        elif method == 'POST':
            response = requests.post(url, headers=headers, json=data)
        
        return response.json()

# Usage
rms = RMSIntegration()
user = rms.authenticate('username', 'password')

if user:
    students = rms.api_call('students')
    faculties = rms.api_call('faculties')
```

## Available Endpoints

### Authentication
- `POST /api/external/authenticate/` - Get API token
- `GET /api/external/validate/` - Validate token
- `POST /api/external/revoke/` - Revoke token
- `GET /api/external/docs/` - API documentation

### Academic Structure
- `GET /api/sessions/` - Academic sessions
- `GET /api/faculties/` - Faculties
- `GET /api/departments/` - Departments
- `GET /api/levels/` - Academic levels
- `GET /api/courses/` - Courses

### User Management
- `GET /api/students/` - Students (with search)
- `GET /api/users/` - Users (Super Admin only)

### Results Management (Coming Soon)
- `GET /api/results/` - Student results
- `POST /api/results/` - Create/update results
- `GET /api/transcripts/` - Generate transcripts

## Response Format
All API responses follow this format:

**Success:**
```json
{
    "status": "success",
    "data": { ... },
    "message": "Optional success message"
}
```

**Error:**
```json
{
    "status": "error",
    "message": "Error description",
    "errors": { ... }
}
```

## Rate Limits
- **Anonymous users**: 100 requests per hour
- **Authenticated users**: 1000 requests per hour

## Security Best Practices
1. **Store tokens securely** (server-side sessions, not localStorage for sensitive data)
2. **Use HTTPS** in production
3. **Validate tokens** before making API calls
4. **Revoke tokens** when users logout
5. **Handle token expiration** gracefully

## Error Handling
```javascript
async function safeAPICall(endpoint, token) {
    try {
        const response = await callRMSAPI(endpoint, token);
        
        if (response.status === 'error') {
            if (response.message.includes('Invalid token')) {
                // Token expired, re-authenticate
                redirectToLogin();
            } else {
                showError(response.message);
            }
        }
        
        return response.data;
    } catch (error) {
        console.error('API call failed:', error);
        showError('Connection failed. Please try again.');
    }
}
```

## Next Steps
1. **Test the API** using the browsable interface at `http://localhost:8000/api/`
2. **Create a superuser** to test authentication
3. **Add sample data** (faculties, departments, students)
4. **Integrate with your existing website** using the examples above
5. **Implement result management** features as needed

## Support
For integration support or custom endpoints, refer to the API documentation at `/api/external/docs/`
