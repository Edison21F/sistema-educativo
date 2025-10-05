# Authentication API Test Endpoints

## Sample Users
After running the createSampleUsers script, you can use these credentials:

- **Super Admin**: `superadmin` / `Admin123!`
- **Teacher**: `maria.teacher` / `Teacher123!`
- **Student**: `juan.student` / `Student123!`

## Test Endpoints

### 1. API Login
```bash
# Test Super Admin Login
curl -X POST http://localhost:3000/auth/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "superadmin",
    "password": "Admin123!",
    "userType": "admin"
  }' \
  -c cookies.txt

# Test Teacher Login
curl -X POST http://localhost:3000/auth/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "maria.teacher",
    "password": "Teacher123!",
    "userType": "teacher"
  }' \
  -c cookies.txt

# Test Student Login
curl -X POST http://localhost:3000/auth/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "juan.student",
    "password": "Student123!",
    "userType": "student"
  }' \
  -c cookies.txt
```

### 2. Check Authentication Status
```bash
curl -X GET http://localhost:3000/auth/api/auth-status \
  -b cookies.txt
```

### 3. Get User Profile
```bash
curl -X GET http://localhost:3000/auth/api/profile \
  -b cookies.txt
```

### 4. Update Profile
```bash
# Update Teacher Profile
curl -X PUT http://localhost:3000/auth/api/profile \
  -H "Content-Type: application/json" \
  -d '{
    "completeNmeTeacher": "María Elena Rodríguez",
    "emailTeacher": "maria.elena@educativo.com",
    "phoneTeacher": "+0987654322",
    "specialization": "Matemáticas Avanzadas",
    "experience": 6
  }' \
  -b cookies.txt
```

### 5. Change Password
```bash
curl -X POST http://localhost:3000/auth/api/change-password \
  -H "Content-Type: application/json" \
  -d '{
    "currentPassword": "Teacher123!",
    "newPassword": "NewTeacher456!",
    "confirmPassword": "NewTeacher456!"
  }' \
  -b cookies.txt
```

### 6. Get Users (Admin only)
```bash
# Get all teachers
curl -X GET http://localhost:3000/auth/api/users/teachers \
  -b cookies.txt

# Get all students with pagination and search
curl -X GET "http://localhost:3000/auth/api/users/students?page=1&limit=5&search=juan&status=active" \
  -b cookies.txt

# Get all admins
curl -X GET http://localhost:3000/auth/api/users/admins \
  -b cookies.txt
```

### 7. Update User Status (Admin only)
```bash
# Activate a student
curl -X PATCH http://localhost:3000/auth/api/users/students/1/status \
  -H "Content-Type: application/json" \
  -d '{
    "status": "active"
  }' \
  -b cookies.txt

# Suspend a teacher
curl -X PATCH http://localhost:3000/auth/api/users/teachers/1/status \
  -H "Content-Type: application/json" \
  -d '{
    "status": "suspended"
  }' \
  -b cookies.txt
```

### 8. Student Registration
```bash
curl -X POST http://localhost:3000/auth/register/student \
  -H "Content-Type: application/json" \
  -d '{
    "username": "ana.student",
    "password": "Student123!",
    "identificationCard": "55667788",
    "completeNameEstudent": "Ana García",
    "emailEstudent": "ana.garcia@estudiante.com",
    "celularEstudent": "+5566778899",
    "ubicacion": "Guayaquil, Ecuador",
    "grade": "9no Grado",
    "guardianName": "Luis García",
    "guardianPhone": "+5566778800"
  }'
```

### 9. Teacher Registration
```bash
curl -X POST http://localhost:3000/auth/register/teacher \
  -H "Content-Type: application/json" \
  -d '{
    "username": "carlos.teacher",
    "password": "Teacher123!",
    "identificationCard": "99887766",
    "completeNmeTeacher": "Carlos Mendoza",
    "emailTeacher": "carlos.mendoza@educativo.com",
    "phoneTeacher": "+9988776655",
    "specialization": "Ciencias Naturales",
    "experience": 3
  }'
```

### 10. Admin Registration (Super Admin only)
```bash
# First login as super admin, then:
curl -X POST http://localhost:3000/auth/register/admin \
  -H "Content-Type: application/json" \
  -d '{
    "username": "director.admin",
    "password": "Director123!",
    "identificationCard": "33445566",
    "completeNameAdmin": "Director Educativo",
    "emailAdmin": "director@educativo.com",
    "phoneAdmin": "+3344556677",
    "department": "Dirección Académica",
    "rolAdmin": "director",
    "permissions": {
      "user_management": true,
      "reports": true
    }
  }' \
  -b cookies.txt
```

### 11. Logout
```bash
curl -X POST http://localhost:3000/auth/api/logout \
  -b cookies.txt
```

## Error Testing

### Invalid Login Credentials
```bash
curl -X POST http://localhost:3000/auth/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "invalid",
    "password": "wrong",
    "userType": "student"
  }'
```

### Access Protected Resource Without Auth
```bash
curl -X GET http://localhost:3000/auth/api/profile
```

### Student Trying to Access Admin Endpoint
```bash
# Login as student first, then:
curl -X GET http://localhost:3000/auth/api/users/teachers \
  -b cookies.txt
```