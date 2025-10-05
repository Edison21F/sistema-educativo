// Simplified app for testing without database
const express = require('express');
const cors = require('cors');

const app = express();

// Basic middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Set port
app.set('port', process.env.PORT || 3000);

// Test routes
app.get('/', (req, res) => {
    res.json({
        message: 'Authentication API Server is running!',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        endpoints: {
            auth: {
                login: 'POST /auth/api/login',
                register: 'POST /auth/register/{userType}',
                profile: 'GET /auth/api/profile',
                logout: 'POST /auth/api/logout'
            }
        }
    });
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage()
    });
});

// Authentication endpoints documentation
app.get('/auth', (req, res) => {
    res.json({
        message: 'Authentication API Endpoints',
        endpoints: [
            {
                method: 'POST',
                path: '/auth/api/login',
                description: 'Login with username, password, and userType',
                body: {
                    username: 'string',
                    password: 'string',
                    userType: 'teacher | student | admin'
                }
            },
            {
                method: 'POST',
                path: '/auth/register/student',
                description: 'Register new student'
            },
            {
                method: 'POST', 
                path: '/auth/register/teacher',
                description: 'Register new teacher'
            },
            {
                method: 'GET',
                path: '/auth/api/profile',
                description: 'Get authenticated user profile'
            },
            {
                method: 'POST',
                path: '/auth/api/logout',
                description: 'Logout current user'
            }
        ],
        sampleUsers: {
            admin: { username: 'superadmin', password: 'Admin123!' },
            teacher: { username: 'maria.teacher', password: 'Teacher123!' },
            student: { username: 'juan.student', password: 'Student123!' }
        }
    });
});

// Test authentication endpoint (without database)
app.post('/auth/test-login', (req, res) => {
    const { username, password, userType } = req.body;
    
    if (!username || !password || !userType) {
        return res.status(400).json({
            success: false,
            message: 'Username, password, and userType are required'
        });
    }
    
    // Mock authentication for testing
    const testUsers = {
        'superadmin': { password: 'Admin123!', type: 'admin', role: 'super_admin' },
        'maria.teacher': { password: 'Teacher123!', type: 'teacher', role: 'teacher' },
        'juan.student': { password: 'Student123!', type: 'student', role: 'student' }
    };
    
    const user = testUsers[username];
    
    if (!user || user.password !== password || user.type !== userType) {
        return res.status(401).json({
            success: false,
            message: 'Invalid credentials'
        });
    }
    
    return res.json({
        success: true,
        message: 'Login successful (TEST MODE)',
        data: {
            username,
            userType,
            role: user.role,
            authenticated: true
        }
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        message: `${req.method} ${req.path} is not available`,
        availableEndpoints: ['/', '/health', '/auth', '/auth/test-login']
    });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({
        error: 'Internal server error',
        message: err.message || 'Something went wrong'
    });
});

module.exports = app;