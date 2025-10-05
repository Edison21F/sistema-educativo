const app = require('./app.simple');

const port = app.get('port');
app.listen(port, () => {
    console.log(`✓ Simple Authentication API Server running on port ${port}`);
    console.log(`✓ Health check: http://localhost:${port}/health`);
    console.log(`✓ API docs: http://localhost:${port}/auth`);
    console.log(`✓ Test login: POST http://localhost:${port}/auth/test-login`);
});