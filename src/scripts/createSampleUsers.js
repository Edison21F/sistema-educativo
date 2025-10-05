const orm = require('../Database/dataBase.orm');
const { hashPassword, cifrarDatos } = require('../lib/encrypDates');

async function createSampleUsers() {
    try {
        console.log('Creating sample users...');

        // Crear un administrador de muestra
        const adminPassword = await hashPassword('Admin123!');
        const sampleAdmin = await orm.administrator.create({
            identificationCardAdmin: cifrarDatos('12345678'),
            completeNameAdmin: cifrarDatos('Super Administrador'),
            emailAdmin: cifrarDatos('admin@educativo.com'),
            phoneAdmin: cifrarDatos('+1234567890'),
            usernameAdmin: 'superadmin',
            passwordAdmin: adminPassword,
            rolAdmin: 'super_admin',
            stateAdmin: 'active',
            department: 'Administración',
            permissions: {
                user_management: true,
                system_config: true,
                reports: true,
                backup: true
            },
            createAdmin: new Date().toLocaleString()
        });
        console.log('✓ Super Admin created:', sampleAdmin.usernameAdmin);

        // Crear un profesor de muestra
        const teacherPassword = await hashPassword('Teacher123!');
        const sampleTeacher = await orm.teacher.create({
            identificationCardTeacher: cifrarDatos('87654321'),
            completeNmeTeacher: cifrarDatos('María Rodríguez'),
            emailTeacher: cifrarDatos('maria.rodriguez@educativo.com'),
            phoneTeacher: cifrarDatos('+0987654321'),
            usernameTeahcer: 'maria.teacher',
            passwordTeacher: teacherPassword,
            specialization: 'Matemáticas',
            experience: 5,
            rolTeacher: 'teacher',
            stateTeacher: 'active',
            createTeahcer: new Date().toLocaleString()
        });
        console.log('✓ Teacher created:', sampleTeacher.usernameTeahcer);

        // Crear un estudiante de muestra
        const studentPassword = await hashPassword('Student123!');
        const sampleStudent = await orm.student.create({
            identificationCardStudent: cifrarDatos('11223344'),
            completeNameEstudent: cifrarDatos('Juan Pérez'),
            emailEstudent: cifrarDatos('juan.perez@estudiante.com'),
            celularEstudent: cifrarDatos('+1122334455'),
            usernameEstudent: 'juan.student',
            passwordEstudent: studentPassword,
            ubicationStudent: 'Quito, Ecuador',
            grade: '10mo Grado',
            guardianName: cifrarDatos('Carlos Pérez'),
            guardianPhone: cifrarDatos('+1122334456'),
            rolStudent: 'student',
            stateEstudent: 'active',
            enrollmentDate: new Date(),
            createStudent: new Date().toLocaleString()
        });
        console.log('✓ Student created:', sampleStudent.usernameEstudent);

        console.log('\n=== SAMPLE USERS CREATED ===');
        console.log('Super Admin - Username: superadmin, Password: Admin123!');
        console.log('Teacher - Username: maria.teacher, Password: Teacher123!');
        console.log('Student - Username: juan.student, Password: Student123!');
        console.log('================================');

        process.exit(0);

    } catch (error) {
        console.error('Error creating sample users:', error);
        process.exit(1);
    }
}

// Ejecutar si se llama directamente
if (require.main === module) {
    createSampleUsers();
}

module.exports = createSampleUsers;