const orm = require('../Database/dataBase.orm');
const { cifrarDatos, hashPassword } = require('../lib/encrypDates');

const userSeeder = async () => {
    try {
        console.log('Starting user seeder...');

        // ==================== CREATE TEST ADMIN ====================
        const adminExists = await orm.administrator.findOne({
            where: { usernameAdmin: 'admin' }
        });

        if (!adminExists) {
            const adminPassword = await hashPassword('Admin123!');
            
            await orm.administrator.create({
                identificationCardAdmin: cifrarDatos('12345678'),
                completeNameAdmin: cifrarDatos('Administrator System'),
                emailAdmin: cifrarDatos('admin@sistema.com'),
                phoneAdmin: cifrarDatos('+1234567890'),
                usernameAdmin: 'admin',
                passwordAdmin: adminPassword,
                rolAdmin: 'super_admin',
                stateAdmin: 'active',
                department: 'IT',
                permissions: {
                    users: true,
                    reports: true,
                    settings: true,
                    audit: true
                },
                createAdmin: new Date().toLocaleString()
            });
            console.log('✅ Test admin created - Username: admin, Password: Admin123!');
        } else {
            console.log('ℹ️ Test admin already exists');
        }

        // ==================== CREATE TEST TEACHER ====================
        const teacherExists = await orm.teacher.findOne({
            where: { usernameTeahcer: 'teacher' }
        });

        if (!teacherExists) {
            const teacherPassword = await hashPassword('Teacher123!');
            
            await orm.teacher.create({
                identificationCardTeacher: cifrarDatos('87654321'),
                completeNmeTeacher: cifrarDatos('Maria Garcia Lopez'),
                emailTeacher: cifrarDatos('teacher@sistema.com'),
                phoneTeacher: cifrarDatos('+1234567891'),
                usernameTeahcer: 'teacher',
                passwordTeacher: teacherPassword,
                rolTeacher: 'teacher',
                stateTeacher: 'active',
                specialization: 'Mathematics',
                experience: 5,
                createTeahcer: new Date().toLocaleString()
            });
            console.log('✅ Test teacher created - Username: teacher, Password: Teacher123!');
        } else {
            console.log('ℹ️ Test teacher already exists');
        }

        // ==================== CREATE TEST STUDENT ====================
        const studentExists = await orm.student.findOne({
            where: { usernameEstudent: 'student' }
        });

        if (!studentExists) {
            const studentPassword = await hashPassword('Student123!');
            
            await orm.student.create({
                identificationCardStudent: cifrarDatos('11223344'),
                completeNameEstudent: cifrarDatos('Juan Perez Martinez'),
                emailEstudent: cifrarDatos('student@sistema.com'),
                celularEstudent: cifrarDatos('+1234567892'),
                usernameEstudent: 'student',
                passwordEstudent: studentPassword,
                rolStudent: 'student',
                stateEstudent: 'active',
                ubicationStudent: 'Ciudad Principal',
                grade: '10th Grade',
                guardianName: cifrarDatos('Carlos Perez'),
                guardianPhone: cifrarDatos('+1234567893'),
                enrollmentDate: new Date(),
                createStudent: new Date().toLocaleString()
            });
            console.log('✅ Test student created - Username: student, Password: Student123!');
        } else {
            console.log('ℹ️ Test student already exists');
        }

        // ==================== CREATE ADDITIONAL TEST USERS ====================
        
        // Create pending teacher for testing approval workflows
        const pendingTeacherExists = await orm.teacher.findOne({
            where: { usernameTeahcer: 'teacher_pending' }
        });

        if (!pendingTeacherExists) {
            const pendingTeacherPassword = await hashPassword('TeacherPending123!');
            
            await orm.teacher.create({
                identificationCardTeacher: cifrarDatos('99887766'),
                completeNmeTeacher: cifrarDatos('Ana Sofia Rodriguez'),
                emailTeacher: cifrarDatos('teacher_pending@sistema.com'),
                phoneTeacher: cifrarDatos('+1234567894'),
                usernameTeahcer: 'teacher_pending',
                passwordTeacher: pendingTeacherPassword,
                rolTeacher: 'teacher',
                stateTeacher: 'pending',
                specialization: 'Science',
                experience: 2,
                createTeahcer: new Date().toLocaleString()
            });
            console.log('✅ Pending teacher created - Username: teacher_pending, Password: TeacherPending123!');
        }

        // Create inactive student for testing status workflows
        const inactiveStudentExists = await orm.student.findOne({
            where: { usernameEstudent: 'student_inactive' }
        });

        if (!inactiveStudentExists) {
            const inactiveStudentPassword = await hashPassword('StudentInactive123!');
            
            await orm.student.create({
                identificationCardStudent: cifrarDatos('55667788'),
                completeNameEstudent: cifrarDatos('Luis Fernando Castro'),
                emailEstudent: cifrarDatos('student_inactive@sistema.com'),
                celularEstudent: cifrarDatos('+1234567895'),
                usernameEstudent: 'student_inactive',
                passwordEstudent: inactiveStudentPassword,
                rolStudent: 'student',
                stateEstudent: 'inactive',
                ubicationStudent: 'Ciudad Secundaria',
                grade: '9th Grade',
                enrollmentDate: new Date(),
                createStudent: new Date().toLocaleString()
            });
            console.log('✅ Inactive student created - Username: student_inactive, Password: StudentInactive123!');
        }

        console.log('\n🎉 User seeding completed successfully!');
        console.log('\n📋 Test Users Summary:');
        console.log('🔑 Admin: admin / Admin123!');
        console.log('👨‍🏫 Teacher: teacher / Teacher123!');
        console.log('👨‍🎓 Student: student / Student123!');
        console.log('⏳ Pending Teacher: teacher_pending / TeacherPending123!');
        console.log('❌ Inactive Student: student_inactive / StudentInactive123!');
        console.log('\n💡 You can use these credentials to test the authentication system!');

    } catch (error) {
        console.error('❌ Error in user seeder:', error);
        throw error;
    }
};

// Función para ejecutar el seeder
const runSeeder = async () => {
    try {
        await userSeeder();
        process.exit(0);
    } catch (error) {
        console.error('❌ Seeder failed:', error);
        process.exit(1);
    }
};

// Ejecutar si se llama directamente
if (require.main === module) {
    runSeeder();
}

module.exports = userSeeder;