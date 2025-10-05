const student = (sequelize, type) => {
    return sequelize.define('students', {
        idEstudent: {
            type: type.INTEGER,
            autoIncrement: true,
            primaryKey: true,
        },
        identificationCardStudent: {
            type: type.TEXT,
            allowNull: false,
            unique: true,
            comment: 'Encrypted identification card'
        },
        completeNameEstudent: {
            type: type.TEXT,
            allowNull: false,
            comment: 'Encrypted full name'
        },
        emailEstudent: {
            type: type.TEXT,
            allowNull: false,
            comment: 'Encrypted email address'
        },
        celularEstudent: {
            type: type.TEXT,
            allowNull: false,
            comment: 'Encrypted phone number'
        },
        usernameEstudent: {
            type: type.STRING(100),
            allowNull: false,
            unique: true,
            comment: 'Plain text username for login'
        },
        passwordEstudent: {
            type: type.STRING(255),
            allowNull: false,
            comment: 'Hashed password'
        },
        photoEstudent: {
            type: type.STRING(255),
            allowNull: true,
            comment: 'Profile photo filename'
        },
        ubicationStudent: {
            type: type.STRING(255),
            allowNull: true,
            comment: 'Student location/address'
        },
        rolStudent: {
            type: type.ENUM('student', 'student_leader', 'graduate'),
            defaultValue: 'student',
            comment: 'Student role'
        },
        stateEstudent: {
            type: type.ENUM('active', 'inactive', 'pending', 'graduated', 'suspended'),
            defaultValue: 'pending',
            comment: 'Account status'
        },
        grade: {
            type: type.STRING(20),
            allowNull: true,
            comment: 'Current grade or level'
        },
        enrollmentDate: {
            type: type.DATEONLY,
            allowNull: true,
            comment: 'Date of enrollment'
        },
        guardianName: {
            type: type.TEXT,
            allowNull: true,
            comment: 'Encrypted guardian name'
        },
        guardianPhone: {
            type: type.TEXT,
            allowNull: true,
            comment: 'Encrypted guardian phone'
        },
        createStudent: {
            type: type.STRING(50),
            allowNull: false,
            comment: 'Creation timestamp'
        },
        updateStudent: {
            type: type.STRING(50),
            allowNull: true,
            comment: 'Last update timestamp'
        }
    }, {
        timestamps: false,
        tableName: 'students',
        comment: 'Students table with encrypted sensitive data'
    });
};

module.exports = student;