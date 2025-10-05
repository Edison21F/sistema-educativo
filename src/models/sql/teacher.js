const teacher = (sequelize, type) => {
    return sequelize.define('teachers', {
        idTeacher: {
            type: type.INTEGER,
            autoIncrement: true,
            primaryKey: true,
        },
        identificationCardTeacher: {
            type: type.TEXT,
            allowNull: false,
            unique: true,
            comment: 'Encrypted identification card'
        },
        completeNmeTeacher: {
            type: type.TEXT,
            allowNull: false,
            comment: 'Encrypted full name'
        },
        emailTeacher: {
            type: type.TEXT,
            allowNull: false,
            comment: 'Encrypted email address'
        },
        phoneTeacher: {
            type: type.TEXT,
            allowNull: false,
            comment: 'Encrypted phone number'
        },
        usernameTeahcer: {
            type: type.STRING(100),
            allowNull: false,
            unique: true,
            comment: 'Plain text username for login'
        },
        passwordTeacher: {
            type: type.STRING(255),
            allowNull: false,
            comment: 'Hashed password'
        },
        photoEstudent: {
            type: type.STRING(255),
            allowNull: true,
            comment: 'Profile photo filename'
        },
        rolTeacher: {
            type: type.ENUM('teacher', 'head_teacher', 'coordinator'),
            defaultValue: 'teacher',
            comment: 'Teacher role'
        },
        stateTeacher: {
            type: type.ENUM('active', 'inactive', 'pending', 'suspended'),
            defaultValue: 'pending',
            comment: 'Account status'
        },
        specialization: {
            type: type.STRING(255),
            allowNull: true,
            comment: 'Teacher specialization or subject'
        },
        experience: {
            type: type.INTEGER,
            defaultValue: 0,
            comment: 'Years of experience'
        },
        createTeahcer: {
            type: type.STRING(50),
            allowNull: false,
            comment: 'Creation timestamp'
        },
        updateTeacher: {
            type: type.STRING(50),
            allowNull: true,
            comment: 'Last update timestamp'
        }
    }, {
        timestamps: false,
        tableName: 'teachers',
        comment: 'Teachers table with encrypted sensitive data'
    });
};

module.exports = teacher;