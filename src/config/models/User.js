const mongoose = require('mongoose')

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        trim: true
    },
    studentID: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    date: {
        type: Date,
        default: Date.now
    },
    role: {
        type: 'String',
        default: 'user',
        enum: ['user', 'admin']
    }
})
const User = mongoose.model('User', UserSchema)
    // User.findOne({ email: '17020772@vnu.edu.vn' })
    //     .then(user => {
    //         if (user) console.log(user)
    //         console.log(123)
    //     }).catch(err => console.log(err))
module.exports = User