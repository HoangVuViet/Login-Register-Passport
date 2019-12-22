const User = require('./User')
const isAdmin = () => {
    return function(req, res, next) {

        const { email, password } = req.body

        if (!email.includes('@') && !email.includes('admin')) {
            User.findOne({ studentID: email })
                .then(user => {
                    if (!user) return next()
                    if (user.role == "admin") {
                        return res.redirect('/admin')
                    }
                    next()
                }).catch(err => console.log(err))

        } else {
            User.findOne({ email: email })
                .then(user => {
                    if (!user) return next()
                    else {
                        if (user.role == "admin") {
                            return res.redirect('/admin')
                        }
                    }
                    next()
                }).catch(err => console.log(err))
        }
        next()
    }
}
module.exports = { isAdmin }