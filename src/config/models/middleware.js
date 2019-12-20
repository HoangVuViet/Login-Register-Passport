const User = require('./User')
const requireAdmin = () => {
    return function(req, res, next) {
        console.log(req.body)
        const { email, password } = req.body
        console.log(req.body)
        if (!email.includes('@') && !email.includes('admin')) {
            User.findOne({ studentID: email }, function(err, user) {
                console.log(User)
                if (err) { return next(err); }

                if (!user) {
                    return next()
                }

                if (user.role == "admin") {
                    return res.redirect('/admin')
                }

                next()
            })

        } else {
            User.findOne({ email: email }, function(err, user) {
                console.log(User)
                if (err) { return next(err); }

                if (!user) {
                    return next()
                }

                if (user.role == "admin") {
                    return res.redirect('/admin')
                }

                next()
            })
        }
    }
}
module.exports = requireAdmin