const User = require('./User')
module.exports = {
    ensureAuthenticated: function(req, res, next) {
        if (req.isAuthenticated()) {
            return next()
        }
        req.flash('error_msg', 'Please log in to view that resource');
        res.redirect('users/login')
    },
    forwardAuthenticated: function(req, res, next) {
        if (!req.isAuthenticated()) {
            return next()
        }
        if (req.user) {
            User.findOne({ "_id": req.user._id }, function(err, user) {
                if (err) {
                    throw err;
                } else if (user.role = "user") {
                    return next();
                } else {
                    return res.redirect("/admin")
                }
            })
        }
    }
}