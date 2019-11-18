const express = require('express')
const router = express.Router()
const passport = require('passport')
const bcrypt = require('bcryptjs')
const request = require('request')

const { ensureAuthenticated, forwardAuthenticated } = require('../config/models/auth')
    //User model
const User = require('../config/models/User')
router.get('/', (req, res) => res.render('home'))
router.get('/dashboard', ensureAuthenticated, (req, res) => res.render('dashboard', {

    name: req.user.name
}))

// Resgister Handle
router.get('/login', (req, res) => res.render('login'))
router.get('/register', (req, res) => res.render('register'))

// Resgister Handle
router.post('/register', (req, res) => {
        const { name, email, username, password, password2 } = req.body
        console.log(password)
        console.log(req.body)
        var errors = []
            //Check required fields
        if (!name || !email || !password || !password2) {
            errors.push({ msg: 'Please enter all fields' });
        }
        // Check password matched
        if (password != password2) {
            errors.push({ msg: 'Passwords do not match' });
        }
        // Check password.length()
        if (password.length < 6) {
            errors.push({ msg: 'Password must be at least 6 characters' });
        }

        if (errors.length > 0) {
            res.render('register', {
                errors,
                name,
                email,
                password,
                password2
            })
        } else {
            // Validation passed
            User.findOne(({ email: email }))
                .then(user => {
                    if (user) {
                        // User exists
                        errors.push({ msg: 'Email is already registered' })
                        res.render('register', {
                            errors,
                            name,
                            email,
                            password,
                            password2
                        })
                    } else {
                        const newUser = new User({
                                name,
                                email,
                                password
                            })
                            //Hash Password
                        bcrypt.genSalt(10, (err, salt) => bcrypt.hash(newUser.password, salt, (err, hash) => {
                            if (err) throw err
                                // Set password to hashed
                            newUser.password = hash
                                // Save user
                            newUser.save()
                                .then(user => {
                                    req.flash('success_msg', 'You are now registed and can login')
                                    res.redirect('/login')
                                })
                                .catch(err => console.log(err))
                        }))
                        console.log(newUser)



                    }
                })
        }
        console.log(errors)
    })
    // Login Handle
router.post('/login', (req, res, next) => {
        passport.authenticate('local', {
            successRedirect: '/dashboard',
            failureRedirect: '/login',
            failureFlash: true
        })(req, res, next)
    })
    // Logout
router.get('/logout', (req, res) => {
    req.logout()
    req.flash('success_msg', 'You are logged out')
    res.redirect('/login')
})
module.exports = router