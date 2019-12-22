const express = require('express')
const router = express.Router()
const passport = require('passport')
const bcrypt = require('bcryptjs')
const request = require('request')
const { ensureAuthenticated, forwardAuthenticated } = require('../config/models/auth')
const User = require('../config/models/User')
const { isAdmin } = require('../config/models/middleware')
router.get('/login', forwardAuthenticated, (req, res) => res.render('login'))

// Register Page
router.get('/register', forwardAuthenticated, (req, res) => res.render('register'))
    // Forgot Password Page
router.get('/forgotpassword', forwardAuthenticated, (req, res) => res.render('forgotpass'))

// Resgister Handle
router.post('/register', (req, res) => {
        const { name, email, studentID, password, password2 } = req.body
        var errors = []
        console.log(password)
        console.log(req.body)
            //Check required fields
        if (!name || !email || !password || !password2 || !studentID) {
            errors.push({ msg: 'Please enter all fields' })
        }
        // Check password matched
        if (password != password2) {
            errors.push({ msg: 'Passwords do not match' })
        }
        // Check password.length()
        if (password.length < 5) {
            errors.push({ msg: 'Password must be at least 6 characters' })
        }
        if (studentID != parseInt(studentID)) {
            errors.push({ msg: 'ID is invalid!' })
        }
        if (errors.length > 0) {
            res.render('register', {
                errors,
                name,
                email,
                studentID,
                password,
                password2
            })
        } else {
            // Validation passed
            User.findOne(({ studentID }))
                .then(user => {
                    if (user) {
                        // User exists
                        errors.push({ msg: 'ID is already registered!' })
                        res.render('register', {
                            errors,
                            name,
                            email,
                            studentID,
                            password,
                            password2
                        })
                    } else {
                        const newUser = new User({
                                name,
                                email,
                                studentID,
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
                                    res.redirect('/users/login')
                                })
                                .catch(err => console.log(err))
                        }))
                        console.log(newUser)
                    }
                })
        }
        console.log(errors)
    })
    // Forgot Password Handle
router.post('/forgotpassword', (req, res) => {
        const { studentID, email, token } = req.body
        var errors = []
        console.log(req.body)
        console.log(email)
        if (studentID != parseInt(studentID)) {
            errors.push({ msg: 'ID is invalid!' })
        }
        if (!studentID || !email) {
            errors.push({ msg: 'Please enter all fields' })
        }
        if (errors.length > 0) {
            res.render('forgotpass', {
                errors,
                studentID,
                email

            })
        } else {
            User.findOne({ studentID: studentID, email: email })
                .then(user => {
                    if (!user) {
                        // User doesn't exist
                        errors.push({ msg: 'Mã số sinh viên hoặc email không tồn tại!' })
                        res.render('forgotpass', {
                            errors,
                            studentID,
                            email
                        })
                    }
                }).catch(err => console.log(err))
        }

    })
    // Login Handle
router.post(
        '/login',
        passport.authenticate('local', {
            failureRedirect: '/login'
        }), (req, res) => {
            if (req.user.role === 'admin') {
                res.redirect('/admin')
            }
            if (req.user.role === 'user') {
                res.redirect('/dashboard')
            }
        })
    // Logout
router.get('/logout', (req, res) => {
    req.logout()
    req.flash('success_msg', 'You are logged out')
    res.redirect('/users/login')
})
module.exports = router