const express = require('express')
const router = express.Router()
const passport = require('passport')
const bcrypt = require('bcryptjs')
const request = require('request')
const async = require('async')
const crypto = require('crypto')
const nodemailer = require('nodemailer')
const { ensureAuthenticated, forwardAuthenticated } = require('../config/models/auth')
const User = require('../config/models/User')
const { isAdmin } = require('../config/models/middleware')
router.get('/login', forwardAuthenticated, (req, res) => res.render('login'))

// Register Page
router.get('/register', forwardAuthenticated, (req, res) => res.render('register'))
    // Forgot Password Page
router.get('/forgotpassword', forwardAuthenticated, (req, res) => res.render('forgotpass'))
    //ResetPassword Page
router.get('/reset/:token', function(req, res) {
        User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
            if (!user) {
                req.flash('error', 'Password reset token is invalid or has expired.')
                return res.redirect('/users/forgotpassword')
            }
            res.render('reset', { token: req.params.token })
        })
    })
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
router.post('/forgotpassword', (req, res, next) => {
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
            async.waterfall([
                (done) => {
                    crypto.randomBytes(20, (err, buf) => {
                        var token = buf.toString('hex')
                        done(err, token)
                    })
                }, (token, done) => {
                    User.findOne({ email: req.body.email, studentID: req.body.studentID }, function(err, user) {
                        if (!user) {
                            // User doesn't exist
                            errors.push({ msg: 'Mã số sinh viên hoặc email không tồn tại!' })
                            res.render('forgotpass', {
                                errors,
                                studentID,
                                email
                            })
                        } else {
                            user.resetPasswordToken = token
                            user.resetPasswordExpires = Date.now() + 3600000 // 1 hour

                            user.save(function(err) {
                                done(err, token, user)
                            })
                        }
                    })

                }, (token, user, done) => {
                    var smtpTransport = nodemailer.createTransport({
                        service: 'gmail',
                        auth: {
                            user: 'finalsessiontest@gmail.com',
                            pass: 'anhhoang'
                        }
                    });
                    var mailOptions = {
                        to: user.email,
                        from: 'finalsessiontest@gmail.com',
                        subject: 'Password Reset',
                        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
                            'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
                            'http://' + req.headers.host + '/users/reset/' + token + '\n\n' +
                            'If you did not request this, please ignore this email and your password will remain unchanged.\n'
                    };
                    smtpTransport.sendMail(mailOptions, function(err) {
                        console.log('mail sent')
                        req.flash('success', 'An e-mail has been sent to ' + user.email + ' with further instructions.')
                        done(err, 'done')
                    })
                }
            ], function(err) {
                if (err) return next(err)
                req.flash('success_msg', `An email has been sent to ${req.body.email}.Please check that email to reset your own password!`)
                res.redirect('/users/forgotpassword')
            })
        }

    })
    //Resetpassword Handle

router.post('/reset/:token', function(req, res, next) {
        const { password, confirm } = req.body
        var errors = []
        async.waterfall([
            function(done) {
                User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
                    if (!user) {
                        req.flash('error', 'Password reset token is invalid or has expired.')
                        return res.redirect('back')
                    }
                    if (!req.body.password) {
                        errors.push({ msg: 'Please enter all fields!' })
                    }
                    if (req.body.password.length < 5) {
                        errors.push({ msg: 'Password must be at least 6 characters' })
                    }
                    if (req.body.password !== req.body.confirm) {
                        errors.push({ msg: 'Passwords do not match.' })
                    }
                    if (errors.length > 0) {
                        res.render('reset', {
                            errors,
                            password,
                            confirm,
                            token: req.params.token
                        })
                    } else {
                        bcrypt.genSalt(10, (err, salt) => bcrypt.hash(req.body.password, salt, (err, hash) => {
                            if (err) throw err
                                // Set password to hashed
                            user.password = hash
                                // Save user
                            user.resetPasswordToken = undefined
                            user.resetPasswordExpires = undefined
                            user.save(function(err) {
                                req.logIn(user, (err) => {
                                    done(err, user)
                                })
                            })
                        }))
                    }
                })
            },
            function(user, done) {
                var smtpTransport = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        user: 'finalsessiontest@gmail.com',
                        pass: 'anhhoang'
                    }
                })
                var mailOptions = {
                    to: user.email,
                    from: 'finalsessiontest@gmail.com',
                    subject: 'Your password has been changed',
                    text: 'Hello,\n\n' +
                        'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
                }
                smtpTransport.sendMail(mailOptions, function(err) {
                    done(err)
                })
            }
        ], function(err) {
            if (err) return next(err)
            req.flash('success_msg', `Success! Your password has been changed`)
            return res.redirect('/users/login')
        })
    })
    // Login Handle
router.post(
        '/login',
        passport.authenticate('local', {
            failureRedirect: '/users/login',
            failureFlash: true
        }), (req, res, next) => {
            if (req.user.role === 'admin') {
                res.redirect('/admin')
            }
            if (req.user.role === 'user') {
                res.redirect('/dashboard')
            }
            (req, res, next)
        })
    // Logout
router.get('/logout', (req, res) => {
    req.logout()
    req.flash('success_msg', 'You are logged out')
    res.redirect('/users/login')
})
module.exports = router