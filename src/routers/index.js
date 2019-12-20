const express = require('express')
const router = express.Router()
const passport = require('passport')
const bcrypt = require('bcryptjs')
const request = require('request')

const { ensureAuthenticated, forwardAuthenticated } = require('../config/models/auth')
    //User model
const User = require('../config/models/User')
router.get('/', (req, res) => res.render('login'))
router.get('/dashboard', ensureAuthenticated, (req, res) => res.render('dashboard', {
    name: req.user.name
}))
router.get('/admin', (req, res) => res.render('adminpage'))
router.get('/profile/:id', (req, res) => {
    res.send('Id is' + req.params.id)
})
module.exports = router