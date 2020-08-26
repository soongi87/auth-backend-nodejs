'use strict';

const express = require('express');
const app = express();
const cors = require('cors');
const bodyParser = require('body-parser');

const jwt = require('jsonwebtoken');
var config = require('./config');
var bcrypt = require('bcryptjs');

//read from file
const fs = require('fs');

const _ = require('lodash');

const port = 3000;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cors());

app.post('/login', function(req, res) {

    let rawData = fs.readFileSync('user.json');
    let allUser = JSON.parse(rawData);

    var email  = req.body.email;
    var password = req.body.password;

    if(email != null && password != null) {

        var user = _.find(allUser, { 'email': email });

        if(user) {

            var passwordIsValid = bcrypt.compareSync(password, user.password);

            if(passwordIsValid) {

                var token = jwt.sign({ email: email }, config.secret, {
                    expiresIn: 86400// expires in 24 hours
                });

                res.status(200).send({
                    'success': 1,
                    'message': 'Account found.',
                    'token': token
                });

            } else {
                res.status(200).send({
                    'success': 0,
                    'message': 'Password is invalid'
                });
            }

        } else {
            res.status(200).send({
                'success': 0,
                'message': 'Account not found'
            });
        }

    }

});

app.post('/register', function(req, res) {

    var firstName  = req.body.first_name;
    var lastName = req.body.last_name;
    var email  = req.body.email;
    var password = req.body.password;

    let rawData = fs.readFileSync('user.json');
    let allUser = JSON.parse(rawData);

    //check user email in json file.
    var user = _.find(allUser, { 'email': email });

    if(!user) {

        var hashedPassword = bcrypt.hashSync(password, 8);

        let newUser = {
            first_name: firstName,
            last_name: lastName,
            email: email,
            password: hashedPassword
        };

        allUser.push(newUser);

        let data = JSON.stringify(allUser);
        fs.writeFileSync('user.json', data);

        var token = jwt.sign({ email: email }, config.secret, {
            expiresIn: 86400// expires in 24 hours
        });

        res.status(200).send({
            'success': 1,
            'message': 'Register successfully',
            'token': token
        });

    } else {
        res.status(200).send({
            'success': 0,
            'message': 'Email Address Exist.'
        });
    }

});

app.get('/home', function(req, res) {

    var token = req.headers['x-access-token'];

    if (!token) {
        res.status(200).send({ success: 0, message: 'No token provided.' })
    }

    jwt.verify(token, config.secret, function(err, decoded) {
        if (err) {
            res.status(200).send({ success: 0, message: 'Failed to authenticate token.' })
        } else {

            let rawData = fs.readFileSync('user.json');
            let allUser = JSON.parse(rawData);

            let user = {};
            user = _.find(allUser, { 'email': decoded.email });
            user.iat = decoded.iat;
            user.exp = decoded.exp;
            delete user.password;

            res.status(200).send({'success': 1, message: 'Successful authenticate token.', user: user});
        }
    });
});

app.listen(port, function() {
    console.log('Server is running on PORT:',port);
});
