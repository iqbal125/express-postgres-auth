const db = require('../db.js')
const moment = require('moment')

const helpers = require('./helpers')
const setToken = helpers.setToken
const generateBytes = helpers.generateBytes
const hashPassword = helpers.hashPassword

const sgMail = require('@sendgrid/mail');
const localSignIn = require('./passport_config').localSignIn
const requireAuth = require('./passport_config').requireAuth

const express = require('express')
const router = express.Router()


router.get('/private', requireAuth, (req, res) => {
    res.send('Accessed Private Endpoint')
}) 

router.post('/login',
  (req, res, next) => {
      localSignIn(req, res)
})

/*
JWT is sessionless, so logout only needs to be implemented
client side. 
*/

router.post('/signup', (req, res, next ) => {
    let password = req.body.password
    let username = req.body.username
  
    //check if username exists
    let query1 = `SELECT * FROM users
                  WHERE username=$1`
  
    //if not insert into database              
    let query2 = `INSERT INTO users (username, password)
                  VALUES($1, $2)
                  RETURNING id, username`
    
    let values1 = [username]
  
    //signup user, called inside callback1
    let callback2 = (q_err, q_res) => {
      if(q_err) {res.status(500).send(q_err)}
      //send back user id and info after signup
      if(q_res) {
        let id = q_res.rows[0].id
        let username = q_res.rows[0].username
    
        let user = {
          id,
          username
        }
    
        //jwt token login after signup
        res.send({token: setToken(user)});
      }
    }
  
    //create password hash before saving to db
    hashPassword(password)
      .then((password_hash) => {
        /* values2 and callback1 have to be scoped 
           here inside the .then() call because 
           they have to wait until the password 
           hash is generated before executing 
        */
  
        let values2 = [username, password_hash]
  
        //Check if user exists callback
        let callback1 = (q_err, q_res) => {
  
          if(q_err) { res.status(500).send(q_err)  }
          if(q_res.rows.length != 0) {
            res.status(401).send("User Already Exists")
          }
          if(q_res.rows.length === 0) {
            //if email not found, create user in db
            db.query(query2, values2, callback2)
          }
        }
        
        //check if user exists
        db.query(query1, values1, callback1)
    })
})

  
router.post('/forgot', (req, res) => {
    let username = req.body.username
  
    //find user in db
    let query1 = `SELECT * 
                  FROM USERS
                  WHERE username=$1`
  
    //save reset token and time to db
    let query2 = `UPDATE users 
                  SET resettoken=$1, resettokentime=$2
                  WHERE username=$3`
  
    let values1 = [username]
  
    //callback after verifying password reset email sent
    let callback2 = (q_err, q_res) => {
      if(q_res) {
        res.send("Successfully Sent Password reset")
      }
      if(q_err) {console.log(q_err) }
    }
  
  
    //check if email exists
    let callback1 = (q_err, q_res) => {
      if(q_res.rows[0]) {
        //generate reset token
        generateBytes()
          .then(token => {
            //setup email
            const msg = {
              to: 'test@example.com',
              from: 'test@example.com',
              subject: 'Password Reset',
              text: 'Here is the Password Reset Link, Will expire in 1 hour',
              html: 'Please change password' + 
              'with the following link <br/>' +
              'http://yourdomain.com/reset/' +
              token
            };
  
            //send email to user
            sgMail.send(msg)
              .then(res => console.log())
              .catch(err => console.log(err))
            
            //set expire time 1 hour from now
            let milli = Date.now() + 3600000
            let expiresIn = moment(milli).format('MM-DD-YYYY HH:mm') 
  
            let values2 = [token, expiresIn, username]
            console.log(values2)
  
            //save reset time and token to database
            db.query(query2, values2, callback2)
          })
          .catch(err => console.log(err))
  
      } else {
        res.send("Email Not Found")
      }
      if(q_err) {console.log(q_err)}
    }
    //find user in db
    db.query(query1, values1, callback1)
})
  
  
router.post('/password_reset', (req, res) => {
    let username = req.body.username
    let new_password = req.body.password
    let token = req.body.token
  
    //check if user and resettoken exists
    query1 = `SELECT * 
              FROM users 
              WHERE username=$1 AND resettoken=$2`
    
    //save new password to db, set token and reset time to empty strings
    query2 = `UPDATE users 
              SET username=$1, password=$2, resettoken=$3, resettokentime=$4
              WHERE username=$1`
    
    values1 = [username, token]
  
    //called inside callback1 after new password is saved to db
    callback2 = (q_err, q_res) => {
      if(q_res) {
        res.send("Password Successfully Reset")
      } else {
         console.log(q_err)
      }
    }
  
    //hash password and put to db
    hashPassword(new_password)
     .then((password_hash) => {
      /* values2 and callback1 have to be scoped 
         here inside the .then() call because 
         they have to wait until the password 
         hash is generated before executing 
      */
  
      let values2 = [
        username,
        password_hash, 
        '',
        ''
      ]
    
      //make sure token hasnt expired
      //then save new user password to db
      //set token and reset time in db to empty strings
      callback1 = (q_err, q_res) => {
        if(q_res.rows[0]) {
          let format = "MM-DD-YYYY HH:mm"
          let now = moment().format(format)
          let expiresAt = q_res.rows[0].resettokentime

          if(moment(expiresAt, format).isAfter(now)) {
            //save new password to db
            db.query(query2, values2, callback2)
          } else {
            res.send('Token Expired')
          }
        }
        if(!q_res.rows[0]) {
          res.send("Username not Found or Invalid Token")
        }
        console.log(q_err)
      }
      //check if user exists
      db.query(query1, values1, callback1)
      })
    .catch(err => console.log(err))
}) 

module.exports = router