const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const ExtractJWT = require("passport-jwt").ExtractJwt;
const JWTStrategy   = require("passport-jwt").Strategy;
const db = require('../db.js')
const checkPassword = require('./helpers').checkPassword
const setToken = require('./helpers').setToken


const requireAuth = passport.authenticate('jwt', { session: false });

const localSignIn = (req, res) => {
    oPts = {
        session: false,
    }
    passport.authenticate('local', oPts, (error, user, info) => {
        if(error) { res.status(500).send(error); }
        if(info) { res.status(401).send(info); }
        if(!user && !info) { 
            res.status(401).send('Authentication Failed');
        } 
        if(user) {
            user = {
                id: user.rows[0].id,
                username: user.rows[0].username
            }
            //send jwt token as login
            res.send({token: setToken(user)});
        }
   })(req, res)
}


passport.use(new JWTStrategy({
    jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
    secretOrKey   : 'secret'
    },
  (jwtPayload, cb) => {
    //check if id exists in database
        return cb(null, jwtPayload)
    }
));


passport.use(new LocalStrategy({
    //change if your property names are different
    usernameField: 'username',
    passwordField: 'password',
    session: false
  }, (username, password, done) => {
  
    let query = `SELECT * from users
                 WHERE username=$1`
  
    let values = [username]

    //check if username exists and then check password
    let callback = (err, user) => {
      if (err) { return console.log(err); }
      if (user.rows.length === 0) {
          return done(null, false, {message: "User Not Found"} ) 
        }
      if(user.rows.length != 0) {
        checkPassword(password, user.rows[0].password, done)
          .then(() => done(null, user))
          .catch(err => console.log(err))
      }
    }
    db.query(query, values, callback) 
}))



// uncomment if  you want sessions
// passport.serializeUser((user, done) => {
//   console.log(user)
//   if(user.rows) {
//     done(null, user.rows[0].id)
//   }
//   else {
//     done(null, user.id)
//   }
// })

// passport.deserializeUser((id, cb) => {
//   let query = `SELECT * FROM users
//                WHERE id = $1`
  
//   let values = [id]

//   let callback = (err, results) => {
//     if(err) {
//       console.log(err)
//     }
//     console.log(err)
//     cb(null, results.rows[0])
//   }

//   db.query(query, values, callback)
// })


const exportObj = {
    requireAuth, 
    localSignIn
}

module.exports = exportObj
