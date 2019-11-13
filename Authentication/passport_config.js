const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const ExtractJWT = require('passport-jwt').ExtractJwt;
const JWTStrategy = require('passport-jwt').Strategy;
const db = require('../db.js');
const checkPassword = require('./helpers').checkPassword;

const requireAuth = passport.authenticate('jwt', { session: false });

passport.use(
  new JWTStrategy(
    {
      jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
      secretOrKey: 'secret'
    },
    (jwtPayload, cb) => {
      let id = [jwtPayload.id];
      let query = `SELECT *
                   FROM users 
                   WHERE id=$1`;

      //check if id exists then allow endpoint
      let callback = (err, user) => {
        if (err) {
          return cb(err, false);
        }
        if (user.rows.length === 0) {
          return cb(null, false);
        }
        if (user.rows.length != 0) {
          return cb(null, jwtPayload);
        }
      };
      db.query(query, id, callback);
    }
  )
);

passport.use(
  new LocalStrategy(
    {
      //change if your property names are different
      usernameField: 'email',
      passwordField: 'password',
      session: false
    },
    (username, password, done) => {
      let query = `SELECT * from users
                   WHERE email=$1 OR username=$1`;

      let values = [username];

      //check if username exists and then check password
      let callback = (err, user) => {
        if (err) {
          return console.log(err);
        }
        if (user.rows.length === 0) {
          return done(null, false, { message: 'User Not Found' });
        }
        if (user.rows.length != 0) {
          checkPassword(password, user.rows[0].password, done)
            .then(() => done(null, user))
            .catch(err => console.log(err));
        }
      };
      db.query(query, values, callback);
    }
  )
);

const exportObj = {
  requireAuth
};

module.exports = exportObj;
