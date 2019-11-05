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
