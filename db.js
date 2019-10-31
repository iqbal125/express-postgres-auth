const { Pool } = require('pg')

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'newdb',
  password: '',
  post: 5432
})

module.exports = pool
