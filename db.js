const { Pool } = require('pg');
const { db_pwd } = require('./keys');

console.log(db_pwd);

const pool = new Pool({
	user: 'postgres',
	host: 'localhost',
	database: 'newdb',
	password: db_pwd,
	post: 5432,
});

module.exports = pool;
