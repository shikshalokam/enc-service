const config = {
  "development": {
    "username": process.env.DB_USER,
    "password": process.env.DB_PASSWORD,
    "database": process.env.DB_NAME,
    "host":  process.env.DB_HOST,
    "dialect": process.env.DB_DIALECT,
    "benchmark":true,
    "pool":{
      max:300
    },
    "scheme":"PKCS1",
    "version":"1.0.0",
    "hashAlgorithm": "sha256",
    "logging": false
  },
  "prod": {
    "username": process.env.DB_USER,
    "password": process.env.DB_PASSWORD,
    "database": process.env.DB_NAME,
    "host": process.env.DB_HOST,
    "port" : process.env.DB_PORT,
    "dialect": process.env.DB_DIALECT,
    "pool":{
      max:300
    },
    "scheme":"PKCS1",
    "version":"1.0.0",
    "hashAlgorithm": "sha256",
    "logging": false
  }
}


module.exports = config;
