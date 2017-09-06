const sqlite3 = require('sqlite3').verbose()
var bcrypt = require('bcrypt')
let db  = new sqlite3.Database('./db.db', (err)=> {
    if (err){
        console.error(err.message)
    }
})

var sql = `
CREATE TABLE IF NOT EXISTS user(
email text,
password text,
role text,
hash text,
salt text
)
`
var users = [
  {
    email: "chan.han.1@us.af.mil",
    password: "password1",
    role: "admin"
  },
  {
    email: "caleb.ziegler.1@us.af.mil",
    password: "password2",
    role: "peasant"
  },
  {
    email: "gregory.anderson.26@us.af.mil",
    password: "password3",
    role: "peon"
  },
]
var users_input = users.map((d)=>{
  return [d.email,d.password, d.role].join(',')
})
console.log(users_input)
var sql2 = `
INSERT INTO user(email, password, role, hash, salt)
VALUES (?,?,?,?,?)
`
db.serialize(()=>{
  db.run('DROP Table IF EXISTS user')
  db.run(sql, [], function(err){
    if (err){
      console.log(err.message)
    }
    console.log(`Table Created`)
  })
  var stmt = db.prepare(sql2)
  for (i = 0;i<users.length;i++){
    var salt = bcrypt.genSaltSync(10)
    var hash = bcrypt.hashSync(users[i].password, salt)
    var authenticated = bcrypt.compareSync(users[i].password, hash)
    stmt.run(users[i].email,users[i].password, users[i].role, hash, salt)
  }
  stmt.finalize()
  db.all('SELECT * from user', (err, rows)=>{
    if (err){
      throw err    
    }
    rows.forEach((row)=>{
      console.log(row)
    })
  })
  //.run('DROP TABLE user')
})

db.close()
  /*sql = `INSERT into user(name, password, role, hash, salt)
    VALUES
    ('Joe Han'),
    ('Caleb Ziegler', 'password', 'false'),
    
    `
    db4.run(sql, [], function(err){
        if (err){
          console.error(err.message)
        } 
    console.log(`A row has been inserted with rowid ${this.lastID}`)
    })   
})*/


