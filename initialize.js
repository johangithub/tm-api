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
salt text,
id int
)
`
var users = [
  {
    email: "chan.han.1@us.af.mil",
    password: "password1",
    role: "admin",
    id: 999
  },
  {
    email: "caleb.ziegler.1@us.af.mil",
    password: "password2",
    role: "admin",
    id: 999
  },
  {
    email: "gregory.anderson.26@us.af.mil",
    password: "password3",
    role: "admin",
    id: 999
  },
  {
    email: "officer@us.af.mil",
    password: "password",
    role: "officer",
    id: 999
  },
  {
    email: "billet.owner@us.af.mil",
    password: "password",
    role: "billet_owner",
    id: 999
  },
  {
    email: "losingcc@us.af.mil",
    password: "password",
    role: "losing_commander",
    id: 999
  },
]

for (let i=1;i<101;i++){
  users.push({
    email: "officer."+i+"@us.af.mil",
    password: "password",
    role: "officer",
    id: i
  })
}

for (let i=1;i<101;i++){
  users.push({
    email: "billet.owner."+i+"@us.af.mil",
    password: "password",
    role: "billet_owner",
    id: i
  })
}

var sql2 = `
INSERT INTO user(email, password, role, hash, salt, id)
VALUES (?,?,?,?,?,?)
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
    stmt.run(users[i].email,users[i].password, users[i].role, hash, salt, users[i].id)
  }
  stmt.finalize()
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


