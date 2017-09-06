const sqlite3 = require('sqlite3').verbose()
let db = new sqlite3.Database('./chinook.db')

// 1. Query all results
let sql1 = 'SELECT DISTINCT country as country FROM customers';
db.all(sql1, [], (err, rows) => {
    if (err){
        throw err
    }
    rows.forEach((row)=>{
        console.log(row.country)
    })
})

// 2. Query one item
playlistId = 5
let sql2 = 'SELECT playlistID id, Name name from playlists where playlistId='+playlistId
db.get(sql2, [], (err, row)=>{
    if (err){
        return console.error(err.message)
    }
    return row ? console.log(row.id, row.name) : console.log('No playlist found with the id '+playlistId)
})

// 3. Query using each() method
let sql3 = `
Select FirstName firstName,
LastName lastName,
Email email
from customers
where country = ?
order by firstname
`

db.each(sql3, ['USA'], (err, row)=>{
    if (err){
        throw err
    }
    console.log(`${row.firstName} ${row.lastName} - ${row.email}`)
})

db.close()


// 4. Serialize execution
// Use new table
let db2  = new sqlite3.Database(':memory:', (err)=> {
    if (err){
        console.error(err.message)
    }
})

db2.serialize(() => {
  // Queries scheduled here will be serialized.
  db2.run('CREATE TABLE greetings(message text)')
    .run(`INSERT INTO greetings(message)
          VALUES('Hi'),
                ('Hello'),
                ('Welcome')`)
    .each(`SELECT message FROM greetings`, (err, row) => {
      if (err){
        throw err;
      }
      console.log(row.message);
    })
});

// 5. Parallelize execution

db2.parallelize(()=>{
    dbSum(1,1, db2)
    dbSum(2,2, db2)
    dbSum(3,3, db2)
    dbSum(4,4, db2)
    dbSum(5,5, db2)
})
db2.close()
function dbSum(a, b, db) {
  db.get('SELECT (? + ?) sum', [a, b], (err, row) => {
    if (err) {
      console.error(err.message);
    }
    console.log(`The sum of ${a} and ${b} is ${row.sum}`);
  });
}


let db3  = new sqlite3.Database(':memory:', (err)=> {
    if (err){
        console.error(err.message)
    }
})
let languages = ['C++', 'Python', 'Java', 'C#', 'Go']
let placeholders = languages.map((language)=> '(?)').join(',')
// 6. Insert Table and Update
db3.serialize(()=>{
    db3.run('CREATE TABLE langs(name text)')
       .run('Insert into langs(name) VALUES(?)', ['C'], function(err){
            if (err) {
                console.log(err.message)
            }
            console.log(`A row has been inserted with rowid ${this.lastID}`)
       })
       .run('Insert into langs(name) Values '+ placeholders,languages, function (err){
            if (err){
                console.error(err.message)
            }
            console.log(`Rows inserted ${this.changes}`)
       })
       .all('SELECT * from langs', [], function(err, rows){
            if (err){
                throw err
            }
            else {
                rows.forEach((row)=>{
                    console.log(row)
                })
            }
            
        })

})



db3.close()


let db4  = new sqlite3.Database('./db.db', (err)=> {
    if (err){
        console.error(err.message)
    }
})

db4.serialize(()=>{
  db4.run('CREATE TABLE user(name text, password text, admin boolean)', [], function(err){
    if (err){
      console.log(err.message)
    }
    console.log(`Rows inserted ${this.changes}`)
  })
})