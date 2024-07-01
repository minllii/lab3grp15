const express = require('express')
const app = express()
const port = process.env.PORT || 3000;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

app.use(express.json())

//new user registration
 app.post('/user', async (req, res) => {
   //check if username already exist
   let existing = await client.db("labuser").collection("labuserdetail").findOne({
     username: req.body.username
   })
   if(existing){
     res.status(400).send("username already exist")
   }
   else{
   //insertOne the registration data to mongo
   const hash = bcrypt.hashSync(req.body.password, 10); //hash pwd, 10 rounds
   //console.log(req.body.username)
   let result = await client.db("labuser").collection("labuserdetail").insertOne(
   {
     username: req.body.username,
     password: hash, //instead of password: req.body.password, -- bcs want to hash pwd
     name: req.body.name
   }
 )
 res.send(result)
 }
 })
 
 //user login api
 app.post('/login', async (req, res) => {
   if (req.body.username != null && req.body.password != null) {
   // step #1: res.body.username? -need to check if username is in database-find
   let result = await client.db("labuser").collection("labuserdetail").findOne({
       //req.body.username is username submitted by user, 'username' is the document in data
       username: req.body.username 
   })
 
   if (result) {
     // step #2: if user exist, check if password is correct
     if (bcrypt.compareSync(req.body.password, result.password) == true) {
       // password is correct
       var token = jwt.sign(
         { _id: result._id, username: result.username, name: result.name}, 
         'lab3passkey',
         {expiresIn: 360}
       );
       res.send(token)
     } else {
       // password is incorrect
       res.status(401).send('wrong password')
     }
 
   } else {
     // step #3: if user not found
     res.status(401).send("username is not found")
   }
   } else {
     req.status(400).send("missing username or password")
   }
 })
   
 // get user profile
 app.get('/user/:id', verifyToken, async (req, res) => {
   let auth = req.headers.authorization
   let authSplitted = auth.split(' ')
   let token = authSplitted[1]
   let decoded = jwt.verify(token, 'lab3passkey')
   console.log(decoded)
    //console.log(req.headers.authorization.split(' '))
 
   if (decoded._id != req.params.id) {
     res.status(401).send('Unauthorized Access')
   }else {
     let result = await client.db("labuser").collection("labuserdetail").findOne({
       _id: new ObjectId(req.params.id)
     })
     res.send(result)
   }
 })
 
 // update user account
 app.patch('/user/:id', verifyToken, async (req, res) => {
   if (req.identify._id != req.params.id) {
     res.send('Unauthorized')
   }else {
     let result = await client.db("labuser").collection("labuserdetail").updateOne(
       {
         _id: new ObjectId(req.params.id)
       },
       {
         $set: {
           name: req.body.name
         }
       }
     )
     res.send(result)
   }
 })
 
 // delete user account
 app.delete('/user', (req, res) => {
   // deleteOne
   console.log('delete user account')
 })

app.listen(port, () => {
   console.log(`Example app listening on port ${port}`)
})

function verifyToken(req, res, next){
   const authHeader = req.headers['authorization']
   const token = authHeader && authHeader.split(' ')[1]
 
   if (token == null) return res.sendStatus(401)
 
   jwt.verify(token, "lab3passkey", (err, decoded) => {
     console.log(err)
 
     if (err) return res.sendStatus(403)
 
     req.identify = decoded
 
     next()
   })
 }

const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = "mongodb+srv://chai:mlFKEKK27@cluster0.ug7mkaj.mongodb.net/?appName=Cluster0";

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    await client.close();
  }
}
run().catch(console.dir);
