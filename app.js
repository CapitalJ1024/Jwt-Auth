const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");//initialing jwt
const mongoose = require("mongoose"); //initialising mongoose
const bcrypt = require("bcryptjs")//initialising bcryptjs.
const express = require("express");  //initialising express
const app = express(); // declaring express

dotenv.config({path: './config.env'});//declaring the path of .env file|
//**************url to connect monog atlas
const DB = process.env.DATABASE;
const PORT=process.env.PORT;
//************* connecting to mongoose
 mongoose.connect(DB , {
     useNewUrlParser: true,
     
     useUnifiedTopology: true,
    
 }).then(() => {
     console.log('connection succesful');
 } ) .catch((err) => console.log(err));


 //************** creating schema
 const schema = new mongoose.Schema({
     email : {type : String,
        required: true},
     password : {type : String,
        required: true},
     tokens :[  //field for tokens
         {
         token : {type :String,
                required: true}
         }
     ]   
 });

 //******************hashing password
 schema.pre('save', async function(next){ //calling pre function before save , funtion is a call back middleware.
    if(this.isModified('password')){ //if password is filled by user only then this works
            this.password = await bcrypt.hash(this.password , 12)//12 is salt length.//this keyword is used for the global object it belong

        }
        next();
    });

//*******************creating json web token
//                         |------we are not using fat arrow function because of 'this' keyword
schema.methods.genauthToken = async function(){
    try{
        let tokenJ = jwt.sign({_id: this._id}, process.env.SECRET_KEY)//two fun should pass - 1. payload (unique data -- can be id),2. Secret key
                                                        

        this.tokens = this.tokens.concat({token : tokenJ})//adding token in then token field 
        await this.save();//saving token
        return tokenJ;                                        
    }catch(err){
        console.log(err);
    }
}



 //creating model
const user = new mongoose.model ("user", schema);

// for parsing the input
app.use(express.urlencoded({ extended: true }))

//declaring route'/' 
app.get("/", function(req,res){
    res.sendFile( __dirname + '/index.html')
})

//async version       |--------------------------------------------------declaring async for async-await before call back function
app.post("/signup", async function(req, res){
    const {email , password} = req.body;
    if (!email || !password){
        return res.status(400).json({error : "please fill all the details"})  //validation of filling all the fields;;
    }
    try{
        const userExist= await user.findOne({email: email})  //first email is for all emails already exist in db , second is entered by use //this is a promise statement.
    
        if(userExist){
            return res.status(422).json({error : "Email already exist."})
        }

        const Up = new user ({email, password}); //we can also use req.body instead of {email,pass};; 

        const register = await Up.save();                              //await is used when promise is returning.
        if (register){
            res.redirect("/login");
        }else{
            res.status(500).json({error :"Registration failed"})
        }
        
    }
    catch(err) {console.log(err);}
    
})


//declaring login route
app.get("/login", function(req, res){
    res.sendFile(__dirname + '/login.html')
})

app.post("/login", async function(req, res){
    try {
    const {email , password} = req.body; 

    if (!email || !password){
        return res.status(400).json({error : "please fill all the details"})  //validation of filling all the fields;;
    }

    const signin = await user.findOne({email: email});
    
    if (signin){
    const match = await bcrypt.compare(password, signin.password);  //direct hashed pass match ni ker skte , isliye filled pass, saved hashed pass ko compare krne ke liye iska use kiya.
    const token = await signin.genauthToken();//passing token
    //console.log(token);
    if(!match){        
        res.status(400).json({error :"invalid credetials.pass"})
    }
    else{
    res.json({message :"Login successful"})
    console.log("Process Completed")
    }}else{
        res.status(400).json({error :"invalid credetials"})
    }
}catch(err){console.log(err);}
})

// creating server 
app.listen(PORT, function(){
    console.log("Server started on port "+PORT)//template literal ni aa rhe !!!!!!!!!!!!!!!!!!!!!!!!!!!
})


