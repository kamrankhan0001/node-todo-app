const express = require("express");
require("dotenv").config();
const clc = require("cli-color");
const mongoose = require("mongoose");
const userModel = require('./Models/userModel');
const validator = require("validator");
const session = require("express-session");
const bcrypt = require("bcrypt");
const mongoDbSession = require('connect-mongodb-session')(session);
const { cleanupAndValidate, genrateJWTToken, sendVerificationToken } = require("./authUtils");
const { isAuth } = require("./middlewares/isAuth");
const todoModel = require("./Models/todoModel");
const rateLimiting = require("./middlewares/rateLimiting");
const jwt = require("jsonwebtoken");

// constant
const app = express();
const PORT = process.env.PORT || 8000;
//new mongoDbSession({ ... }): This creates a new instance of the MongoDB session store.
const store = new mongoDbSession({
    uri : process.env.MONGO_URI, //The uri property is being set to the value of the MONGO_URI
    collection : "sessions",   //collection property is being set to the string "sessions"
});

//mongoDB connection 
mongoose
.connect(process.env.MONGO_URI)
.then(()=>{
    console.log(clc.yellow("mongoDB connected Succesfully"));
})
.catch((err)=>{
    console.log(clc.red(err));
});

// middleware
app.set("view engine", "ejs"); //ejs set the default view engine for rendering dynamic content
app.use(express.json());   // for handle the json request 
app.use(express.urlencoded({extended : true})); // to handle the form 
app.use(
    session({
      secret: process.env.SECRET_KEY,
      resave: false, //if the session data hasn't changed. Setting it to false
      saveUninitialized: false, //a session that is not yet modified
      store: store,
    })
  );
  //midleware for connecting all the public folder
  app.use(express.static("public"));
// Route

app.get('/', (req, res)=>{
    return res.send("This is your Server");
})

app.get('/register', (req, res)=>{
    return res.render("register");
})
app.post('/register', async (req, res)=>{
    console.log(req.body);
    const {name, email, password, username} = req.body;

    // data validate
try {
  //calling cleanupAndValidate function
    await cleanupAndValidate({email, name, password, username}); 
} catch (error) {
    return res.send({
        status : 400,
        message: "Data invalid",
        error: error,
        data : req.body,
    });
}
//check if email and username exits or not
const userEmailExists = await userModel.findOne({ email });
if (userEmailExists) {
  return res.send({
    status: 400,
    message: "Email already exits",
  });
}

const userUsernameExists = await userModel.findOne({ username });
if (userUsernameExists) {
  return res.send({
    status: 400,
    message: "Username already exits",
    data: username,
  });
}
   //hashed the password
   const hashedPassword = await bcrypt.hash(
    password,
    parseInt(process.env.SALT)
  );
  //console.log(hashedPassword);

    // save the user in DB
    const userObj = new userModel({
        name : name,
        email : email,
        password : hashedPassword,
        username : username,
    });

    try {
        const userDb =  await userObj.save();
        console.log(userDb);

        // generate the token 
const verifiedToken = genrateJWTToken(email);
    console.log(verifiedToken);

    //send the email to user
    sendVerificationToken({ email, verifiedToken });

    return res.redirect("/login");
    } catch (error) {
      console.log(error);
        return res.send({
            status : 500,
            message : "Database error",
            error : error,
        })
    }
});

app.get("/verifytoken/:id", async (req, res) => {
  console.log(req.params.id);
  const token = req.params.id;

  jwt.verify(token, process.env.SECRET_KEY, async (err, email) => {
    // console.log(email);

    try {
      await userModel.findOneAndUpdate(
        { email: email },
        { isEmailAuthenticated: true }
      );

      return res.send({
        status: 200,
        message: "Your email has been authenticated, please go to login page",
      });
    } catch (error) {
      return res.send({
        status: 500,
        message: "Database error",
        error: error,
      });
    }
  });
});


app.get('/login',(req, res)=>{
    return res.render("login");
});

app.post('/login', async (req, res)=>{
 const { loginId, password } = req.body;

 //data validation

  if (!loginId || !password)
  return res.send({
    status: 400,
    message: "Missing credentials",
  });

if (typeof loginId !== "string" || typeof password !== "string") {
  return res.send({
    status: 400,
    message: "Invalid data format",
  });
}

try {
    let userDb  = {};
    //either username or email
    if (validator.isEmail(loginId)) {
      userDb = await userModel.findOne({ email: loginId });
      if (!userDb) {
        return res.send({
          status: 400,
          message: "Wrong email",
        });
      }
    } else {
      userDb = await userModel.findOne({ username: loginId });
      if (!userDb) {
        return res.send({
          status: 400,
          message: "Wrong username",
        });
      }
    }

// is email Verified
if(!userDb.isEmailAuthenticated){
  return res.send({
    status : 400,
    message: "please verify your email id before login",

  });
}
    //password comparison
    const isMatched = await bcrypt.compare(password, userDb.password);
    if (!isMatched) {
      return res.send({
        status: 400,
        message: "Incorrect Passoword",
      });
    }
    
    // session
  console.log(req.session);
  req.session.isAuth = true;
  req.session.user ={
    username: userDb.username,
    email : userDb.email,
    userId : userDb._id,
};
    return res.redirect("/dashboard");
  } catch (error) {
    return res.send({
      status: 500,
      message: "Database Error",
      error: error,
    });
  }
});

app.get("/dashboard", isAuth, async (req, res) => {
    
      return res.render("dashboard");
  });

//logout
app.post("/logout", isAuth, (req, res) => {
    req.session.destroy((error) => {
      if (error) throw error;
      return res.redirect("/login");
    });
  });

  app.post("/logout_from_all_devices", isAuth, async (req, res) => {
    //create the session schema
    const sessionSchema = new mongoose.Schema({ _id: String }, { strict: false });
    const sessionModel = mongoose.model("session", sessionSchema);
  
    //get the user data who is making the request
    const username = req.session.user.username;
  
    //delete the sessions from db
    try {
      const deleteDb = await sessionModel.deleteMany({
        "session.user.username": username,
      });
      console.log(deleteDb);
      return res.redirect("/login");
    } catch (error) {
      return res.send({
        status: 500,
        message: "logout unsuccessfull",
        error: error,
      });
    }
  });

 //todo
 //due to private route am going to use auth here
app.post("/create-item", isAuth, rateLimiting,  async (req, res) => {
    const todoText = req.body.todo;
    const username = req.session.user.username;
  
    //data validation
    if (!todoText) {
      return res.send({
        status: 400,
        message: "Missing todo text",
      });
    } else if (typeof todoText !== "string") {
      return res.send({
        status: 400,
        message: "Invalid Todo format",
      });
    } else if (todoText.length < 3 || todoText.length > 100) {
      return res.send({
        status: 400,
        message: "Length of todo text should be 3-100",
      });
    }
  
    //make the entry in DB
    const todoObj = new todoModel({
      todo: todoText,
      username: username,
    });
  
    try {
      const todoDb = await todoObj.save();
      console.log(todoDb);
      return res.send({
        status: 201,
        message: "Todo created successfully",
        data: todoDb,
      });
    } catch (error) {
      return res.send({
        status: 500,
        message: "Database error",
        error: error,
      });
    }
  });
   
//edit
//check the ownership
// find the todo and update the todo with new data

app.post("/edit-item", isAuth, rateLimiting, async (req, res) => {
  console.log(req.body);
  const { id, newData } = req.body;
  const username = req.session.user.username;

  if (!newData || !id) {
    return res.send({
      status: 400,
      message: "Missing credentials",
    });
  }

  if (newData.length < 3 || newData.length > 100) {
    return res.send({
      status: 400,
      message: "Todo length should be 3 to 100",
    });

  }
 //find the todo with todoID
 try {
  const todoDb = await todoModel.findOne({ _id: id });

  console.log(todoDb);

  //check ownership
  if (todoDb.username !== username) {
    return res.send({
      status: 403,
      message: "Not allowed to edit, authorisation failed",
    });
  }

  //update the todo in DB

  const todoPrev = await todoModel.findOneAndUpdate(
    { _id: id },
    { todo: newData }
  );
  console.log(todoPrev);

  return res.send({
    status: 200,
    message: "Todo has been updated successfully",
  });
} catch (error) {
  return res.send({
    status: 500,
    message: "Database error",
    error: error,
  });
}
});
//delete
//username
// todoId
//data vaiildation
//check the owenership
//delete the respective todo

app.post("/delete-item", isAuth, rateLimiting, async (req, res) => {
 // console.log(req.body);
  const { id } = req.body;
  const username = req.session.user.username;

  if (!id) {
    return res.send({
      status: 400,
      message: "Missing credentials",
    });
  }

  //find the todo with todoID
  try {
    const todoDetails = await todoModel.findOne({ _id: id });

    //check ownership
    if (todoDetails.username !== username) {
      return res.send({
        status: 403,
        message: "Not allowed to delete, authorisation failed",
      });
    }

    //update the todo in DB

    const todoDb = await todoModel.findOneAndDelete({ _id: id });
    //console.log("hello", todoDb);

    return res.send({
      status: 200,
      message: "Todo has been deleted successfully",
    });
  } catch (error) {
    return res.send({
      status: 500,
      message: "Database error",
      error: error,
    });
  }
});

// app.get("/read-item", isAuth, async (req, res) => {
//   const username = req.session.user.username;

//   try {
//     const todoDb = await todoModel.find({ username: username });
//     console.log(todoDb);
//     return res.send({
//       status: 200,
//       message: "Read successfull",
//       data: todoDb,
//     });
//   } catch (error) {
//     return res.send({
//       status: 500,
//       message: "Database Error",
//       error: error,
//     });
//   }
// });

//pagination_dashboard?skip=10
app.get("/pagination_dashboard", isAuth, async (req, res) => {
  // Retrieves the value of the "skip" query parameter from the request. If the parameter is not provided, it defaults to 0
  const SKIP = req.query.skip || 0;
  const LIMIT = 5; // set limit to 5
  const username = req.session.user.username;//Extracts the username from the user session.

  //mongodb aggregate functions
  //pagination
  //match

  try {
    const todoDb = await todoModel.aggregate([
      {
        $match: { username: username }, //stage filters documents in the todoModel
      },
      {
        $facet: { //stage allows multiple aggregation pipelines to be executed within the same query
          data: [{ $skip: parseInt(SKIP) }, { $limit: LIMIT }],
        },
      },
    ]);

    //console.log(todoDb[0].data);

    return res.send({
      status: 200,
      message: "Read  successfull",
      data: todoDb[0].data,
    });
  } catch (error) {
    return res.send({
      status: 500,
      message: "Database Error",
      error: error,
    });
  }
});

app.listen(PORT, ()=>{
  console.log(clc.yellow("Server is running on:"));
    console.log(clc.yellow.underline(`http://localhost:${PORT}/`));
});