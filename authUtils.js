const validator = require("validator");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const cleanupAndValidate = ({ email, password, username, name }) => {
  return new Promise((resolve, reject) => {
    // Check if any of the required fields are missing
    if (!email || !username || !name || !password) {
      reject("Missing Credentials");
    }
// Check the types of email, username, and password
    if (typeof email !== "string") reject("Invalid email type");
    if (typeof username !== "string") reject("Invalid username type");
    if (typeof password !== "string") reject("Invalid password type");

// Check the length of username and password
    if (username.length <= 2 || username.length > 30)
      reject("Username length should be 3-30 only");
    if (password.length <= 2 || password.length > 30)
      reject("password length should be 3-30 only");

      // Validate email using the validator library (assuming it's imported)
    if (!validator.isEmail(email)) {
      reject("Invalid Email Format");
    }
 // If all checks pass, resolve the Promise
    resolve();
  });
};
//Function to generate a JWT token based on the provided email and a secret key
const genrateJWTToken = (email) => {
  //uses the jwt.sign method from a library to create a signed token.
  const token = jwt.sign(email, process.env.SECRET_KEY);
  return token;
};
// Function to send an email for email verification
const sendVerificationToken = ({ email, verifiedToken }) => {

// Creating a nodemailer transporter with Gmail SMTP settings
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    service: "Gmail",
    auth: {
      user: "shibasish3210@gmail.com",
      pass: "aduq ncro thlt ofeu",
    },
  });
// Email options, including sender, recipient, subject, and verification link in HTML content
  const mailOptions = {
    from: "shibasish3210@gmail.com",
    to: email,
    subject: "Email Verification for TODO APP",
    html: `Click <a href='http://localhost:8000/verifytoken/${verifiedToken}' > Here </a>`,
  };
// Sending the email and logging errors or success information to the console
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) console.log(error);
    else console.log("Email has been sent successfully: " + info.response);
  });
};
// Exporting the functions for use in other parts of the application
module.exports = { 
  cleanupAndValidate, 
  genrateJWTToken, 
  sendVerificationToken 
};