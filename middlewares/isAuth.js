// Import your isAuth middleware
const isAuth = (req, res, next) => {
    if (req.session.isAuth) { // if it is true then calling the function next()
      next();
    } else {
      // If the user is not authenticated, middleware redirect to the login page
      return res.redirect("/login");
    }
  };
  
  module.exports = { isAuth };