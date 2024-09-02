const accessModel = require("../Models/accessModel");
// Middleware function for rate limiting
const rateLimiting = async (req, res, next)=>{
// log the current session id    
console.log(req.session.id);
const sessionId = req.session.id;
// check if the person if making the request for the first time
// find the entry with this sessionId
try {
    const accessDb = await accessModel.findOne({
        sessionId : sessionId
    })
    //If no entry exists, create a new object in the accessModel
    if(!accessDb){
const accessObj = new accessModel({
    sessionId : sessionId,
    time : Date.now(),
})
await accessObj.save();
// call next middleware in the stack
next();
return;
    }

 // if accessDb is not null, this is not a first request compare the time
    //console.log(accessDb.time);
    //console.log(Date.now());
    const diff = (Date.now() - accessDb.time)/1000;
    console.log(diff);
// If the time difference is less than 5 seconds, send a rate-limiting respo    
    if(diff < 5){
        return res.send({
            status : 400,
            message : "Too many request please wait some time",
        });
    }
    // // Update the time in the accessModel and call the next middleware
    await accessModel.findOneAndUpdate({sessionId}, {time : Date.now() });
    next();
} catch (error) {
    return res.send({
        status : 500,
        message : "Database error",
        error : error,
    });
}
};
// Export the rateLimiting middleware for use in other parts of the application
module.exports = rateLimiting;