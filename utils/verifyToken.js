const jwt = require('jsonwebtoken');
const User = require("../models/userModel");




const verifyToken = async(req,res,next) => {
   
    // return async (req, res, next) => {
        const token = req.header('Authorization').replace('Bearer ', '')
        if (!token) {
            return res.status(401).send("Token not found");
        }
        try {
          
            const decoded = jwt.verify(token, process.env.JWT_SECRET)
           

            const user = await User.findOne({ email: decoded.email })
            if (user.role === "admin") {
                req.user = user;
                next();
            }
            else {
                console.log("you don't have admin access");
                res.status(401).send("Admin authorization required");
            }



        } catch (error) {
            console.error('Error verifying token:', error);
            res.status(400).send('Invalid token.');
        }
    // }
}

module.exports = verifyToken;