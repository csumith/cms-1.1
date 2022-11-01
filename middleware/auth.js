const {statusCodes} = require("http-status-codes")
const jwt = require("jsonwebtoken")

// logic to logged read user id

const auth = async (req,res,next) =>{
    try{

        const token = req.header('Authorization')

        jwt.verify(token , process.env.TOKEN_SECRET, (err,user)=> {
            if(err)
            return res.status(statusCodes.BAD_REQUEST).json({msg: "Invalid Token"})

          //  res.json({ id: user.id })

          req.user = user
        //  res.json({user})
          next() //  forwarding response to the next controller
        })

       

    }catch (err) {
        return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ msg: err.
            message})
    }
}
module.exports = auth