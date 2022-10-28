 const {StatusCodes} = require('http-status-codes')
const authController = {
    register: async (req,res) =>{
        
        try{
             res.json({msg: "register"})
        }catch(err){
            return res.status(StatusCodes.INTERNAL_SERVAL_ERROR).json({msg: err.message})
        }
    },
    login: async (req,res) =>{
        try{
             res.json({msg: "login"})
        }catch(err){
            return res.status(StatusCodes.INTERNAL_SERVAL_ERROR).json({msg: err.message})
        }
    },
    logout: async (req,res) =>{
  try{
             res.json({msg: "logout"})
        }catch(err){
            return res.status(StatusCodes.INTERNAL_SERVAL_ERROR).json({msg: err.message})
        }
    },
    refereshToken: async (req,res) =>{
  try{
             res.json({msg: "refreshToken"})
        }catch(err){
            return res.status(StatusCodes.INTERNAL_SERVAL_ERROR).json({msg: err.message})
        }
    },
    resetPassword: async (req,res) =>{
  try{
             res.json({msg: "resetPassword"})
        }catch(err){
            return res.status(StatusCodes.INTERNAL_SERVAL_ERROR).json({msg: err.message})
        }
    },

}
module.exports = authController
