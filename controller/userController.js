const { statusCodes } = require('http-status-codes');
const User = require('../model/userModel')


const userController = {
    getall : async (req,res) =>{ 
       try{
        const users = await User.find({})
        res.json({ users, length: users.length})
       }catch(err){
        return res.status(statusCodes.INTERNAL_SERVER_ERROR).json({msg: err.message})
       }
    },
    getCurrentUser : async (req,res) => {
try{
    res.json({msg: "get login user info"})
}catch(err){
    return res.status(statusCodes.INTERNAL_SERVER_ERROR).json({msg: err.message})
}
     },
    updateUser: async (req,res) => { 
try{
    res.json({msg: "update user info"})
}catch(err){
    return res.status(statusCodes.INTERNAL_SERVER_ERROR).json({msg: err.message})
}
    },
    deleteUser: async (req,res) => {
try{
    res.json({msg: "delete user"})
}catch(err){
    return res.status(statusCodes.INTERNAL_SERVER_ERROR).json({msg: err.message})
}
     },
     changeRole: async (req,res) => {
        try{
            res.json({msg: "change user role"})
        }catch(err){
            return res.status(statusCodes.INTERNAL_SERVER_ERROR).json({msg: err.message})
        }
             },

    
}

module.exports = userController