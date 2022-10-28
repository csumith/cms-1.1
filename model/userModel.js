const mongoose = require('mongoose')
const UserSchema = new mongoose.Schema({
    name:{
       type: String,
       required:true,
       trim:true
     
    },
    email: {
       type: String,
       required:true,
       trim:true,
     
    },

    mobile: {
    type: String,
    required:true,
     trim:true,
     unique: true


    },
    password: {
      type: String,
      required:true,
      trim:true,
      
    },
    role: {
     type: String,
     default :"student",
      enum: ["student", "trainer", "superadmin"]
    },
      address :{
      type: Object,
      default: {
      }
     },
     image: {
        type: Object,
        default : {
        url : "https://storiavoce.com/wp-content/plugins.Lightbox/images/No-image-found.jpg"
        
        }
     }
    },{
        collection: "users",
        timestamps: true
     
})

module.exports = mongoose.model("User",UserSchema)