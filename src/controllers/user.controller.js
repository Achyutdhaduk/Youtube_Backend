import { asyncHandler } from "../utils/asynchandler.js"
import {ApiError} from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import {uploadOnCloudinary, deleteFileFromCloudinary} from "../utils/cloudnary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import  jwt  from "jsonwebtoken";
import mongoose from "mongoose";


// User ma :capital U hase te mongodb na User no data check mate 

const generateAccessAndRefreshTokens = async(userId)=>
{
    try {
        const user =  await User.findById(userId)
        const accessToken = user.generateAccessToken()
       const refreshToken =  user.generateRefreshToken()

       user.refreshToken = refreshToken
       await user.save({validateBeforeSave : false})

       return {accessToken,refreshToken}
    } catch (error) 
    {
        throw new ApiError(500,"Something went wrong while generating referesh and access token")
        
    }
}


const registerUser  = asyncHandler(async (req,res)=>{
    
    // --get user details from frontend
     
    const {fullName, email, username, password} = req.body
    //console.log("email:",email)
    //console.log(req.body);

    // -- validation – not empty

    if(
        [fullName,email,username,password].some((field)=>
        field?.trim() === "")
    ){
        throw new ApiError(400,"All fields are required")
    }

    // --check if user already exists:username,email

    const existedUser = await User.findOne({
        $or:[{username},{email}]
    })
    if(existedUser){
        throw new ApiError(409, "User with email or username already Exists")
    }

    // --check for images, check for avatar

        const avatarLocalPath = req.files?.avatar[0]?.path; 
   
//   //  const coverImageLocalPath = req.files?.coverImage[0]?.path;
   
  let coverImageLocalPath;
  if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
      coverImageLocalPath = req.files.coverImage[0].path
  }
  

    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar file is required")
    }

    // --upload them to cloudinary , avatar

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar){
        throw new ApiError(400, "Avatar-cloud file is required")
    }

    // --create user object – create entry in db
    
    const user = await User.create({
        fullName,
        avatar:avatar.url,
        coverImage:coverImage.url || "",
        email,
        password,
        username:username.toLowerCase()

    })
    
    // --remove password and refresh token field from response

    const createUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    // --check for user creation

    if(!createUser){
        throw new ApiError(500,"Something went wrong while registering the user")
    }

    // --Retrun res
    
    return res.status(201).json(
        new ApiResponse(200, createUser,"User registered Successfully")
    )
})



const loginUser = asyncHandler(async(req,res)=>{

    // req body -> data
    // usernaem or email
    // find the user
    // password check
    // access and refresh token
    // send cookie 

     // req body -> data

    const {email,username,password} =req.body
     // usernaem or email

     // if(!(username || email)){throw new ApiError(400,"username or email required")}
    if(!username && !email){
        throw new ApiError(400,"username and password is required")
    }

    // find the user

   const user =  await User.findOne({
        $or:[{username},{email}]
    })

    if(!user){
        throw new ApiError(404,"User does not exist")
    }

     // password check


   const isPasswordValid = await user.isPasswordCorrect(password)

    if(!isPasswordValid){
        throw new ApiError(404,"Invalid user credentials")
    }


     // access and refresh token
    const {accessToken,refreshToken}= await  generateAccessAndRefreshTokens(user._id)

const loggedInUser = await User.findById(user._id).select("-password -refreshToken")


// send cookie

const options ={
    // http only and secure: true  karvathi cookie ma change backend thi thase frontend thi nai kari sakay. frontend thi khali joy sakay
    httpOnly: true, 
    secure : true,
}
// cookie use karva app.js ma app.use cookiparser add karel 6 atle .cookie karine vapari sakayu
return res.status(200)
.cookie("accessToken",accessToken,options)
.cookie("refreshToken",refreshToken,options)
.json(
    new ApiResponse(
        200,
        {
            user: loggedInUser, accessToken,
            refreshToken
        },
        "User logged In Successfully"
        
    )
)

}

)


const logoutUser = asyncHandler(async(req,res)=>{
   await  User.findByIdAndUpdate(
        req.user._id,
        {
            $unset:{
                refreshToken: 1,
            }
        },
        {
            new : true
        }

    )

    const options = {
        httpOnly : true,
        secure : true
    }

    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(new ApiResponse(200,{},"User logged Out"))
})

const refreshAccessToken = asyncHandler(async(req,res)=>{

    //je user generate karse
  
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
    //generate no thay to
    if(!incomingRefreshToken){
        throw new ApiError(401,"unauthorized request")
    }

    //verify karse and decoded token verify sathe (origial)
   try {
     const decodedToken = jwt.verify(
         incomingRefreshToken,
         process.env.REFRESH_TOKEN_SECRET
     );
 
     //token verify thay jay pachi decodedtoken thi userid fatch karse -> user detils lese
     const user = await User.findById(decodedToken?._id);
     
     //user details no male to token invalid hase
     if(!user){
         throw new ApiError(401,"Invalid refersh token");
     }
 
     //incoming token match with user taken
     if(incomingRefreshToken != user?.refreshToken){
         throw new ApiError(401,"Refresh toekn is expired or used")
     }
     
     const options={
         httpOnly:true,
         secure : true
     }
     // toekn expire thay gyu to new generate karse
 
     const {accessToken,newrefreshToken} = await generateAccessAndRefreshTokens(user._id)
 
 
     return res
     .status(200)
     .cookie("accessToken",accessToken,options)
     .cookie("refreshToken",newrefreshToken,options)
     .json(
         new ApiResponse(
             200,
             {accessToken,refreshToken:newrefreshToken},
             "Access token refreshed"
         )
     )
 
   } catch (error) {
    throw new ApiError(401, error?.message || "Invalid refresh token")
   }
})


const changeCurrentPassword = asyncHandler(async(req,res)=>{

 const  {oldpassword,newpassword} = req.body

 const user = await User.findById(req.user?._id)
 const isPasswordCorrect = await user.isPasswordCorrect(oldpassword)

 if(!isPasswordCorrect){
    throw new ApiError(400,"Invalid old Password")
 }

 user.password = newpassword
 await user.save({validateBeforeSave:false})

 return res
 .status(200)
 .json(new ApiResponse(200,"Password changed successfully"))
})


const getCurrentUser = asyncHandler(async(req,res)=>{
    return res
    .status(200)
    .json(new ApiResponse(200,req.user,"current user fatched Successfully"))
})

const updateAccountDetails = asyncHandler(async(req,res)=>{

    const {fullName,email}=req.body

    if(!fullName || !email){
        throw new ApiError(400,"All field are required")
    }

    const user =await User.findByIdAndUpdate(req.user?._id,
        {
            $set:{
                fullName,
                email:email
            }
        },{new:true})
        .select("-password")


        return res
        .status(200)
        .json(new ApiResponse(200,user,"Account details updated successfully"))
})


const UpdateUserAvatar = asyncHandler(async(req,res)=>{
    const avatarLocalPath = req.file?.path
    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar file is missing")
    }
    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url){
        throw new ApiError(400,"Error while uploading on avatar")
    }

    const oldImageUrl = req.user?.avatar;

  const user =  await User.findByIdAndUpdate(
        req.user?._id,
        {
    $set:{
    avatar:avatar.url
        }
        },{new:true}
    ).select("-password")

    await deleteFileFromCloudinary(oldImageUrl);

    return res 
    .status(200)
    .json(
        new ApiResponse(200, user, "Avatar image updated successfully")
    )

})

const updateUserCoverImage = asyncHandler(async(req,res)=>{
    const coverImageLocalPath = req.file?.path

    if(!coverImageLocalPath){
        throw new ApiError(400,"Cover Image file is missing")
    }
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!coverImage.url){
        throw new ApiError(400,"Error ehile uploading on coverImage")
    }

    const oldImageUrl = req.user?.coverimage

    const user =await User.findByIdAndUpdate(
        req.user?._id,
        {
        $set:
        {
        coverImage:coverImage.url
        }
        },
        {new:true}
    ).select("-password")

    await deleteFileFromCloudinary(oldImageUrl);

    return res 
    .status(200)
    .json(
        new ApiResponse(200, user, "Cover image updated successfully")
    )

})

const getUserChannelProfile = asyncHandler(async(req,res)=>{


    //url mathi username lay lese
    const {username} = req.params

    if(!username?.trim()){
        throw new ApiError(400,"username is missing")
    }
    console.log(username);
    
    // username database ma gotse ane ani field lese using aggregate $match 

    const channel = await User.aggregate([
        {
            $match:{
                username: username?.toLowerCase()
            }
        },
        // $lookup subscriber field subscriber mate  and subscribedTo field  chanenel mate lese
        {
            // subscriber calculate karva mate: chanel goti levani ane count karvani
            $lookup:{
                from:"subscriptions",
                localField:"_id",
                foreignField:"channel",
                as:"subscribers"
            }
        },
        {
            // tame ketlane subscribe karo cho e find karva : subscriber(user pote) goti levano chenel mathi ane count karvana  
            $lookup:{
                from:"subscriptions",
                localField:"_id",
                foreignField:"subscriber",
                as:"subscribedTo"
            }
        },


        // subscriber count karva $size  and tame ketlane subscribe karo e count karva subscribeTo $size
        {
         $addFields:{
            subscribersCount:{
                $size:"$subscribers"

            },
            channelsSubscribedToCount:{
                $size:"$subscribedTo"
            },

            // tame subscribe karel hase to e field ma check karse tame ana subscriber ma cho ke nahi  :: $in array and object ma check karse
            isSubscribed:{
                $cond: {
                    if:{$in:[req.user?._id,"$subscribers.subscriber"]},
                    then: true,
                    else:false
                }
            }
         }   
        },

       

        // only selected field leva $project thi
        {
            $project:{
                 fullName:1,
                 username:1,
                 subscribersCount:1,
                 channelsSubscribedToCount:1,
                 isSubscribed:1,
                 avatar:1,
                 coverImage:1,
                 email:1,

            }
        } 
    ]) 
    
    console.log(channel+"aaaaaaaaa")
    if(!channel?.length){
        throw new ApiError(404,"channel does not exists")
    }

    return res
    .status(200)
    .json(new ApiResponse(200, channel[0], "channel profile fetched successfully"))
    console.log(channel)
})

const getWatchHistory = asyncHandler(async(req,res)=>{
    const user = await User.aggregate([
        {
            $match:{
                //direct id sathe match no thay kem ke e object sathe hoy atle object mathi id alag karva mate 
                _id: new mongoose.Types.ObjectId(req.user._id)
            }
        },
        {
            $lookup:{

                from:"videos",
                localField:"watchHistory",
                foreignField:"_id",
                as:"watchHistory",

                pipeline:[
                    {
                        $lookup:{
                            from:"users",
                            localField:"owner",
                            foreignField:"_id",
                            as:"owner",
                            
                            pipeline:[
                                {
                                    $project:{
                                        fullName:1,
                                        username:1,
                                        avatar:1,

                                    }
                                }
                            ]
                        }
                    },
                    {
                        $addFields:{
                            owner:{
                                $first:"$owner"
                            }
                        }
                    }
                ]

            }
        }
    ])

    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            user[0].watchHistory,"watch history fetched successfully"))
})

export{
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    UpdateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getWatchHistory
}