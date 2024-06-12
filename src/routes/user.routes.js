import { Router }from "express";
import { 
    loginUser,
    getUserChannelProfile, 
    logoutUser,
    getCurrentUser,
    updateAccountDetails,
    changeCurrentPassword, 
    UpdateUserAvatar, 
    updateUserCoverImage,
    refreshAccessToken,
    getWatchHistory,
    registerUser } from "../controllers/user.controller.js";
import {upload} from "../middlewares/multer.middleware.js"
import { veriftJWT } from "../middlewares/auth.middleware.js";
// import { loginUser } from "../controllers/user.controller.js";



const router = Router()

router.route("/register").post(
    upload.fields([
        {
        name:"avatar",
        maxCount:1
        },  
        {
        name:"coverImage",
        maxCount:1,
    } 
    ]),registerUser)

    // upload.fields ->multer middleware use kariyu -> route ma add kariyu

    router.route("/login").post(loginUser)

    //secured routes

    //verifyJWT thi user login 6 ke nay e khabar pade
    router.route("/logout").post( veriftJWT,logoutUser)
    
    router.route("/refresh-token").post(refreshAccessToken)

    router.route("/change-passsword").post(veriftJWT,changeCurrentPassword)

    router.route("/current-user").get(veriftJWT,getCurrentUser)

    // badhi details update no thay atla mate patch use karvanu
    router.route("/update-account").patch(veriftJWT,updateAccountDetails)

    router.route("/avatar").patch(veriftJWT,upload.single("avatar"),UpdateUserAvatar)

    router.route("/cover-Image").patch(veriftJWT,upload.single("coverImage"),updateUserCoverImage)

    router.route("/c/:username").get(veriftJWT,getUserChannelProfile)

    router.route("/history").get(veriftJWT,getWatchHistory)
export default router

