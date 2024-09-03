import { ApiError } from "../utils/apiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";


export const verifyJWT = asyncHandler(async (req, res, next) => {
    try {
        // console.log(req.cookies);
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")
        
        // const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NmQ3NDUwZTFkZjAxYTVlYjJhNzk4ZmQiLCJlbWFpbCI6ImFuc2hhbEBnbWFpbC5jb20iLCJ1c2VybmFtZSI6ImFuc2hhbCIsImZ1bGxOYW1lIjoiYW5zaGFsIGFsaSIsImlhdCI6MTcyNTM4NDY0MSwiZXhwIjoxNzI1NDcxMDQxfQ.kon3R8PpOEDy-xb77ciPfkRGs6KQqV9V8JztXycT3Ag'

        // console.log(token);
        if (!token) {
            throw new ApiError(401, "Unauthorized this")
        }
        const decode = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
        const user = await User.findById(decode?._id).select("-password -refreshToken")
        if (!user) {
            throw new ApiError(401, "Unauthorized")
        }
        req.user = user
        next()
    } catch (error) {
        throw new ApiError(401, error.message || "Unauthorized")
    }


}) 