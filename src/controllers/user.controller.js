import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/apiError.js';
import { User } from '../models/user.model.js';
import { uploadOnCloudinary } from '../utils/cloudinary.js';
import { ApiResponse } from '../utils/apiResponse.js';


const registerUser = asyncHandler(async (req, res, next) => {
    // get user detail from frontend
    // validation of user detail - not empty
    // check if user already exists : email, username
    // check for images, check for avatar
    // upload them to cloudinary
    // create user object, create entry in db
    // remove password and refresh token field from response
    // check for user creation, return response

    const { username, email, fullName, password } = req.body;
    // console.log("email", email);
    // console.log(req.body);

    if ([username, email, fullName, password].some(field => field?.trim() === "")) {
        throw new ApiError(400, "All fields are required");
    }

    const existedUser = await User.findOne({
        $or: [{ email }, { username }]
    })
    if(existedUser) {
        throw new ApiError(409, "User already exists");
    }
    const avatarLocalPath = req.files?.avatar[0]?.path;
    // console.log(req.files);
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;
    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
        coverImageLocalPath = req.files.coverImage[0].path;
    }

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar file is required");
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if(!avatar){
        throw new ApiError(500, "avatar file is not uploaded");
    }

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username:username.toLowerCase()
    })

    const createUser = await User.findById(user._id).select("-password -refreshToken");

    if(!createUser){
        throw new ApiError(500, "User is not created");
    }
    res.status(201).json(new ApiResponse(201, createUser, "User created successfully"));
});

export { registerUser };