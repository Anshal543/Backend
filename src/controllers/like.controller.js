import mongoose from "mongoose";
import { Like } from "../models/like.model.js";
import { ApiError } from "../utils/apiError.js";
import { ApiResponse } from "../utils/apiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";

const toggleLikeByTarget = async (req, targetField, targetId) => {
    if (!mongoose.Types.ObjectId.isValid(targetId)) {
        throw new ApiError(400, `Invalid ${targetField} id`);
    }

    const existingLike = await Like.findOne({
        [targetField]: targetId,
        likedBy: req.user?._id
    });

    if (existingLike) {
        await existingLike.deleteOne();
        return { liked: false };
    }

    const like = await Like.create({
        [targetField]: targetId,
        likedBy: req.user?._id
    });

    return { liked: true, like };
};

const toggleVideoLike = asyncHandler(async (req, res) => {
    const result = await toggleLikeByTarget(req, "video", req.params.videoId);

    return res.status(200).json(new ApiResponse(200, result, "Video like updated successfully"));
});

const toggleCommentLike = asyncHandler(async (req, res) => {
    const result = await toggleLikeByTarget(req, "comment", req.params.commentId);

    return res.status(200).json(new ApiResponse(200, result, "Comment like updated successfully"));
});

const toggleTweetLike = asyncHandler(async (req, res) => {
    const result = await toggleLikeByTarget(req, "tweet", req.params.tweetId);

    return res.status(200).json(new ApiResponse(200, result, "Tweet like updated successfully"));
});

const getLikedVideos = asyncHandler(async (req, res) => {
    const likedVideos = await Like.find({
        likedBy: req.user?._id,
        video: { $exists: true, $ne: null }
    })
        .populate("video")
        .sort({ createdAt: -1 });

    return res.status(200).json(new ApiResponse(200, likedVideos, "Liked videos fetched successfully"));
});

export {
    toggleVideoLike,
    toggleCommentLike,
    toggleTweetLike,
    getLikedVideos
};
