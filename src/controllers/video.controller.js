import mongoose from "mongoose";
import { Video } from "../models/video.model.js";
import { ApiError } from "../utils/apiError.js";
import { ApiResponse } from "../utils/apiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";

const createVideo = asyncHandler(async (req, res) => {
    const { videoFile, thumbnail, title, description, duration, isPublished } = req.body;

    if (!videoFile || !thumbnail || !title || !description || !duration) {
        throw new ApiError(400, "All required video fields must be provided");
    }

    const video = await Video.create({
        videoFile,
        thumbnail,
        title,
        description,
        duration,
        isPublished,
        owner: req.user?._id
    });

    return res.status(201).json(new ApiResponse(201, video, "Video created successfully"));
});

const getAllVideos = asyncHandler(async (req, res) => {
    const { owner, isPublished } = req.query;

    const filter = {};

    if (owner) {
        filter.owner = owner;
    }

    if (typeof isPublished !== "undefined") {
        filter.isPublished = isPublished === "true";
    }

    const videos = await Video.find(filter).sort({ createdAt: -1 });

    return res.status(200).json(new ApiResponse(200, videos, "Videos fetched successfully"));
});

const getVideoById = asyncHandler(async (req, res) => {
    const { videoId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(videoId)) {
        throw new ApiError(400, "Invalid video id");
    }

    const video = await Video.findById(videoId).populate("owner", "username fullName avatar");

    if (!video) {
        throw new ApiError(404, "Video not found");
    }

    return res.status(200).json(new ApiResponse(200, video, "Video fetched successfully"));
});

const updateVideo = asyncHandler(async (req, res) => {
    const { videoId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(videoId)) {
        throw new ApiError(400, "Invalid video id");
    }

    const video = await Video.findById(videoId);

    if (!video) {
        throw new ApiError(404, "Video not found");
    }

    if (String(video.owner) !== String(req.user?._id)) {
        throw new ApiError(403, "You are not allowed to update this video");
    }

    const { title, description, thumbnail, isPublished } = req.body;

    if (title !== undefined) video.title = title;
    if (description !== undefined) video.description = description;
    if (thumbnail !== undefined) video.thumbnail = thumbnail;
    if (isPublished !== undefined) video.isPublished = isPublished;

    await video.save();

    return res.status(200).json(new ApiResponse(200, video, "Video updated successfully"));
});

const deleteVideo = asyncHandler(async (req, res) => {
    const { videoId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(videoId)) {
        throw new ApiError(400, "Invalid video id");
    }

    const video = await Video.findById(videoId);

    if (!video) {
        throw new ApiError(404, "Video not found");
    }

    if (String(video.owner) !== String(req.user?._id)) {
        throw new ApiError(403, "You are not allowed to delete this video");
    }

    await video.deleteOne();

    return res.status(200).json(new ApiResponse(200, {}, "Video deleted successfully"));
});

const togglePublishStatus = asyncHandler(async (req, res) => {
    const { videoId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(videoId)) {
        throw new ApiError(400, "Invalid video id");
    }

    const video = await Video.findById(videoId);

    if (!video) {
        throw new ApiError(404, "Video not found");
    }

    if (String(video.owner) !== String(req.user?._id)) {
        throw new ApiError(403, "You are not allowed to update this video");
    }

    video.isPublished = !video.isPublished;
    await video.save();

    return res
        .status(200)
        .json(new ApiResponse(200, video, "Video publish status updated successfully"));
});

export {
    createVideo,
    getAllVideos,
    getVideoById,
    updateVideo,
    deleteVideo,
    togglePublishStatus
};
