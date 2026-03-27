import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import api from '../api/axios'
import { useAuth } from '../context/AuthContext'
import CommentSection from '../components/CommentSection'

function formatViews(n) {
  if (!n) return '0'
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
  return n.toString()
}

export default function VideoPage() {
  const { videoId } = useParams()
  const { user } = useAuth()
  const [video, setVideo] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [liked, setLiked] = useState(false)
  const [likeLoading, setLikeLoading] = useState(false)
  const [subscribed, setSubscribed] = useState(false)
  const [subLoading, setSubLoading] = useState(false)
  const [descExpanded, setDescExpanded] = useState(false)

  useEffect(() => {
    setLoading(true)
    setError(null)
    api
      .get(`/videos/${videoId}`)
      .then((res) => setVideo(res.data.data))
      .catch(() => setError('Video not found or could not be loaded.'))
      .finally(() => setLoading(false))
  }, [videoId])

  const handleLike = async () => {
    if (!user || likeLoading) return
    setLikeLoading(true)
    try {
      await api.post(`/likes/toggle/v/${videoId}`)
      setLiked((prev) => !prev)
    } catch (err) {
      console.error(err)
    } finally {
      setLikeLoading(false)
    }
  }

  const handleSubscribe = async () => {
    if (!user || !video || subLoading) return
    setSubLoading(true)
    try {
      await api.post(`/subscriptions/c/${video.owner._id}`)
      setSubscribed((prev) => !prev)
    } catch (err) {
      console.error(err)
    } finally {
      setSubLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="max-w-4xl mx-auto p-6 animate-pulse">
        <div className="aspect-video bg-zinc-800 rounded-2xl mb-4" />
        <div className="h-6 bg-zinc-800 rounded w-3/4 mb-3" />
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-full bg-zinc-800" />
          <div className="flex flex-col gap-1.5">
            <div className="h-3.5 bg-zinc-800 rounded w-32" />
            <div className="h-3 bg-zinc-800 rounded w-20" />
          </div>
        </div>
      </div>
    )
  }

  if (error || !video) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-3">
        <span className="text-4xl">😕</span>
        <p className="text-zinc-400 text-sm">{error || 'Video not found.'}</p>
        <Link to="/" className="text-red-400 hover:text-red-300 text-sm">
          ← Back to Home
        </Link>
      </div>
    )
  }

  const owner = video.owner || {}
  const isOwner = user && user._id === (owner._id || owner)

  return (
    <div className="max-w-4xl mx-auto p-6">
      {/* Video player */}
      <div className="aspect-video bg-black rounded-2xl overflow-hidden mb-4">
        <video
          src={video.videoFile}
          controls
          autoPlay
          className="w-full h-full"
          controlsList="nodownload"
        />
      </div>

      {/* Title */}
      <h1 className="text-xl font-bold text-white mb-3 leading-snug">{video.title}</h1>

      {/* Channel + actions row */}
      <div className="flex items-center justify-between flex-wrap gap-4 pb-4 border-b border-zinc-800">
        <div className="flex items-center gap-3">
          <Link to={`/channel/${owner.username}`}>
            {owner.avatar ? (
              <img
                src={owner.avatar}
                alt={owner.username}
                className="w-10 h-10 rounded-full object-cover"
              />
            ) : (
              <div className="w-10 h-10 rounded-full bg-zinc-700 flex items-center justify-center text-zinc-400 font-bold">
                {(owner.fullName || owner.username || '?')[0].toUpperCase()}
              </div>
            )}
          </Link>
          <div>
            <Link
              to={`/channel/${owner.username}`}
              className="text-sm font-semibold text-white hover:text-zinc-300"
            >
              {owner.fullName}
            </Link>
            <p className="text-xs text-zinc-400">@{owner.username}</p>
          </div>

          {user && !isOwner && (
            <button
              onClick={handleSubscribe}
              disabled={subLoading}
              className={`ml-2 px-5 py-1.5 rounded-full text-sm font-semibold transition-colors ${
                subscribed
                  ? 'bg-zinc-700 text-white hover:bg-zinc-600'
                  : 'bg-white text-black hover:bg-zinc-200'
              }`}
            >
              {subscribed ? 'Subscribed' : 'Subscribe'}
            </button>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleLike}
            disabled={!user || likeLoading}
            className={`flex items-center gap-2 px-4 py-1.5 rounded-full text-sm font-medium transition-colors ${
              liked
                ? 'bg-blue-600 text-white'
                : 'bg-zinc-800 text-white hover:bg-zinc-700'
            } disabled:opacity-50 disabled:cursor-not-allowed`}
          >
            👍 {liked ? 'Liked' : 'Like'}
          </button>
        </div>
      </div>

      {/* Description */}
      <div
        className="bg-zinc-800/60 rounded-xl p-4 my-4 cursor-pointer"
        onClick={() => setDescExpanded(!descExpanded)}
      >
        <p className="text-xs text-zinc-400 mb-1.5">
          {formatViews(video.views)} views &bull;{' '}
          {new Date(video.createdAt).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
          })}
        </p>
        <p
          className={`text-sm text-zinc-300 whitespace-pre-wrap ${
            !descExpanded ? 'line-clamp-3' : ''
          }`}
        >
          {video.description}
        </p>
        {video.description?.length > 150 && (
          <button className="text-xs text-zinc-400 hover:text-white mt-1 font-medium">
            {descExpanded ? 'Show less' : 'Show more'}
          </button>
        )}
      </div>

      {/* Comments */}
      <div className="mt-6">
        <CommentSection videoId={videoId} />
      </div>
    </div>
  )
}
