import { Link } from 'react-router-dom'

function formatDuration(seconds) {
  if (!seconds) return '0:00'
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = Math.floor(seconds % 60)
  if (h > 0) return `${h}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`
  return `${m}:${s.toString().padStart(2, '0')}`
}

function formatViews(views) {
  if (!views) return '0 views'
  if (views >= 1_000_000) return `${(views / 1_000_000).toFixed(1)}M views`
  if (views >= 1_000) return `${(views / 1_000).toFixed(1)}K views`
  return `${views} views`
}

function timeAgo(date) {
  const diff = (Date.now() - new Date(date)) / 1000
  if (diff < 60) return 'just now'
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  if (diff < 2592000) return `${Math.floor(diff / 86400)}d ago`
  if (diff < 31536000) return `${Math.floor(diff / 2592000)}mo ago`
  return `${Math.floor(diff / 31536000)}y ago`
}

export default function VideoCard({ video }) {
  const owner = video.owner || {}

  return (
    <div className="flex flex-col gap-2 group">
      <Link to={`/video/${video._id}`} className="block">
        <div className="relative aspect-video rounded-xl overflow-hidden bg-zinc-800">
          {video.thumbnail ? (
            <img
              src={video.thumbnail}
              alt={video.title}
              className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
            />
          ) : (
            <div className="w-full h-full flex items-center justify-center text-zinc-600 text-sm">
              No thumbnail
            </div>
          )}
          <span className="absolute bottom-1.5 right-1.5 bg-black/80 text-white text-xs px-1.5 py-0.5 rounded font-medium">
            {formatDuration(video.duration)}
          </span>
        </div>
      </Link>

      <div className="flex gap-3 px-0.5">
        <Link to={`/channel/${owner.username}`} className="flex-shrink-0 mt-0.5">
          {owner.avatar ? (
            <img
              src={owner.avatar}
              alt={owner.username}
              className="w-9 h-9 rounded-full object-cover"
            />
          ) : (
            <div className="w-9 h-9 rounded-full bg-zinc-700 flex items-center justify-center text-zinc-400 text-sm font-bold">
              {(owner.fullName || owner.username || '?')[0].toUpperCase()}
            </div>
          )}
        </Link>

        <div className="flex flex-col gap-0.5 min-w-0">
          <Link to={`/video/${video._id}`}>
            <h3 className="text-sm font-medium text-white line-clamp-2 leading-snug hover:text-zinc-200">
              {video.title}
            </h3>
          </Link>
          <Link
            to={`/channel/${owner.username}`}
            className="text-xs text-zinc-400 hover:text-white truncate"
          >
            {owner.fullName || owner.username}
          </Link>
          <p className="text-xs text-zinc-500">
            {formatViews(video.views)} &bull; {timeAgo(video.createdAt)}
          </p>
        </div>
      </div>
    </div>
  )
}
