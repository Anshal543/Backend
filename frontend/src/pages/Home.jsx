import { useState, useEffect } from 'react'
import api from '../api/axios'
import VideoCard from '../components/VideoCard'

function SkeletonCard() {
  return (
    <div className="flex flex-col gap-2 animate-pulse">
      <div className="aspect-video bg-zinc-800 rounded-xl" />
      <div className="flex gap-3 px-0.5">
        <div className="w-9 h-9 rounded-full bg-zinc-800 flex-shrink-0 mt-0.5" />
        <div className="flex-1 flex flex-col gap-2 pt-1">
          <div className="h-3.5 bg-zinc-800 rounded w-full" />
          <div className="h-3.5 bg-zinc-800 rounded w-4/5" />
          <div className="h-3 bg-zinc-800 rounded w-1/2" />
        </div>
      </div>
    </div>
  )
}

export default function Home() {
  const [videos, setVideos] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    api
      .get('/videos?isPublished=true')
      .then((res) => setVideos(res.data.data || []))
      .catch(() => setError('Could not load videos. Make sure the backend is running.'))
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-5 p-6">
        {Array.from({ length: 12 }).map((_, i) => (
          <SkeletonCard key={i} />
        ))}
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-3 text-center px-4">
        <span className="text-4xl">📺</span>
        <p className="text-zinc-400 text-sm">{error}</p>
      </div>
    )
  }

  if (videos.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-3">
        <span className="text-4xl">🎬</span>
        <p className="text-zinc-400 text-sm">No videos yet. Upload the first one!</p>
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-5 p-6">
      {videos.map((video) => (
        <VideoCard key={video._id} video={video} />
      ))}
    </div>
  )
}
