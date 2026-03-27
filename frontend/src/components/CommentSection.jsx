import { useState, useEffect } from 'react'
import api from '../api/axios'
import { useAuth } from '../context/AuthContext'

function timeAgo(date) {
  const diff = (Date.now() - new Date(date)) / 1000
  if (diff < 60) return 'just now'
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

export default function CommentSection({ videoId }) {
  const { user } = useAuth()
  const [comments, setComments] = useState([])
  const [loading, setLoading] = useState(true)
  const [newComment, setNewComment] = useState('')
  const [posting, setPosting] = useState(false)
  const [editingId, setEditingId] = useState(null)
  const [editContent, setEditContent] = useState('')

  useEffect(() => {
    api
      .get(`/comments/${videoId}`)
      .then((res) => setComments(res.data.data || []))
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [videoId])

  const handleAddComment = async (e) => {
    e.preventDefault()
    if (!newComment.trim() || posting) return
    setPosting(true)
    try {
      const res = await api.post(`/comments/${videoId}`, { content: newComment })
      setComments([{ ...res.data.data, owner: user }, ...comments])
      setNewComment('')
    } catch (err) {
      console.error(err)
    } finally {
      setPosting(false)
    }
  }

  const handleEdit = async (commentId) => {
    try {
      const res = await api.patch(`/comments/c/${commentId}`, { content: editContent })
      setComments(comments.map((c) => (c._id === commentId ? { ...c, content: res.data.data.content } : c)))
      setEditingId(null)
    } catch (err) {
      console.error(err)
    }
  }

  const handleDelete = async (commentId) => {
    try {
      await api.delete(`/comments/c/${commentId}`)
      setComments(comments.filter((c) => c._id !== commentId))
    } catch (err) {
      console.error(err)
    }
  }

  return (
    <div>
      <h3 className="text-lg font-semibold text-white mb-5">
        {loading ? 'Comments' : `${comments.length} Comment${comments.length !== 1 ? 's' : ''}`}
      </h3>

      {/* Add comment */}
      {user && (
        <form onSubmit={handleAddComment} className="flex gap-3 mb-7">
          <img
            src={user.avatar}
            alt={user.username}
            className="w-9 h-9 rounded-full object-cover flex-shrink-0 mt-0.5"
          />
          <div className="flex-1">
            <input
              type="text"
              value={newComment}
              onChange={(e) => setNewComment(e.target.value)}
              placeholder="Add a comment..."
              className="w-full bg-transparent border-b border-zinc-700 focus:border-zinc-400 py-1.5 text-sm text-white placeholder-zinc-500 focus:outline-none transition-colors"
            />
            {newComment && (
              <div className="flex justify-end gap-2 mt-2">
                <button
                  type="button"
                  onClick={() => setNewComment('')}
                  className="text-xs text-zinc-400 hover:text-white px-3 py-1.5 rounded-full"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={posting}
                  className="text-xs bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-4 py-1.5 rounded-full font-medium"
                >
                  {posting ? 'Posting...' : 'Comment'}
                </button>
              </div>
            )}
          </div>
        </form>
      )}

      {/* Comment list */}
      {loading ? (
        <div className="flex flex-col gap-5">
          {[1, 2, 3].map((i) => (
            <div key={i} className="flex gap-3 animate-pulse">
              <div className="w-9 h-9 rounded-full bg-zinc-800 flex-shrink-0" />
              <div className="flex-1 flex flex-col gap-2 pt-1">
                <div className="h-3 bg-zinc-800 rounded w-1/4" />
                <div className="h-3 bg-zinc-800 rounded w-3/4" />
              </div>
            </div>
          ))}
        </div>
      ) : comments.length === 0 ? (
        <p className="text-sm text-zinc-500">No comments yet. Be the first to comment!</p>
      ) : (
        <ul className="flex flex-col gap-5">
          {comments.map((comment) => (
            <li key={comment._id} className="flex gap-3">
              {comment.owner?.avatar ? (
                <img
                  src={comment.owner.avatar}
                  alt={comment.owner.username}
                  className="w-9 h-9 rounded-full object-cover flex-shrink-0"
                />
              ) : (
                <div className="w-9 h-9 rounded-full bg-zinc-700 flex items-center justify-center text-zinc-400 text-sm font-bold flex-shrink-0">
                  {(comment.owner?.username || '?')[0].toUpperCase()}
                </div>
              )}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-sm font-medium text-white">
                    @{comment.owner?.username}
                  </span>
                  <span className="text-xs text-zinc-500">{timeAgo(comment.createdAt)}</span>
                </div>

                {editingId === comment._id ? (
                  <div>
                    <input
                      type="text"
                      value={editContent}
                      onChange={(e) => setEditContent(e.target.value)}
                      className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-zinc-500 mb-2"
                    />
                    <div className="flex gap-2">
                      <button
                        onClick={() => setEditingId(null)}
                        className="text-xs text-zinc-400 hover:text-white px-3 py-1 rounded-full"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={() => handleEdit(comment._id)}
                        className="text-xs bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded-full"
                      >
                        Save
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    <p className="text-sm text-zinc-300">{comment.content}</p>
                    {user && user._id === comment.owner?._id && (
                      <div className="flex gap-3 mt-1">
                        <button
                          onClick={() => {
                            setEditingId(comment._id)
                            setEditContent(comment.content)
                          }}
                          className="text-xs text-zinc-500 hover:text-white"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => handleDelete(comment._id)}
                          className="text-xs text-zinc-500 hover:text-red-400"
                        >
                          Delete
                        </button>
                      </div>
                    )}
                  </>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
