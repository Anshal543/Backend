import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function Register() {
  const { register } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ fullName: '', username: '', email: '', password: '' })
  const [avatar, setAvatar] = useState(null)
  const [avatarPreview, setAvatarPreview] = useState(null)
  const [coverImage, setCoverImage] = useState(null)
  const [coverPreview, setCoverPreview] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value })

  const handleAvatarChange = (e) => {
    const file = e.target.files[0]
    if (file) {
      setAvatar(file)
      setAvatarPreview(URL.createObjectURL(file))
    }
  }

  const handleCoverChange = (e) => {
    const file = e.target.files[0]
    if (file) {
      setCoverImage(file)
      setCoverPreview(URL.createObjectURL(file))
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    if (!avatar) {
      setError('Profile picture (avatar) is required.')
      return
    }
    setLoading(true)
    try {
      const formData = new FormData()
      Object.entries(form).forEach(([key, value]) => formData.append(key, value))
      formData.append('avatar', avatar)
      if (coverImage) formData.append('coverImage', coverImage)
      await register(formData)
      navigate('/login', { state: { message: 'Account created! Please sign in.' } })
    } catch (err) {
      setError(err.response?.data?.message || 'Registration failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const inputClass =
    'w-full bg-zinc-700 border border-zinc-600 rounded-xl px-4 py-2.5 text-sm text-white placeholder-zinc-500 focus:outline-none focus:border-zinc-400 transition-colors'

  return (
    <div className="min-h-screen bg-zinc-900 flex items-center justify-center px-4 py-8">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="text-center mb-8">
          <Link to="/" className="inline-block font-bold text-3xl">
            <span className="text-red-500">New</span>
            <span className="text-white">Tube</span>
          </Link>
          <p className="text-zinc-400 mt-2 text-sm">Create your account</p>
        </div>

        <div className="bg-zinc-800 rounded-2xl p-8 shadow-xl border border-zinc-700">
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            {/* Avatar preview */}
            <div className="flex items-center gap-4 mb-1">
              <label htmlFor="avatar-input" className="cursor-pointer">
                <div className="w-16 h-16 rounded-full bg-zinc-700 border-2 border-dashed border-zinc-500 hover:border-zinc-400 overflow-hidden flex items-center justify-center">
                  {avatarPreview ? (
                    <img src={avatarPreview} alt="avatar" className="w-full h-full object-cover" />
                  ) : (
                    <span className="text-2xl">👤</span>
                  )}
                </div>
              </label>
              <div>
                <p className="text-sm text-zinc-300 font-medium">Profile picture</p>
                <p className="text-xs text-zinc-500">Required &bull; Click to upload</p>
              </div>
              <input
                id="avatar-input"
                type="file"
                accept="image/*"
                onChange={handleAvatarChange}
                className="hidden"
              />
            </div>

            <div>
              <label className="block text-sm text-zinc-300 mb-1.5">Full Name</label>
              <input
                type="text"
                name="fullName"
                value={form.fullName}
                onChange={handleChange}
                required
                placeholder="Your full name"
                className={inputClass}
              />
            </div>

            <div>
              <label className="block text-sm text-zinc-300 mb-1.5">Username</label>
              <input
                type="text"
                name="username"
                value={form.username}
                onChange={handleChange}
                required
                placeholder="Choose a username"
                className={inputClass}
              />
            </div>

            <div>
              <label className="block text-sm text-zinc-300 mb-1.5">Email</label>
              <input
                type="email"
                name="email"
                value={form.email}
                onChange={handleChange}
                required
                placeholder="your@email.com"
                className={inputClass}
              />
            </div>

            <div>
              <label className="block text-sm text-zinc-300 mb-1.5">Password</label>
              <input
                type="password"
                name="password"
                value={form.password}
                onChange={handleChange}
                required
                placeholder="Create a password"
                className={inputClass}
              />
            </div>

            {/* Cover image */}
            <div>
              <label className="block text-sm text-zinc-300 mb-1.5">
                Cover Image <span className="text-zinc-500 text-xs">(optional)</span>
              </label>
              {coverPreview && (
                <div className="h-20 rounded-lg overflow-hidden mb-2">
                  <img src={coverPreview} alt="cover" className="w-full h-full object-cover" />
                </div>
              )}
              <input
                type="file"
                accept="image/*"
                onChange={handleCoverChange}
                className="w-full text-xs text-zinc-400 file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-medium file:bg-zinc-600 file:text-zinc-200 hover:file:bg-zinc-500 file:cursor-pointer"
              />
            </div>

            {error && (
              <div className="bg-red-500/10 border border-red-500/30 text-red-400 text-sm rounded-lg px-4 py-2.5">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-red-600 hover:bg-red-700 disabled:opacity-60 disabled:cursor-not-allowed text-white font-semibold py-2.5 rounded-xl text-sm transition-colors mt-1"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Creating account...
                </span>
              ) : (
                'Create account'
              )}
            </button>
          </form>
        </div>

        <p className="text-center text-zinc-500 text-sm mt-6">
          Already have an account?{' '}
          <Link to="/login" className="text-red-400 hover:text-red-300 font-medium">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  )
}
