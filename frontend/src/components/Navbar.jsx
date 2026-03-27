import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function Navbar() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [menuOpen, setMenuOpen] = useState(false)

  const handleSearch = (e) => {
    e.preventDefault()
    // Search is handled client-side on the home page for now
  }

  const handleLogout = async () => {
    await logout()
    setMenuOpen(false)
    navigate('/')
  }

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 flex items-center justify-between px-4 h-14 bg-zinc-900 border-b border-zinc-800">
      {/* Logo */}
      <Link to="/" className="flex items-center gap-1 font-bold text-xl flex-shrink-0">
        <span className="text-red-500">New</span>
        <span className="text-white">Tube</span>
      </Link>

      {/* Search bar */}
      <form
        onSubmit={handleSearch}
        className="flex items-center flex-1 max-w-md mx-6"
      >
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search"
          className="flex-1 bg-zinc-800 border border-zinc-700 rounded-l-full px-4 py-1.5 text-sm text-white placeholder-zinc-500 focus:outline-none focus:border-zinc-500"
        />
        <button
          type="submit"
          className="bg-zinc-700 hover:bg-zinc-600 border border-l-0 border-zinc-700 px-4 py-1.5 rounded-r-full text-sm text-zinc-300"
        >
          &#x1F50D;
        </button>
      </form>

      {/* Auth area */}
      <div className="flex items-center gap-3 flex-shrink-0">
        {user ? (
          <div className="relative">
            <button
              onClick={() => setMenuOpen(!menuOpen)}
              className="flex items-center gap-2 focus:outline-none"
            >
              <img
                src={user.avatar}
                alt={user.username}
                className="w-8 h-8 rounded-full object-cover border border-zinc-600"
              />
            </button>

            {menuOpen && (
              <div className="absolute right-0 mt-2 w-48 bg-zinc-800 border border-zinc-700 rounded-xl shadow-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-zinc-700">
                  <p className="text-sm font-medium text-white truncate">{user.fullName}</p>
                  <p className="text-xs text-zinc-400 truncate">@{user.username}</p>
                </div>
                <Link
                  to={`/channel/${user.username}`}
                  onClick={() => setMenuOpen(false)}
                  className="flex items-center px-4 py-2.5 text-sm text-zinc-300 hover:bg-zinc-700 hover:text-white"
                >
                  Your Channel
                </Link>
                <Link
                  to="/settings"
                  onClick={() => setMenuOpen(false)}
                  className="flex items-center px-4 py-2.5 text-sm text-zinc-300 hover:bg-zinc-700 hover:text-white"
                >
                  Settings
                </Link>
                <button
                  onClick={handleLogout}
                  className="flex items-center w-full px-4 py-2.5 text-sm text-zinc-300 hover:bg-zinc-700 hover:text-white border-t border-zinc-700"
                >
                  Sign out
                </button>
              </div>
            )}
          </div>
        ) : (
          <div className="flex items-center gap-2">
            <Link
              to="/login"
              className="text-sm text-zinc-300 hover:text-white px-4 py-1.5 rounded-full border border-zinc-600 hover:border-zinc-400"
            >
              Sign in
            </Link>
            <Link
              to="/register"
              className="text-sm font-medium text-white bg-red-600 hover:bg-red-700 px-4 py-1.5 rounded-full"
            >
              Sign up
            </Link>
          </div>
        )}
      </div>
    </nav>
  )
}
