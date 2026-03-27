import { NavLink } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const NAV_ITEMS = [
  { to: '/', label: 'Home', icon: '🏠', end: true },
  { to: '/history', label: 'History', icon: '🕐', auth: true },
  { to: '/liked', label: 'Liked Videos', icon: '👍', auth: true },
  { to: '/playlists', label: 'Playlists', icon: '📋', auth: true },
  { to: '/tweets', label: 'Tweets', icon: '✍️', auth: true },
]

export default function Sidebar() {
  const { user } = useAuth()

  return (
    <aside className="fixed left-0 top-14 bottom-0 w-56 bg-zinc-900 border-r border-zinc-800 overflow-y-auto">
      <ul className="py-3 px-2">
        {NAV_ITEMS.filter((item) => !item.auth || user).map(({ to, label, icon, end }) => (
          <li key={to}>
            <NavLink
              to={to}
              end={end}
              className={({ isActive }) =>
                `flex items-center gap-3.5 px-4 py-2.5 rounded-xl text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-zinc-800 text-white'
                    : 'text-zinc-400 hover:bg-zinc-800/60 hover:text-white'
                }`
              }
            >
              <span className="text-lg leading-none">{icon}</span>
              <span>{label}</span>
            </NavLink>
          </li>
        ))}
      </ul>

      {!user && (
        <div className="px-4 py-4 border-t border-zinc-800 mt-2">
          <p className="text-xs text-zinc-500 leading-relaxed">
            Sign in to like videos, comment, and subscribe.
          </p>
        </div>
      )}
    </aside>
  )
}
