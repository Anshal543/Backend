import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import Navbar from './components/Navbar'
import Sidebar from './components/Sidebar'
import Home from './pages/Home'
import Login from './pages/Login'
import Register from './pages/Register'
import VideoPage from './pages/VideoPage'
import ChannelPage from './pages/ChannelPage'
import HistoryPage from './pages/HistoryPage'
import LikedVideosPage from './pages/LikedVideosPage'
import PlaylistsPage from './pages/PlaylistsPage'
import TweetsPage from './pages/TweetsPage'
import SettingsPage from './pages/SettingsPage'

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-zinc-900">
        <div className="w-8 h-8 border-4 border-zinc-700 border-t-red-500 rounded-full animate-spin" />
      </div>
    )
  }
  return user ? children : <Navigate to="/login" replace />
}

function Layout({ children }) {
  return (
    <div className="flex flex-col h-screen bg-zinc-900 text-white">
      <Navbar />
      <div className="flex flex-1 overflow-hidden pt-14">
        <Sidebar />
        <main className="flex-1 overflow-y-auto ml-56">
          {children}
        </main>
      </div>
    </div>
  )
}

function AppRoutes() {
  const { user, loading } = useAuth()

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-zinc-900">
        <div className="w-8 h-8 border-4 border-zinc-700 border-t-red-500 rounded-full animate-spin" />
      </div>
    )
  }

  return (
    <Routes>
      <Route path="/login" element={user ? <Navigate to="/" replace /> : <Login />} />
      <Route path="/register" element={user ? <Navigate to="/" replace /> : <Register />} />
      <Route path="/" element={<Layout><Home /></Layout>} />
      <Route path="/video/:videoId" element={<Layout><VideoPage /></Layout>} />
      <Route path="/channel/:username" element={<Layout><ChannelPage /></Layout>} />
      <Route
        path="/history"
        element={<ProtectedRoute><Layout><HistoryPage /></Layout></ProtectedRoute>}
      />
      <Route
        path="/liked"
        element={<ProtectedRoute><Layout><LikedVideosPage /></Layout></ProtectedRoute>}
      />
      <Route
        path="/playlists"
        element={<ProtectedRoute><Layout><PlaylistsPage /></Layout></ProtectedRoute>}
      />
      <Route
        path="/tweets"
        element={<ProtectedRoute><Layout><TweetsPage /></Layout></ProtectedRoute>}
      />
      <Route
        path="/settings"
        element={<ProtectedRoute><Layout><SettingsPage /></Layout></ProtectedRoute>}
      />
    </Routes>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  )
}
