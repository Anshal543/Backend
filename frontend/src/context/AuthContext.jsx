import { createContext, useContext, useState, useEffect } from 'react'
import api from '../api/axios'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api
      .get('/users/current-user')
      .then((res) => setUser(res.data.data))
      .catch(() => setUser(null))
      .finally(() => setLoading(false))
  }, [])

  const login = async (credentials) => {
    const res = await api.post('/users/login', credentials)
    setUser(res.data.data.user)
    return res.data
  }

  const register = async (formData) => {
    const res = await api.post('/users/register', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return res.data
  }

  const logout = async () => {
    await api.post('/users/logout')
    setUser(null)
  }

  return (
    <AuthContext.Provider value={{ user, setUser, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}
