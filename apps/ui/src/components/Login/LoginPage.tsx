import React, { useState, useEffect } from 'react'
import { API_BASE_PATH, GetApiHandler, PostApiHandler } from '../../utils/ApiHandler'
import Button from '../Common/Button'
import { AuthStatusDto } from '@maintainerr/contracts'

interface LoginPageProps {
  onLoginSuccess?: () => void
  initialStatus?: AuthStatusDto
}

export const LoginPage: React.FC<LoginPageProps> = ({
  onLoginSuccess,
  initialStatus,
}) => {
  const [oidcEnabled, setOidcEnabled] = useState<boolean>(
    initialStatus?.oidcEnabled ?? true,
  )
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const basePath = import.meta.env.VITE_BASE_PATH ?? ''

  useEffect(() => {
    // Check for query param errors (e.g., from OIDC callback)
    const params = new URLSearchParams(window.location.search)
    const queryError = params.get('error')
    if (queryError) {
      setError(decodeURIComponent(queryError))
    }

    if (!initialStatus) {
      GetApiHandler<AuthStatusDto>('/auth/status')
        .then((res) => {
          if (res) {
            setOidcEnabled(res.oidcEnabled)
            if (res.authenticated && onLoginSuccess) {
              onLoginSuccess()
            }
          }
        })
        .catch(() => {
          // Keep default state
        })
    }
  }, [initialStatus, onLoginSuccess])

  const handleOidcLogin = () => {
    const oidcLoginUrl = `${API_BASE_PATH}/api/auth/oidc/login`
    window.location.href = oidcLoginUrl
  }

  const handleLocalLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!username || !password) {
      setError('Please enter both username and password')
      return
    }

    setLoading(true)
    setError(null)

    try {
      const res = await PostApiHandler('/auth/login', { username, password })
      if (res?.success) {
        if (onLoginSuccess) {
          onLoginSuccess()
        } else {
          window.location.reload()
        }
      } else {
        setError('Login failed: invalid response from server')
      }
    } catch (err: any) {
      const msg =
        err.response?.data?.message ||
        err.response?.data?.error ||
        err.message ||
        'Invalid username or password'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-900 px-4 py-12 sm:px-6 lg:px-8">
      <div className="w-full max-w-md space-y-8 rounded-xl border border-zinc-700/80 bg-zinc-800/90 p-8 shadow-2xl backdrop-blur-sm">
        <div className="text-center">
          <div className="flex justify-center">
            <img
              src={`${basePath}/apple-touch-icon.png`}
              alt="Maintainerr Logo"
              className="h-16 w-16 rounded-xl shadow-md"
              onError={(e) => {
                // If logo fails to load, gracefully hide img
                ;(e.target as HTMLElement).style.display = 'none'
              }}
            />
          </div>
          <h2 className="mt-4 text-3xl font-extrabold tracking-tight text-white">
            Maintainerr
          </h2>
          <p className="mt-2 text-sm text-zinc-400">
            Sign in to access your dashboard
          </p>
        </div>

        {error && (
          <div
            data-testid="login-error"
            className="rounded-md border border-red-500/50 bg-red-900/30 p-4 text-sm text-red-200"
          >
            <div className="flex items-center space-x-2">
              <svg
                className="h-5 w-5 shrink-0 text-red-400"
                viewBox="0 0 20 20"
                fill="currentColor"
              >
                <path
                  fillRule="evenodd"
                  d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                  clipRule="evenodd"
                />
              </svg>
              <span>{error}</span>
            </div>
          </div>
        )}

        <div className="space-y-4">
          {oidcEnabled && (
            <div>
              <button
                type="button"
                data-testid="oidc-login-button"
                onClick={handleOidcLogin}
                className="flex w-full cursor-pointer items-center justify-center rounded-lg border border-maintainerr-500 bg-maintainerr-600 px-4 py-3 text-base font-semibold text-white shadow-md transition duration-150 hover:bg-maintainerr hover:border-maintainerr focus:outline-none focus:ring-2 focus:ring-maintainerr-500 focus:ring-offset-2 focus:ring-offset-zinc-800"
              >
                <svg
                  className="mr-3 h-5 w-5"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"
                  />
                </svg>
                Login with OIDC
              </button>
            </div>
          )}

          {oidcEnabled && (
            <div className="relative flex items-center justify-center py-2">
              <div className="w-full border-t border-zinc-700" />
              <span className="absolute bg-zinc-800 px-3 text-xs uppercase tracking-wider text-zinc-400">
                Or with credentials
              </span>
            </div>
          )}

          <form onSubmit={handleLocalLogin} className="space-y-4">
            <div>
              <label
                htmlFor="username"
                className="block text-sm font-medium text-zinc-300"
              >
                Username or Email
              </label>
              <input
                id="username"
                type="text"
                data-testid="username-input"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="mt-1 block w-full rounded-md border border-zinc-600 bg-zinc-700/60 px-3 py-2 text-white placeholder-zinc-400 shadow-sm focus:border-maintainerr-500 focus:outline-none focus:ring-1 focus:ring-maintainerr-500"
                placeholder="admin"
              />
            </div>

            <div>
              <label
                htmlFor="password"
                className="block text-sm font-medium text-zinc-300"
              >
                Password
              </label>
              <input
                id="password"
                type="password"
                data-testid="password-input"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="mt-1 block w-full rounded-md border border-zinc-600 bg-zinc-700/60 px-3 py-2 text-white placeholder-zinc-400 shadow-sm focus:border-maintainerr-500 focus:outline-none focus:ring-1 focus:ring-maintainerr-500"
                placeholder="••••••••"
              />
            </div>

            <Button
              type="submit"
              buttonType="primary"
              data-testid="login-submit-button"
              className="w-full justify-center py-2.5"
              disabled={loading}
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </Button>
          </form>
        </div>
      </div>
    </div>
  )
}

export default LoginPage
