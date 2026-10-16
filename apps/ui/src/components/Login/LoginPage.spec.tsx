import { describe, expect, it, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '../../test-utils/render'
import LoginPage from './LoginPage'
import * as ApiHandler from '../../utils/ApiHandler'

describe('LoginPage', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('renders login screen with OIDC button and credentials form', () => {
    render(
      <LoginPage
        initialStatus={{
          authRequired: true,
          authenticated: false,
          oidcEnabled: true,
          user: null,
        }}
      />,
    )

    expect(screen.getByText('Maintainerr')).toBeTruthy()
    expect(screen.getByTestId('oidc-login-button')).toBeTruthy()
    expect(screen.getByTestId('username-input')).toBeTruthy()
    expect(screen.getByTestId('password-input')).toBeTruthy()
    expect(screen.getByTestId('login-submit-button')).toBeTruthy()
  })

  it('hides OIDC button when oidcEnabled is false', () => {
    render(
      <LoginPage
        initialStatus={{
          authRequired: true,
          authenticated: false,
          oidcEnabled: false,
          user: null,
        }}
      />,
    )

    expect(screen.queryByTestId('oidc-login-button')).toBeNull()
    expect(screen.getByTestId('username-input')).toBeTruthy()
    expect(screen.getByTestId('login-submit-button')).toBeTruthy()
  })

  it('navigates to OIDC login url on OIDC button click', () => {
    delete (window as any).location
    window.location = { href: '', search: '' } as any

    render(
      <LoginPage
        initialStatus={{
          authRequired: true,
          authenticated: false,
          oidcEnabled: true,
          user: null,
        }}
      />,
    )

    const oidcButton = screen.getByTestId('oidc-login-button')
    fireEvent.click(oidcButton)

    expect(window.location.href).toContain('/api/auth/oidc/login')
  })

  it('shows error if submitted with empty credentials', async () => {
    render(
      <LoginPage
        initialStatus={{
          authRequired: true,
          authenticated: false,
          oidcEnabled: false,
          user: null,
        }}
      />,
    )

    const submitButton = screen.getByTestId('login-submit-button')
    const form = submitButton.closest('form')!
    fireEvent.submit(form)

    await waitFor(() => {
      expect(screen.getByTestId('login-error')).toBeTruthy()
    })
  })

  it('calls login API and triggers onLoginSuccess on valid submission', async () => {
    const postSpy = vi.spyOn(ApiHandler, 'PostApiHandler').mockResolvedValue({
      success: true,
      user: { id: 1, email: 'admin@test.local', username: 'admin', role: 'admin' },
    })
    const onLoginSuccess = vi.fn()

    render(
      <LoginPage
        onLoginSuccess={onLoginSuccess}
        initialStatus={{
          authRequired: true,
          authenticated: false,
          oidcEnabled: true,
          user: null,
        }}
      />,
    )

    const usernameInput = screen.getByTestId('username-input')
    const passwordInput = screen.getByTestId('password-input')
    const submitButton = screen.getByTestId('login-submit-button')

    fireEvent.change(usernameInput, { target: { value: 'admin' } })
    fireEvent.change(passwordInput, { target: { value: 'secretpass' } })
    fireEvent.click(submitButton)

    await waitFor(() => {
      expect(postSpy).toHaveBeenCalledWith('/auth/login', {
        username: 'admin',
        password: 'secretpass',
      })
      expect(onLoginSuccess).toHaveBeenCalledTimes(1)
    })
  })

  it('displays error message when login fails', async () => {
    vi.spyOn(ApiHandler, 'PostApiHandler').mockRejectedValue({
      response: { data: { message: 'Invalid credentials provided' } },
    })

    render(
      <LoginPage
        initialStatus={{
          authRequired: true,
          authenticated: false,
          oidcEnabled: false,
          user: null,
        }}
      />,
    )

    fireEvent.change(screen.getByTestId('username-input'), {
      target: { value: 'admin' },
    })
    fireEvent.change(screen.getByTestId('password-input'), {
      target: { value: 'wrongpass' },
    })
    fireEvent.click(screen.getByTestId('login-submit-button'))

    await waitFor(() => {
      expect(screen.getByTestId('login-error')).toBeTruthy()
      expect(screen.getByText('Invalid credentials provided')).toBeTruthy()
    })
  })
})
