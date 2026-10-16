export interface AuthUserDto {
  id: number
  email: string
  username: string
  role: 'admin' | 'user'
}

export interface AuthStatusDto {
  authRequired: boolean
  authenticated: boolean
  oidcEnabled: boolean
  user: AuthUserDto | null
}

export interface LocalLoginDto {
  username: string
  password: string
}

export interface OidcConfigDto {
  enabled: boolean
  issuerUrl?: string
}
