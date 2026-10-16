import { Test, TestingModule } from '@nestjs/testing';
import { AuthController, parseCookies } from './auth.controller';
import { AuthService } from './auth.service';
import { BadRequestException } from '@nestjs/common';
import type { Request, Response } from 'express';

describe('AuthController', () => {
  let controller: AuthController;
  let authService: jest.Mocked<AuthService>;

  beforeEach(async () => {
    const mockAuthService = {
      isOidcEnabled: jest.fn().mockReturnValue(true),
      isAuthRequired: jest.fn().mockResolvedValue(true),
      getAuthStatus: jest.fn().mockResolvedValue({
        authRequired: true,
        authenticated: true,
        oidcEnabled: true,
        user: { id: 1, email: 'user@test.com', username: 'user', role: 'user' },
      }),
      validateLocalLogin: jest.fn().mockResolvedValue({
        user: { id: 1, email: 'admin@test.com', username: 'admin', role: 'admin' },
        token: 'mock-jwt-token',
      }),
      createAuthorizationUrl: jest.fn().mockResolvedValue({
        url: 'https://auth.example.com/oauth2/auth?client_id=test',
        state: 'mock-state',
        codeVerifier: 'mock-verifier',
        redirectUri: 'https://maintainerr.local/api/auth/oidc/callback',
      }),
      handleOidcCallback: jest.fn().mockResolvedValue({
        user: { id: 1, email: 'oidc@test.com', username: 'oidcuser', role: 'user' },
        token: 'oidc-session-token',
      }),
      verifySessionToken: jest.fn().mockReturnValue({
        sub: 1,
        email: 'user@test.com',
        username: 'user',
        role: 'user',
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    authService = module.get(AuthService);
  });

  describe('parseCookies', () => {
    it('correctly parses raw cookie headers', () => {
      const parsed = parseCookies('oidc_state=xyz; maintainerr_session=token123');
      expect(parsed['oidc_state']).toBe('xyz');
      expect(parsed['maintainerr_session']).toBe('token123');
    });

    it('returns empty object when cookie header is undefined or empty', () => {
      expect(parseCookies(undefined)).toEqual({});
      expect(parseCookies('')).toEqual({});
    });
  });

  describe('GET /api/auth/status', () => {
    it('verifies session cookie when present', async () => {
      const mockReq = {
        headers: {
          cookie: 'maintainerr_session=valid-jwt-token',
        },
      } as unknown as Request;

      const res = await controller.getStatus(mockReq);
      expect(authService.verifySessionToken).toHaveBeenCalledWith('valid-jwt-token');
      expect(authService.getAuthStatus).toHaveBeenCalledWith(
        expect.objectContaining({ email: 'user@test.com' }),
      );
      expect(res.authenticated).toBe(true);
    });

    it('verifies Authorization Bearer header when cookie is missing', async () => {
      const mockReq = {
        headers: {
          authorization: 'Bearer bearer-token-xyz',
        },
      } as unknown as Request;

      await controller.getStatus(mockReq);
      expect(authService.verifySessionToken).toHaveBeenCalledWith('bearer-token-xyz');
    });

    it('returns unauthenticated when no token is present', async () => {
      const mockReq = {
        headers: {},
      } as unknown as Request;

      await controller.getStatus(mockReq);
      expect(authService.getAuthStatus).toHaveBeenCalledWith(null);
    });
  });

  describe('POST /api/auth/login', () => {
    it('throws BadRequestException if credentials missing', async () => {
      const mockRes = {
        cookie: jest.fn(),
      } as unknown as Response;

      await expect(
        controller.login({ username: '' }, mockRes),
      ).rejects.toThrow(BadRequestException);
    });

    it('authenticates user and sets session cookie', async () => {
      const mockRes = {
        cookie: jest.fn(),
      } as unknown as Response;

      const result = await controller.login(
        { username: 'admin', password: 'password123' },
        mockRes,
      );

      expect(authService.validateLocalLogin).toHaveBeenCalledWith(
        'admin',
        'password123',
      );
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'maintainerr_session',
        'mock-jwt-token',
        expect.objectContaining({ httpOnly: true, path: '/' }),
      );
      expect(result.success).toBe(true);
      expect(result.user.username).toBe('admin');
    });
  });

  describe('POST /api/auth/logout', () => {
    it('clears session cookie', async () => {
      const mockRes = {
        clearCookie: jest.fn(),
      } as unknown as Response;

      const result = await controller.logout(mockRes);
      expect(mockRes.clearCookie).toHaveBeenCalledWith(
        'maintainerr_session',
        expect.objectContaining({ path: '/' }),
      );
      expect(result.success).toBe(true);
    });
  });

  describe('GET /api/auth/oidc', () => {
    it('returns whether OIDC is enabled', () => {
      expect(controller.getOidcConfig()).toEqual({ enabled: true });
    });
  });

  describe('GET /api/auth/oidc/login', () => {
    it('redirects to IdP authorization URL and sets cookies', async () => {
      const mockReq = {
        get: jest.fn((header) => (header === 'host' ? 'maintainerr.local' : 'https')),
        secure: true,
      } as unknown as Request;

      const mockRes = {
        cookie: jest.fn(),
        redirect: jest.fn(),
      } as unknown as Response;

      await controller.oidcLogin(mockReq, mockRes);

      expect(mockRes.cookie).toHaveBeenCalledWith(
        'oidc_state',
        'mock-state',
        expect.any(Object),
      );
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'oidc_verifier',
        'mock-verifier',
        expect.any(Object),
      );
      expect(mockRes.redirect).toHaveBeenCalledWith(
        302,
        'https://auth.example.com/oauth2/auth?client_id=test',
      );
    });

    it('throws BadRequestException if OIDC is disabled', async () => {
      authService.isOidcEnabled.mockReturnValue(false);
      const mockReq = { get: jest.fn() } as unknown as Request;
      const mockRes = {} as unknown as Response;

      await expect(controller.oidcLogin(mockReq, mockRes)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('GET /api/auth/oidc/callback', () => {
    it('redirects with error if provider returned error', async () => {
      const mockReq = {} as Request;
      const mockRes = { redirect: jest.fn() } as unknown as Response;

      await controller.oidcCallback(
        mockReq,
        mockRes,
        undefined,
        undefined,
        'access_denied',
        'User denied access',
      );

      expect(mockRes.redirect).toHaveBeenCalledWith(
        302,
        '/?error=User%20denied%20access',
      );
    });

    it('throws BadRequestException if code or state missing', async () => {
      const mockReq = {} as Request;
      const mockRes = {} as unknown as Response;

      await expect(
        controller.oidcCallback(mockReq, mockRes),
      ).rejects.toThrow(BadRequestException);
    });

    it('handles callback, sets session cookie, clears OIDC cookies and redirects', async () => {
      const mockReq = {
        headers: {
          cookie: 'oidc_verifier=my-verifier; oidc_redirect_uri=https://cb',
        },
        get: jest.fn().mockReturnValue('localhost:6246'),
      } as unknown as Request;

      const mockRes = {
        clearCookie: jest.fn(),
        cookie: jest.fn(),
        redirect: jest.fn(),
      } as unknown as Response;

      await controller.oidcCallback(mockReq, mockRes, 'auth-code', 'auth-state');

      expect(authService.handleOidcCallback).toHaveBeenCalledWith(
        'auth-code',
        'auth-state',
        'my-verifier',
        'https://cb',
        expect.any(String),
      );
      expect(mockRes.clearCookie).toHaveBeenCalledWith('oidc_state', { path: '/' });
      expect(mockRes.clearCookie).toHaveBeenCalledWith('oidc_verifier', { path: '/' });
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'maintainerr_session',
        'oidc-session-token',
        expect.objectContaining({ httpOnly: true, path: '/' }),
      );
      expect(mockRes.redirect).toHaveBeenCalledWith(302, '/');
    });
  });
});
