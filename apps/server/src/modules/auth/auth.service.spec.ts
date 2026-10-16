import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import axios from 'axios';
import { AuthService, OidcDiscoveryDoc } from './auth.service';
import { User } from './entities/user.entity';
import {
  BadRequestException,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('AuthService', () => {
  let service: AuthService;
  let userRepository: jest.Mocked<Repository<User>>;

  const mockUser: User = {
    id: 1,
    email: 'user@example.com',
    username: 'testuser',
    role: 'user',
    oidcSub: 'sub-123',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    delete process.env.OIDC_ISSUER_URL;
    delete process.env.OIDC_CLIENT_ID;
    delete process.env.OIDC_CLIENT_SECRET;
    delete process.env.OIDC_REDIRECT_URI;
    delete process.env.OIDC_ADMIN_GROUP;
    delete process.env.OIDC_USER_GROUP;
    delete process.env.LOCAL_ADMIN_USERNAME;
    delete process.env.LOCAL_ADMIN_PASSWORD;

    const mockRepo = {
      query: jest.fn().mockResolvedValue([]),
      count: jest.fn().mockResolvedValue(0),
      findOne: jest.fn(),
      create: jest.fn((dto) => ({ ...dto, id: 1 })),
      save: jest.fn((entity) => Promise.resolve({ ...entity, id: entity.id || 1 })),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getRepositoryToken(User),
          useValue: mockRepo,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    userRepository = module.get(getRepositoryToken(User));
  });

  describe('isOidcEnabled', () => {
    it('returns false when variables are not set', () => {
      expect(service.isOidcEnabled()).toBe(false);
    });

    it('returns true when all required OIDC variables are set', () => {
      process.env.OIDC_ISSUER_URL = 'https://auth.example.com';
      process.env.OIDC_CLIENT_ID = 'client-id';
      process.env.OIDC_CLIENT_SECRET = 'client-secret';
      expect(service.isOidcEnabled()).toBe(true);
    });
  });

  describe('isAuthRequired', () => {
    it('returns false if OIDC is not enabled, no local admin, and no users in DB', async () => {
      userRepository.count.mockResolvedValue(0);
      expect(await service.isAuthRequired()).toBe(false);
    });

    it('returns true if OIDC is enabled', async () => {
      process.env.OIDC_ISSUER_URL = 'https://auth.example.com';
      process.env.OIDC_CLIENT_ID = 'client-id';
      process.env.OIDC_CLIENT_SECRET = 'client-secret';
      expect(await service.isAuthRequired()).toBe(true);
    });

    it('returns true if LOCAL_ADMIN_PASSWORD is set', async () => {
      process.env.LOCAL_ADMIN_PASSWORD = 'supersecretpass';
      expect(await service.isAuthRequired()).toBe(true);
    });

    it('returns true if users exist in DB', async () => {
      userRepository.count.mockResolvedValue(1);
      expect(await service.isAuthRequired()).toBe(true);
    });
  });

  describe('getAuthStatus', () => {
    it('returns unauthenticated status when no user is provided', async () => {
      const status = await service.getAuthStatus(null);
      expect(status.authenticated).toBe(false);
      expect(status.user).toBeNull();
    });

    it('returns authenticated user dto when user payload is provided', async () => {
      const status = await service.getAuthStatus({
        sub: 1,
        email: 'admin@example.com',
        username: 'admin',
        role: 'admin',
      });
      expect(status.authenticated).toBe(true);
      expect(status.user).toEqual({
        id: 1,
        email: 'admin@example.com',
        username: 'admin',
        role: 'admin',
      });
    });
  });

  describe('OIDC Discovery', () => {
    it('throws BadRequestException if OIDC_ISSUER_URL is missing', async () => {
      await expect(service.getDiscoveryDoc()).rejects.toThrow(BadRequestException);
    });

    it('fetches and caches discovery document', async () => {
      process.env.OIDC_ISSUER_URL = 'https://auth.example.com/';
      const mockDoc: OidcDiscoveryDoc = {
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/oauth2/auth',
        token_endpoint: 'https://auth.example.com/oauth2/token',
        userinfo_endpoint: 'https://auth.example.com/oauth2/userinfo',
      };
      mockedAxios.get.mockResolvedValueOnce({ data: mockDoc });

      const doc1 = await service.getDiscoveryDoc();
      expect(doc1).toEqual(mockDoc);
      expect(mockedAxios.get).toHaveBeenCalledWith(
        'https://auth.example.com/.well-known/openid-configuration',
        expect.any(Object),
      );

      // Subsequent call should use cache
      const doc2 = await service.getDiscoveryDoc();
      expect(doc2).toEqual(mockDoc);
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);
    });

    it('throws BadRequestException if discovery fetch fails', async () => {
      process.env.OIDC_ISSUER_URL = 'https://bad-issuer.example.com';
      mockedAxios.get.mockRejectedValueOnce(new Error('Network error'));
      await expect(service.getDiscoveryDoc()).rejects.toThrow(BadRequestException);
    });
  });

  describe('createAuthorizationUrl', () => {
    it('generates an authorization URL with PKCE parameters and state', async () => {
      process.env.OIDC_ISSUER_URL = 'https://auth.example.com';
      process.env.OIDC_CLIENT_ID = 'test-client';
      const mockDoc: OidcDiscoveryDoc = {
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/oauth2/auth',
        token_endpoint: 'https://auth.example.com/oauth2/token',
      };
      mockedAxios.get.mockResolvedValueOnce({ data: mockDoc });

      const result = await service.createAuthorizationUrl('http://callback.local');
      expect(result.url).toContain('https://auth.example.com/oauth2/auth');
      expect(result.url).toContain('response_type=code');
      expect(result.url).toContain('client_id=test-client');
      expect(result.url).toContain('code_challenge_method=S256');
      expect(result.state).toBeDefined();
      expect(result.codeVerifier).toBeDefined();
    });
  });

  describe('handleOidcCallback', () => {
    beforeEach(() => {
      process.env.OIDC_ISSUER_URL = 'https://auth.example.com';
      process.env.OIDC_CLIENT_ID = 'test-client';
      process.env.OIDC_CLIENT_SECRET = 'test-secret';
      process.env.OIDC_REDIRECT_URI = 'https://maintainerr.local/api/auth/oidc/callback';
    });

    it('throws BadRequestException if verifier is missing', async () => {
      await expect(
        service.handleOidcCallback('code', 'unknown-state'),
      ).rejects.toThrow(BadRequestException);
    });

    it('successfully exchanges code and merges userinfo claims into new user', async () => {
      const mockDoc: OidcDiscoveryDoc = {
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/oauth2/auth',
        token_endpoint: 'https://auth.example.com/oauth2/token',
        userinfo_endpoint: 'https://auth.example.com/oauth2/userinfo',
      };
      mockedAxios.get.mockResolvedValueOnce({ data: mockDoc });

      const authInfo = await service.createAuthorizationUrl();

      // Mock token endpoint
      const idPayload = Buffer.from(
        JSON.stringify({ sub: 'oidc-123', email: 'john@example.com' }),
      ).toString('base64url');
      mockedAxios.post.mockResolvedValueOnce({
        data: {
          access_token: 'access-token-xyz',
          id_token: `header.${idPayload}.signature`,
          token_type: 'Bearer',
        },
      });

      // Mock userinfo endpoint
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          name: 'John Doe',
          preferred_username: 'johndoe',
          groups: ['users'],
        },
      });

      userRepository.findOne.mockResolvedValueOnce(null);

      const { user, token } = await service.handleOidcCallback(
        'code-123',
        authInfo.state,
      );

      expect(mockedAxios.post).toHaveBeenCalledWith(
        'https://auth.example.com/oauth2/token',
        expect.stringContaining('grant_type=authorization_code'),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          timeout: 15000,
        },
      );
      expect(user.email).toBe('john@example.com');
      expect(user.username).toBe('johndoe');
      expect(user.role).toBe('user');
      expect(token).toBeDefined();

      const verified = service.verifySessionToken(token);
      expect(verified.email).toBe('john@example.com');
    });

    it('assigns admin role when user is in OIDC_ADMIN_GROUP', async () => {
      process.env.OIDC_ADMIN_GROUP = 'maintainerr-admins';

      const mockDoc: OidcDiscoveryDoc = {
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/oauth2/auth',
        token_endpoint: 'https://auth.example.com/oauth2/token',
        userinfo_endpoint: 'https://auth.example.com/oauth2/userinfo',
      };
      mockedAxios.get.mockResolvedValueOnce({ data: mockDoc });

      const authInfo = await service.createAuthorizationUrl();

      const idPayload = Buffer.from(
        JSON.stringify({ sub: 'admin-1', email: 'admin@example.com' }),
      ).toString('base64url');
      mockedAxios.post.mockResolvedValueOnce({
        data: {
          access_token: 'token',
          id_token: `h.${idPayload}.s`,
          token_type: 'Bearer',
        },
      });

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          groups: ['maintainerr-admins'],
        },
      });

      userRepository.findOne.mockResolvedValueOnce(null);

      const { user } = await service.handleOidcCallback(
        'code-123',
        authInfo.state,
      );
      expect(user.role).toBe('admin');
    });

    it('rejects user with 403 Forbidden if not in required group', async () => {
      process.env.OIDC_ADMIN_GROUP = 'admins';
      process.env.OIDC_USER_GROUP = 'members';

      const mockDoc: OidcDiscoveryDoc = {
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/oauth2/auth',
        token_endpoint: 'https://auth.example.com/oauth2/token',
        userinfo_endpoint: 'https://auth.example.com/oauth2/userinfo',
      };
      mockedAxios.get.mockResolvedValueOnce({ data: mockDoc });

      const authInfo = await service.createAuthorizationUrl();

      const idPayload = Buffer.from(
        JSON.stringify({ sub: 'user-2', email: 'random@example.com' }),
      ).toString('base64url');
      mockedAxios.post.mockResolvedValueOnce({
        data: {
          access_token: 'token',
          id_token: `h.${idPayload}.s`,
          token_type: 'Bearer',
        },
      });

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          groups: ['other-group'],
        },
      });

      await expect(
        service.handleOidcCallback('code-123', authInfo.state),
      ).rejects.toThrow(ForbiddenException);
    });

    it('updates existing user attributes on repeated login', async () => {
      const mockDoc: OidcDiscoveryDoc = {
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/oauth2/auth',
        token_endpoint: 'https://auth.example.com/oauth2/token',
      };
      mockedAxios.get.mockResolvedValueOnce({ data: mockDoc });

      const authInfo = await service.createAuthorizationUrl();

      const idPayload = Buffer.from(
        JSON.stringify({ sub: 'sub-new', email: 'user@example.com', preferred_username: 'newname' }),
      ).toString('base64url');
      mockedAxios.post.mockResolvedValueOnce({
        data: {
          access_token: 'token',
          id_token: `h.${idPayload}.s`,
          token_type: 'Bearer',
        },
      });

      const existingUser: User = {
        id: 1,
        email: 'user@example.com',
        username: 'oldname',
        role: 'user',
        oidcSub: 'sub-old',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      userRepository.findOne.mockResolvedValueOnce(existingUser);

      const { user } = await service.handleOidcCallback(
        'code-123',
        authInfo.state,
      );

      expect(user.username).toBe('newname');
      expect(user.oidcSub).toBe('sub-new');
      expect(userRepository.save).toHaveBeenCalled();
    });
  });

  describe('validateLocalLogin', () => {
    it('authenticates with LOCAL_ADMIN_PASSWORD environment variables', async () => {
      process.env.LOCAL_ADMIN_USERNAME = 'superadmin';
      process.env.LOCAL_ADMIN_PASSWORD = 'superpassword123';

      userRepository.findOne.mockResolvedValueOnce(null);

      const { user, token } = await service.validateLocalLogin(
        'superadmin',
        'superpassword123',
      );

      expect(user.username).toBe('superadmin');
      expect(user.role).toBe('admin');
      expect(token).toBeDefined();
    });

    it('authenticates with database user credentials', async () => {
      const password = 'mySecretPassword!';
      const passwordHash = service.hashPassword(password);
      const dbUser: User = {
        id: 5,
        email: 'local@user.com',
        username: 'localuser',
        passwordHash,
        role: 'user',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      userRepository.findOne.mockResolvedValueOnce(dbUser);

      const { user, token } = await service.validateLocalLogin(
        'localuser',
        password,
      );

      expect(user.id).toBe(5);
      expect(token).toBeDefined();
    });

    it('throws UnauthorizedException on invalid password', async () => {
      const passwordHash = service.hashPassword('correctPassword');
      const dbUser: User = {
        id: 5,
        email: 'local@user.com',
        username: 'localuser',
        passwordHash,
        role: 'user',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      userRepository.findOne.mockResolvedValueOnce(dbUser);

      await expect(
        service.validateLocalLogin('localuser', 'wrongPassword'),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('JWT Session Tokens', () => {
    it('generates and verifies valid session tokens', () => {
      const token = service.generateSessionToken({
        sub: 10,
        email: 'jwt@example.com',
        username: 'jwtuser',
        role: 'user',
      });

      const payload = service.verifySessionToken(token);
      expect(payload.sub).toBe(10);
      expect(payload.email).toBe('jwt@example.com');
      expect(payload.username).toBe('jwtuser');
      expect(payload.role).toBe('user');
    });

    it('throws on tampered token signature', () => {
      const token = service.generateSessionToken({
        sub: 10,
        email: 'jwt@example.com',
        username: 'jwtuser',
        role: 'user',
      });

      const parts = token.split('.');
      const tampered = `${parts[0]}.${parts[1]}.badsignature123`;
      expect(() => service.verifySessionToken(tampered)).toThrow(UnauthorizedException);
    });

    it('throws on expired token', () => {
      const now = Math.floor(Date.now() / 1000);
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const body = Buffer.from(
        JSON.stringify({ sub: 1, email: 'exp@test.com', username: 'exp', role: 'user', exp: now - 100 }),
      ).toString('base64url');
      const unsigned = `${header}.${body}`;
      const sig = (service as any).authSecret;
      const crypto = require('crypto');
      const signature = crypto.createHmac('sha256', sig).update(unsigned).digest('base64url');
      const expiredToken = `${unsigned}.${signature}`;

      expect(() => service.verifySessionToken(expiredToken)).toThrow(UnauthorizedException);
    });
  });

  describe('Password Hashing', () => {
    it('hashes and verifies passwords correctly', () => {
      const hash = service.hashPassword('Secret123');
      expect(service.verifyPassword('Secret123', hash)).toBe(true);
      expect(service.verifyPassword('Wrong123', hash)).toBe(false);
      expect(service.verifyPassword('Secret123', 'invalid:hash')).toBe(false);
    });
  });
});
