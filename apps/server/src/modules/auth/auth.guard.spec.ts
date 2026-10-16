import { Test, TestingModule } from '@nestjs/testing';
import { Reflector } from '@nestjs/core';
import { MaintainerrAuthGuard } from './guards/auth.guard';
import { AuthService } from './auth.service';
import { SettingsDataService } from '../settings/settings-data.service';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';

describe('MaintainerrAuthGuard', () => {
  let guard: MaintainerrAuthGuard;
  let reflector: jest.Mocked<Reflector>;
  let authService: jest.Mocked<AuthService>;
  let settingsDataService: Partial<SettingsDataService>;

  const createMockContext = (headers: Record<string, string> = {}, query: Record<string, string> = {}): ExecutionContext => {
    return {
      getHandler: jest.fn(),
      getClass: jest.fn(),
      switchToHttp: jest.fn().mockReturnValue({
        getRequest: jest.fn().mockReturnValue({
          headers,
          query,
        }),
      }),
    } as unknown as ExecutionContext;
  };

  beforeEach(async () => {
    const mockReflector = {
      getAllAndOverride: jest.fn(),
    };

    const mockAuthService = {
      isAuthRequired: jest.fn().mockResolvedValue(true),
      verifySessionToken: jest.fn(),
    };

    settingsDataService = {
      apikey: 'configured-secret-api-key',
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        MaintainerrAuthGuard,
        {
          provide: Reflector,
          useValue: mockReflector,
        },
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
        {
          provide: SettingsDataService,
          useValue: settingsDataService,
        },
      ],
    }).compile();

    guard = module.get<MaintainerrAuthGuard>(MaintainerrAuthGuard);
    reflector = module.get(Reflector);
    authService = module.get(AuthService);
  });

  it('allows access if route is marked @Public()', async () => {
    reflector.getAllAndOverride.mockReturnValue(true);
    const context = createMockContext();

    expect(await guard.canActivate(context)).toBe(true);
  });

  it('allows access if auth is not required', async () => {
    reflector.getAllAndOverride.mockReturnValue(false);
    authService.isAuthRequired.mockResolvedValue(false);
    const context = createMockContext();

    expect(await guard.canActivate(context)).toBe(true);
  });

  it('allows access with matching X-Api-Key header', async () => {
    reflector.getAllAndOverride.mockReturnValue(false);
    authService.isAuthRequired.mockResolvedValue(true);
    const context = createMockContext({ 'x-api-key': 'configured-secret-api-key' });

    expect(await guard.canActivate(context)).toBe(true);
  });

  it('allows access with matching apiKey query parameter', async () => {
    reflector.getAllAndOverride.mockReturnValue(false);
    authService.isAuthRequired.mockResolvedValue(true);
    const context = createMockContext({}, { apiKey: 'configured-secret-api-key' });

    expect(await guard.canActivate(context)).toBe(true);
  });

  it('allows access with valid maintainerr_session cookie', async () => {
    reflector.getAllAndOverride.mockReturnValue(false);
    authService.isAuthRequired.mockResolvedValue(true);
    authService.verifySessionToken.mockReturnValue({
      sub: 1,
      email: 'user@test.com',
      username: 'user',
      role: 'user',
    });

    const context = createMockContext({
      cookie: 'maintainerr_session=valid-session-jwt',
    });

    expect(await guard.canActivate(context)).toBe(true);
  });

  it('allows access with valid Authorization Bearer header', async () => {
    reflector.getAllAndOverride.mockReturnValue(false);
    authService.isAuthRequired.mockResolvedValue(true);
    authService.verifySessionToken.mockReturnValue({
      sub: 1,
      email: 'user@test.com',
      username: 'user',
      role: 'user',
    });

    const context = createMockContext({
      authorization: 'Bearer valid-session-jwt',
    });

    expect(await guard.canActivate(context)).toBe(true);
  });

  it('throws UnauthorizedException when no token or api key provided', async () => {
    reflector.getAllAndOverride.mockReturnValue(false);
    authService.isAuthRequired.mockResolvedValue(true);
    const context = createMockContext();

    await expect(guard.canActivate(context)).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('throws UnauthorizedException when token verification fails', async () => {
    reflector.getAllAndOverride.mockReturnValue(false);
    authService.isAuthRequired.mockResolvedValue(true);
    authService.verifySessionToken.mockImplementation(() => {
      throw new Error('Token expired');
    });

    const context = createMockContext({
      cookie: 'maintainerr_session=expired-jwt',
    });

    await expect(guard.canActivate(context)).rejects.toThrow(
      UnauthorizedException,
    );
  });
});
