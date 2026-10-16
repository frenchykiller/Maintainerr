import {
  Controller,
  Get,
  Post,
  Body,
  Req,
  Res,
  Query,
  BadRequestException,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { Public } from './decorators/public.decorator';

export function parseCookies(cookieHeader?: string): Record<string, string> {
  const list: Record<string, string> = {};
  if (!cookieHeader) return list;

  cookieHeader.split(';').forEach((cookie) => {
    const parts = cookie.split('=');
    const name = parts[0]?.trim();
    if (name) {
      list[name] = decodeURIComponent(parts.slice(1).join('='));
    }
  });

  return list;
}

@Controller('api/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Get('status')
  async getStatus(@Req() req: Request) {
    const cookies = parseCookies(req.headers.cookie);
    const token =
      cookies['maintainerr_session'] ||
      req.headers.authorization?.replace(/^Bearer\s+/i, '');

    let user = null;
    if (token) {
      try {
        user = this.authService.verifySessionToken(token);
      } catch {
        user = null;
      }
    }

    return await this.authService.getAuthStatus(user);
  }

  @Public()
  @Post('login')
  async login(
    @Body() body: { username?: string; password?: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    if (!body?.username || !body?.password) {
      throw new BadRequestException('Username and password are required');
    }

    const { user, token } = await this.authService.validateLocalLogin(
      body.username,
      body.password,
    );

    res.cookie('maintainerr_session', token, {
      httpOnly: true,
      path: '/',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return {
      success: true,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
      },
    };
  }

  @Public()
  @Post('logout')
  async logout(@Res({ passthrough: true }) res: Response) {
    res.clearCookie('maintainerr_session', { path: '/' });
    return { success: true };
  }

  @Public()
  @Get('oidc')
  getOidcConfig() {
    return {
      enabled: this.authService.isOidcEnabled(),
    };
  }

  @Public()
  @Get('oidc/login')
  async oidcLogin(@Req() req: Request, @Res() res: Response) {
    if (!this.authService.isOidcEnabled()) {
      throw new BadRequestException('OIDC is not configured on this server');
    }

    const host = req.get('host') || 'localhost:6246';
    const proto =
      req.get('x-forwarded-proto') || (req.secure ? 'https' : 'http');
    const defaultCallback = `${proto}://${host}/api/auth/oidc/callback`;

    const { url, state, codeVerifier, redirectUri } =
      await this.authService.createAuthorizationUrl(defaultCallback);

    res.cookie('oidc_state', state, {
      httpOnly: true,
      maxAge: 5 * 60 * 1000,
      path: '/',
      sameSite: 'lax',
    });
    res.cookie('oidc_verifier', codeVerifier, {
      httpOnly: true,
      maxAge: 5 * 60 * 1000,
      path: '/',
      sameSite: 'lax',
    });
    res.cookie('oidc_redirect_uri', redirectUri, {
      httpOnly: true,
      maxAge: 5 * 60 * 1000,
      path: '/',
      sameSite: 'lax',
    });

    res.redirect(302, url);
  }

  @Public()
  @Get(['oidc/callback', 'callback/oidc'])
  async oidcCallback(
    @Req() req: Request,
    @Res() res: Response,
    @Query('code') code?: string,
    @Query('state') state?: string,
    @Query('error') error?: string,
    @Query('error_description') errorDescription?: string,
  ) {
    const basePath = process.env.BASE_PATH || '/';

    if (error) {
      const msg = errorDescription || error;
      return res.redirect(
        302,
        `${basePath.replace(/\/+$/, '')}/?error=${encodeURIComponent(msg)}`,
      );
    }

    if (!code || !state) {
      throw new BadRequestException('Missing authorization code or state');
    }

    const cookies = parseCookies(req.headers.cookie);
    const cookieVerifier = cookies['oidc_verifier'];
    const cookieRedirectUri = cookies['oidc_redirect_uri'];

    const host = req.get('host') || 'localhost:6246';
    const proto =
      req.get('x-forwarded-proto') || (req.secure ? 'https' : 'http');
    const fallbackRedirectUri = `${proto}://${host}/api/auth/oidc/callback`;

    const { token } = await this.authService.handleOidcCallback(
      code,
      state,
      cookieVerifier,
      cookieRedirectUri,
      fallbackRedirectUri,
    );

    res.clearCookie('oidc_state', { path: '/' });
    res.clearCookie('oidc_verifier', { path: '/' });
    res.clearCookie('oidc_redirect_uri', { path: '/' });

    res.cookie('maintainerr_session', token, {
      httpOnly: true,
      path: '/',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.redirect(302, basePath);
  }
}
