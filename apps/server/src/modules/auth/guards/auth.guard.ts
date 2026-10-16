import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Optional,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { AuthService } from '../auth.service';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { SettingsDataService } from '../../settings/settings-data.service';
import { parseCookies } from '../auth.controller';

@Injectable()
export class MaintainerrAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly authService: AuthService,
    @Optional()
    private readonly settingsDataService?: SettingsDataService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    const authRequired = await this.authService.isAuthRequired();
    if (!authRequired) {
      return true;
    }

    const req = context.switchToHttp().getRequest<Request>();

    // Support API Key for automated scripts/integrations
    const apiKeyHeader =
      (req.headers['x-api-key'] as string) ||
      (req.headers['x-maintainerr-api-key'] as string) ||
      (req.query?.apiKey as string);

    if (
      apiKeyHeader &&
      this.settingsDataService?.apikey &&
      apiKeyHeader === this.settingsDataService.apikey
    ) {
      return true;
    }

    const cookies = parseCookies(req.headers?.cookie);
    const token =
      cookies['maintainerr_session'] ||
      req.headers?.authorization?.replace(/^Bearer\s+/i, '');

    if (!token) {
      throw new UnauthorizedException('Authentication required');
    }

    try {
      const user = this.authService.verifySessionToken(token);
      (req as any).user = user;
      return true;
    } catch (err: any) {
      throw new UnauthorizedException(err.message || 'Invalid or expired session');
    }
  }
}
