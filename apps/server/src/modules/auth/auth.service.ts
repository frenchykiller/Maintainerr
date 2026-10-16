import {
  Injectable,
  Logger,
  OnModuleInit,
  UnauthorizedException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import axios from 'axios';
import * as crypto from 'crypto';
import { User } from './entities/user.entity';
import { AuthStatusDto, AuthUserDto } from '@maintainerr/contracts';

export interface OidcTokens {
  access_token: string;
  id_token?: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
}

export interface OidcDiscoveryDoc {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri?: string;
  scopes_supported?: string[];
}

export interface SessionPayload {
  sub: number;
  email: string;
  username: string;
  role: 'admin' | 'user';
  iat?: number;
  exp?: number;
}

interface PendingOidcState {
  codeVerifier: string;
  redirectUri: string;
  expiresAt: number;
}

@Injectable()
export class AuthService implements OnModuleInit {
  private readonly logger = new Logger(AuthService.name);
  private discoveryDoc: OidcDiscoveryDoc | null = null;
  private authSecret: string;
  private readonly stateStore = new Map<string, PendingOidcState>();

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {
    this.authSecret =
      process.env.AUTH_SECRET ||
      crypto.randomBytes(32).toString('hex');
  }

  async onModuleInit() {
    // Ensure user table exists regardless of migration runner state
    try {
      await this.userRepository.query(`
        CREATE TABLE IF NOT EXISTS "user" (
          "id" integer PRIMARY KEY AUTOINCREMENT NOT NULL,
          "email" varchar NOT NULL UNIQUE,
          "username" varchar NOT NULL,
          "passwordHash" varchar,
          "oidcSub" varchar,
          "role" varchar NOT NULL DEFAULT ('user'),
          "createdAt" datetime NOT NULL DEFAULT (datetime('now')),
          "updatedAt" datetime NOT NULL DEFAULT (datetime('now'))
        )
      `);
    } catch (err: any) {
      this.logger.warn(`Could not verify user table: ${err.message}`);
    }

    if (this.isOidcEnabled()) {
      await this.getDiscoveryDoc().catch((err) => {
        this.logger.warn(`Failed initial OIDC discovery: ${err.message}`);
      });
    }

    // Clean up expired OIDC pending states every 5 minutes
    setInterval(() => {
      const now = Date.now();
      for (const [key, value] of this.stateStore.entries()) {
        if (value.expiresAt < now) {
          this.stateStore.delete(key);
        }
      }
    }, 5 * 60 * 1000).unref();
  }

  isOidcEnabled(): boolean {
    return Boolean(
      process.env.OIDC_ISSUER_URL &&
        process.env.OIDC_CLIENT_ID &&
        process.env.OIDC_CLIENT_SECRET,
    );
  }

  async isAuthRequired(): Promise<boolean> {
    if (this.isOidcEnabled()) {
      return true;
    }
    if (process.env.LOCAL_ADMIN_PASSWORD) {
      return true;
    }
    const count = await this.userRepository.count().catch(() => 0);
    return count > 0;
  }

  async getAuthStatus(user?: SessionPayload | null): Promise<AuthStatusDto> {
    const authRequired = await this.isAuthRequired();
    const oidcEnabled = this.isOidcEnabled();

    if (!user) {
      return {
        authRequired,
        authenticated: false,
        oidcEnabled,
        user: null,
      };
    }

    const authUser: AuthUserDto = {
      id: user.sub,
      email: user.email,
      username: user.username,
      role: user.role,
    };

    return {
      authRequired,
      authenticated: true,
      oidcEnabled,
      user: authUser,
    };
  }

  async getDiscoveryDoc(): Promise<OidcDiscoveryDoc> {
    if (this.discoveryDoc) {
      return this.discoveryDoc;
    }

    const rawIssuerUrl = process.env.OIDC_ISSUER_URL;
    if (!rawIssuerUrl) {
      throw new BadRequestException('OIDC_ISSUER_URL is not configured');
    }

    const issuerUrl = rawIssuerUrl.replace(/\/+$/, '');
    const discoveryUrl = `${issuerUrl}/.well-known/openid-configuration`;

    try {
      const res = await axios.get<OidcDiscoveryDoc>(discoveryUrl, {
        timeout: 10000,
      });
      this.discoveryDoc = res.data;
      return this.discoveryDoc;
    } catch (err: any) {
      this.logger.error(
        `Failed to fetch OIDC discovery document from ${discoveryUrl}: ${err.message}`,
      );
      throw new BadRequestException(
        `Could not connect to OIDC Provider at ${discoveryUrl}`,
      );
    }
  }

  async createAuthorizationUrl(reqRedirectUri?: string): Promise<{
    url: string;
    state: string;
    codeVerifier: string;
    redirectUri: string;
  }> {
    const doc = await this.getDiscoveryDoc();
    const clientId = process.env.OIDC_CLIENT_ID!;
    const redirectUri =
      process.env.OIDC_REDIRECT_URI ||
      reqRedirectUri ||
      'http://localhost:6246/api/auth/oidc/callback';

    const state = crypto.randomBytes(16).toString('hex');
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');

    const scopes = process.env.OIDC_SCOPES || 'openid profile email groups';

    const authUrl = new URL(doc.authorization_endpoint);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('scope', scopes);
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    // Store state in-memory fallback with 5 min TTL
    this.stateStore.set(state, {
      codeVerifier,
      redirectUri,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });

    return {
      url: authUrl.toString(),
      state,
      codeVerifier,
      redirectUri,
    };
  }

  async handleOidcCallback(
    code: string,
    state: string,
    cookieVerifier?: string,
    cookieRedirectUri?: string,
    fallbackRedirectUri?: string,
  ): Promise<{ user: User; token: string }> {
    const pending = this.stateStore.get(state);
    const codeVerifier = cookieVerifier || pending?.codeVerifier;
    const redirectUri =
      process.env.OIDC_REDIRECT_URI ||
      cookieRedirectUri ||
      pending?.redirectUri ||
      fallbackRedirectUri;

    if (!codeVerifier) {
      throw new BadRequestException(
        'Missing OIDC code verifier or expired state. Please login again.',
      );
    }
    if (!redirectUri) {
      throw new BadRequestException('Missing redirect URI for OIDC callback');
    }

    if (pending) {
      this.stateStore.delete(state);
    }

    const doc = await this.getDiscoveryDoc();
    const clientId = process.env.OIDC_CLIENT_ID!;
    const clientSecret = process.env.OIDC_CLIENT_SECRET!;

    const params = new URLSearchParams();
    params.set('grant_type', 'authorization_code');
    params.set('code', code);
    params.set('redirect_uri', redirectUri);
    params.set('client_id', clientId);
    params.set('client_secret', clientSecret);
    params.set('code_verifier', codeVerifier);

    const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString(
      'base64',
    );

    let tokenRes: any;
    try {
      tokenRes = await axios.post(doc.token_endpoint, params.toString(), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${basicAuth}`,
        },
        timeout: 15000,
      });
    } catch (err: any) {
      const detail = err.response?.data
        ? JSON.stringify(err.response.data)
        : err.message;
      this.logger.error(`OIDC token exchange failed: ${detail}`);
      throw new UnauthorizedException(`OIDC token exchange failed: ${detail}`);
    }

    const tokens: OidcTokens = tokenRes.data;
    let claims: Record<string, any> = {};

    if (tokens.id_token) {
      try {
        const parts = tokens.id_token.split('.');
        if (parts.length >= 2) {
          const payload = Buffer.from(parts[1], 'base64url').toString('utf8');
          claims = JSON.parse(payload);
        }
      } catch (err: any) {
        this.logger.warn(`Failed to parse id_token payload: ${err.message}`);
      }
    }

    // Always fetch and merge /userinfo endpoint per known issues mandate
    if (doc.userinfo_endpoint && tokens.access_token) {
      try {
        const userInfoRes = await axios.get(doc.userinfo_endpoint, {
          headers: {
            Authorization: `Bearer ${tokens.access_token}`,
          },
          timeout: 10000,
        });
        claims = { ...claims, ...userInfoRes.data };
      } catch (err: any) {
        this.logger.warn(
          `Failed to fetch claims from userinfo endpoint: ${err.message}`,
        );
      }
    }

    const emailKey = process.env.OIDC_CLAIM_EMAIL_KEY || 'email';
    const email =
      claims[emailKey] ||
      claims.email ||
      claims.preferred_username ||
      (claims.sub ? `${claims.sub}@oidc.user` : null);

    if (!email) {
      throw new BadRequestException(
        'OIDC login failed: Provider did not return an email or identifier claim.',
      );
    }

    const groupsKey = process.env.OIDC_CLAIM_GROUPS_KEY || 'groups';
    let rawGroups = claims[groupsKey] || claims.roles || [];
    if (typeof rawGroups === 'string') {
      rawGroups = [rawGroups];
    }
    const groups: string[] = Array.isArray(rawGroups) ? rawGroups : [];

    const adminGroup = process.env.OIDC_ADMIN_GROUP;
    const userGroup = process.env.OIDC_USER_GROUP;

    const isAdmin = adminGroup ? groups.includes(adminGroup) : false;
    const isUser = userGroup ? groups.includes(userGroup) : true;

    if (adminGroup && !isAdmin && userGroup && !isUser) {
      throw new ForbiddenException(
        'Access denied: You are not a member of the required OIDC group.',
      );
    }

    const user = await this.findOrCreateOidcUser({
      email,
      username:
        claims.preferred_username ||
        claims.name ||
        email.split('@')[0],
      oidcSub: claims.sub,
      role: isAdmin ? 'admin' : 'user',
    });

    const token = this.generateSessionToken({
      sub: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
    });

    return { user, token };
  }

  async findOrCreateOidcUser(data: {
    email: string;
    username: string;
    oidcSub?: string;
    role: 'admin' | 'user';
  }): Promise<User> {
    let user = await this.userRepository.findOne({
      where: [{ email: data.email }, ...(data.oidcSub ? [{ oidcSub: data.oidcSub }] : [])],
    });

    if (!user) {
      user = this.userRepository.create({
        email: data.email,
        username: data.username,
        oidcSub: data.oidcSub,
        role: data.role,
      });
      return await this.userRepository.save(user);
    }

    let modified = false;
    if (data.oidcSub && user.oidcSub !== data.oidcSub) {
      user.oidcSub = data.oidcSub;
      modified = true;
    }
    if (data.role === 'admin' && user.role !== 'admin') {
      user.role = 'admin';
      modified = true;
    }
    if (data.username && user.username !== data.username) {
      user.username = data.username;
      modified = true;
    }

    if (modified) {
      return await this.userRepository.save(user);
    }

    return user;
  }

  async validateLocalLogin(
    username: string,
    password: string,
  ): Promise<{ user: User; token: string }> {
    // Check fallback local admin env vars
    const envAdminUser = process.env.LOCAL_ADMIN_USERNAME || 'admin';
    const envAdminPass = process.env.LOCAL_ADMIN_PASSWORD;

    if (
      envAdminPass &&
      username.toLowerCase() === envAdminUser.toLowerCase() &&
      password === envAdminPass
    ) {
      let adminUser = await this.userRepository.findOne({
        where: { email: `${envAdminUser}@maintainerr.local` },
      });
      if (!adminUser) {
        adminUser = this.userRepository.create({
          email: `${envAdminUser}@maintainerr.local`,
          username: envAdminUser,
          role: 'admin',
          passwordHash: this.hashPassword(envAdminPass),
        });
        adminUser = await this.userRepository.save(adminUser);
      }
      const token = this.generateSessionToken({
        sub: adminUser.id,
        email: adminUser.email,
        username: adminUser.username,
        role: adminUser.role,
      });
      return { user: adminUser, token };
    }

    // Check DB users
    const user = await this.userRepository.findOne({
      where: [{ username }, { email: username }],
    });

    if (!user || !user.passwordHash) {
      throw new UnauthorizedException('Invalid username or password');
    }

    const isValid = this.verifyPassword(password, user.passwordHash);
    if (!isValid) {
      throw new UnauthorizedException('Invalid username or password');
    }

    const token = this.generateSessionToken({
      sub: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
    });

    return { user, token };
  }

  generateSessionToken(payload: SessionPayload): string {
    const header = Buffer.from(
      JSON.stringify({ alg: 'HS256', typ: 'JWT' }),
    ).toString('base64url');

    const now = Math.floor(Date.now() / 1000);
    const body = Buffer.from(
      JSON.stringify({
        ...payload,
        iat: now,
        exp: now + 7 * 24 * 3600, // 7 days
      }),
    ).toString('base64url');

    const unsignedToken = `${header}.${body}`;
    const signature = crypto
      .createHmac('sha256', this.authSecret)
      .update(unsignedToken)
      .digest('base64url');

    return `${unsignedToken}.${signature}`;
  }

  verifySessionToken(token: string): SessionPayload {
    if (!token) {
      throw new UnauthorizedException('Missing authentication token');
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new UnauthorizedException('Malformed authentication token');
    }

    const [header, body, signature] = parts;
    const unsignedToken = `${header}.${body}`;
    const expectedSignature = crypto
      .createHmac('sha256', this.authSecret)
      .update(unsignedToken)
      .digest('base64url');

    const sigBuf = Buffer.from(signature);
    const expBuf = Buffer.from(expectedSignature);

    if (
      sigBuf.length !== expBuf.length ||
      !crypto.timingSafeEqual(sigBuf, expBuf)
    ) {
      throw new UnauthorizedException('Invalid token signature');
    }

    try {
      const payload: SessionPayload = JSON.parse(
        Buffer.from(body, 'base64url').toString('utf8'),
      );
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < now) {
        throw new UnauthorizedException('Authentication token has expired');
      }
      return payload;
    } catch (err: any) {
      throw new UnauthorizedException(
        `Failed to parse token payload: ${err.message}`,
      );
    }
  }

  hashPassword(password: string): string {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto
      .pbkdf2Sync(password, salt, 10000, 64, 'sha512')
      .toString('hex');
    return `${salt}:${hash}`;
  }

  verifyPassword(password: string, stored: string): boolean {
    const [salt, hash] = stored.split(':');
    if (!salt || !hash) return false;
    const verifyHash = crypto
      .pbkdf2Sync(password, salt, 10000, 64, 'sha512')
      .toString('hex');
    const hashBuf = Buffer.from(hash, 'hex');
    const verifyBuf = Buffer.from(verifyHash, 'hex');
    if (hashBuf.length !== verifyBuf.length) return false;
    return crypto.timingSafeEqual(hashBuf, verifyBuf);
  }
}
