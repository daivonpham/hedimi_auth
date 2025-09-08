import {
  Injectable,
  UnauthorizedException,
  ConflictException,
} from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import * as bcrypt from "bcryptjs";
import { User, UserRole } from "./entities/user.entity";
import { RefreshToken } from "./entities/refresh-token.entity";
import { RegisterDto } from "./dto/register.dto";
import { LoginDto } from "./dto/login.dto";

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
    @InjectRepository(RefreshToken)
    private refreshTokenRepository: Repository<RefreshToken>,
    private jwtService: JwtService
  ) {}

  async register(registerDto: RegisterDto) {
    const { username, email, password } = registerDto;

    // Check if user exists
    const existingUser = await this.usersRepository.findOne({
      where: [{ username }, { email }],
    });

    if (existingUser) {
      throw new ConflictException("Username or email already exists");
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = this.usersRepository.create({
      username,
      email,
      password: hashedPassword,
      role: UserRole.USER,
    });

    await this.usersRepository.save(user);

    return { message: "User registered successfully" };
  }

  async validateUser(loginDto: LoginDto) {
    const { username, password } = loginDto;
    const user = await this.usersRepository.findOne({
      where: { username },
    });

    if (!user) {
      throw new UnauthorizedException("Invalid credentials");
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException("Invalid credentials");
    }

    return user;
  }

  async login(user: User) {
    const payload = {
      sub: user.id,
      username: user.username,
      role: user.role,
    };

    // Generate access token
    const accessToken = this.jwtService.sign(payload, {
      expiresIn: "15m",
    });

    // Generate refresh token
    const refreshToken = this.jwtService.sign(payload, {
      expiresIn: "7d",
    });

    // Save refresh token
    const refreshTokenEntity = this.refreshTokenRepository.create({
      token: refreshToken,
      user,
      expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    });

    await this.refreshTokenRepository.save(refreshTokenEntity);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  async refresh(refreshToken: string) {
    try {
      // Verify refresh token
      const payload = this.jwtService.verify(refreshToken);

      // Check if token exists and is not revoked
      const tokenEntity = await this.refreshTokenRepository.findOne({
        where: {
          token: refreshToken,
          revoked: false,
        },
        relations: ["user"],
      });

      if (!tokenEntity || new Date() > tokenEntity.expires_at) {
        throw new UnauthorizedException("Invalid refresh token");
      }

      // Revoke old refresh token
      tokenEntity.revoked = true;
      await this.refreshTokenRepository.save(tokenEntity);

      // Generate new tokens
      return this.login(tokenEntity.user);
    } catch {
      throw new UnauthorizedException("Invalid refresh token");
    }
  }

  async logout(userId: number, refreshToken: string) {
    const tokenEntity = await this.refreshTokenRepository.findOne({
      where: {
        token: refreshToken,
        user_id: userId,
        revoked: false,
      },
    });

    if (tokenEntity) {
      tokenEntity.revoked = true;
      await this.refreshTokenRepository.save(tokenEntity);
    }

    return { message: "Logged out successfully" };
  }

  async getProfile(userId: number) {
    const user = await this.usersRepository.findOne({
      where: { id: userId },
      select: ["id", "username", "email", "role", "created_at"],
    });

    if (!user) {
      throw new UnauthorizedException("User not found");
    }

    return user;
  }
}
