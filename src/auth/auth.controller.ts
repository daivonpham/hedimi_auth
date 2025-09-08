import { Controller, Post, Body, UseGuards, Req, Get, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshDto } from './dto/refresh.dto';
import { LogoutDto } from './dto/logout.dto';
import { JwtAuthGuard } from './jwt-auth.guard';
import { Throttle } from '@nestjs/throttler';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';

@Controller('api/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @Throttle({ default: { ttl: 3600, limit: 5 } })
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Post('login')
  @Throttle({ default: { ttl: 900, limit: 10 } })
  async login(@Body() loginDto: LoginDto) {
    const user = await this.authService.validateUser(loginDto);
    return this.authService.login(user);
  }

  @Post('refresh')
  @Throttle({ default: { ttl: 3600, limit: 20 } })
  async refresh(@Body() { refreshToken }: RefreshDto) {
    return this.authService.refresh(refreshToken);
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { ttl: 3600, limit: 10 } })
  async logout(@Req() req, @Body() { refreshToken }: LogoutDto) {
    return this.authService.logout(req.user.userId, refreshToken);
  }

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { ttl: 3600, limit: 100 } })
  async getProfile(@Req() req) {
    return this.authService.getProfile(req.user.userId);
  }
}
