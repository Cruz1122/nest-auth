import {
    Controller,
    Get,
    Post,
    Body,
    Patch,
    Param,
    Delete,
    UseGuards,
    HttpCode,
    HttpStatus,
} from '@nestjs/common';
import { UserService } from '../services/UserService';
import {
    CreateUserDto,
    UpdateUserDto,
    LoginDto,
    RefreshTokenDto,
    ChangePasswordDto,
    VerifyEmailDto,
} from '../users/DTO/user.dto';
import { JwtAuthGuard } from '../users/guards/jwt-auth.guard';

@Controller('users')
export class UsersController {
    constructor(private readonly usersService: UserService) { }

    @Post('signup')
    async create(@Body() createUserDto: CreateUserDto) {
        await this.usersService.create(createUserDto);
        return { message: 'User registered successfully. Please check your email for verification code.' };
    }

    @Post('verify-email')
    verifyEmail(@Body() verifyEmailDto: VerifyEmailDto) {
        return this.usersService.verifyEmail(verifyEmailDto);
    }
}
