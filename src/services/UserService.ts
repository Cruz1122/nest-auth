import {
    BadRequestException,
    ConflictException,
    Injectable,
    NotFoundException,
    UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { User as SchemaUser, UserDocument } from '../users/schema/user.schema';
import {
    ChangePasswordDto,
    CreateUserDto,
    LoginDto,
    RefreshTokenDto,
    UpdateUserDto,
    VerifyEmailDto,
} from '../users/DTO/user.dto';
import { User, UserServiceInterface } from '../users/interfaces/user.interface';
import { EmailService } from '../email/email.service';

@Injectable()
export class UserService implements UserServiceInterface {
    constructor(
        @InjectModel(SchemaUser.name) private userModel: Model<UserDocument>,
        private jwtService: JwtService,
        private configService: ConfigService,
        private emailService: EmailService,
    ) { }
    async verify(id: string): Promise<User> {
        const user = await this.userModel.findById(id).exec();
        if (!user) throw new NotFoundException('User not found');
        user.isVerified = true;
        user.verificationCode = undefined;
        user.verificationCodeExpires = undefined;
        await user.save();
        return this.userInterface(user);
    }

    private userInterface(userDoc: UserDocument): User {
        const userObj = userDoc.toObject();
        userObj.id = userObj._id.toString();
        delete userObj.password;
        delete userObj.__v;
        return userObj as User;
    }

    private getTokens(user: UserDocument) {
        const payload = {
            sub: user.id,
            email: user.email,
            role: user.role,
        };
        const accessToken = this.jwtService.sign(payload, {
            secret: this.configService.get('JWT_ACCESS_SECRET'),
            expiresIn: '1h',
        });
        const refreshToken = this.jwtService.sign(payload, {
            secret: this.configService.get('JWT_REFRESH_SECRET'),
            expiresIn: '7d',
        });
        return { accessToken, refreshToken };
    }

    async create(createUserDto: CreateUserDto): Promise<User> {
        const existingUser = await this.userModel.findOne({ email: createUserDto.email }).exec();
        if (existingUser) {
            throw new ConflictException('Email already registered');
        }

        const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const verificationCodeExpires = new Date(Date.now() + 5 * 60 * 1000);

        const createdUser = await this.userModel.create({
            ...createUserDto,
            password: hashedPassword,
            verificationCode,
            verificationCodeExpires,
            isVerified: false,
        });

        await this.emailService.sendVerificationEmail(createdUser.email, createdUser.name, verificationCode);
        return this.userInterface(createdUser);
    }

    async verifyEmail(dto: VerifyEmailDto): Promise<User> {
        const user = await this.userModel.findOne({ email: dto.email }).exec();
        if (!user) throw new NotFoundException('User not found');
        if (
            user.verificationCode !== dto.code ||
            !user.verificationCodeExpires ||
            user.verificationCodeExpires < new Date()
        ) {
            throw new BadRequestException('Invalid or expired code');
        }
        user.isVerified = true;
        user.verificationCode = undefined;
        user.verificationCodeExpires = undefined;
        await user.save();
        return this.userInterface(user);
    }

    async login(dto: LoginDto) {
        const user = await this.userModel.findOne({ email: dto.email }).exec();
        if (!user || !(await bcrypt.compare(dto.password, user.password))) {
            throw new UnauthorizedException('Invalid credentials');
        }
        if (!user.isVerified) {
            throw new UnauthorizedException('Email not verified');
        }
        const tokens = this.getTokens(user);
        return {
            ...tokens,
            user: this.userInterface(user),
        };
    }

    async refreshToken(refreshToken: string) {
        try {
            const payload = this.jwtService.verify(refreshToken, {
                secret: this.configService.get('JWT_REFRESH_SECRET'),
            });
            const user = await this.userModel.findById(payload.sub).exec();
            if (!user) throw new NotFoundException('User not found');
            return this.getTokens(user);
        } catch (err) {
            throw new UnauthorizedException('Invalid refresh token');
        }
    }

    async findAll(): Promise<User[]> {
        const users = await this.userModel.find().exec();
        return users.map((user) => this.userInterface(user));
    }

    async findOne(id: string): Promise<User> {
        const user = await this.userModel.findById(id).exec();
        if (!user) throw new NotFoundException('User not found');
        return this.userInterface(user);
    }

    async findByEmail(email: string): Promise<User> {
        const user = await this.userModel.findOne({ email }).exec();
        if (!user) throw new NotFoundException('User not found');
        return this.userInterface(user);
    }

    async update(id: string, updateDto: UpdateUserDto): Promise<User> {
        const user = await this.userModel.findByIdAndUpdate(id, updateDto, { new: true }).exec();
        if (!user) throw new NotFoundException('User not found');
        return this.userInterface(user);
    }

    async remove(id: string): Promise<void> {
        const result = await this.userModel.findByIdAndDelete(id).exec();
        if (!result) throw new NotFoundException('User not found');
    }

    async verifyUser(id: string): Promise<void> {
        const user = await this.userModel.findById(id).exec();
        if (!user) throw new NotFoundException('User not found');
        user.isVerified = true;
        await user.save();
    }

    async changePassword(id: string, dto: ChangePasswordDto): Promise<void> {
        const user = await this.userModel.findById(id).exec();
        if (!user) throw new NotFoundException('User not found');

        const isMatch = await bcrypt.compare(dto.oldPassword, user.password);
        if (!isMatch) throw new UnauthorizedException('Old password is incorrect');

        user.password = await bcrypt.hash(dto.newPassword, 10);
        await user.save();
    }
}

export default UserService;
