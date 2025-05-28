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

    private userInterface(userDoc: UserDocument): User {
        const userObj = userDoc.toObject();
        userObj.id = userObj._id.toString();
        delete userObj.password;
        delete userObj.__v;
        return userObj as User;
    }

    async create(createUserDto: CreateUserDto): Promise<User> {
        const existingUser = await this.userModel
            .findOne({ email: createUserDto.email })
            .exec();
        if (existingUser) {
            throw new ConflictException('Email already registered');
        }

        const hashedPassword = await bcrypt.hash(createUserDto.password, 10);

        const verificationCode =
            Math.floor(100000 + Math.random() * 900000).toString();
        const verificationCodeExpires = new Date();
        verificationCodeExpires.setMinutes(
            verificationCodeExpires.getMinutes() + 5,
        );

        // Guardar el usuario en la base de datos
        const createdUser = await this.userModel.create({
            ...createUserDto,
            password: hashedPassword,
            verificationCode,
            verificationCodeExpires,
            isVerified: false,
        });

        // Enviar correo de verificación
        await this.emailService.sendVerificationEmail(
            createdUser.email,
            verificationCode,
        );

        return this.userInterface(createdUser);
    }
}

export default UserService;
