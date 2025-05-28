import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from '../schema/user.schema';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(
        @InjectModel(User.name) private userModel: Model<UserDocument>,
        private configService: ConfigService,
    ) {
        const secretKey = configService.get<string>('JWT_ACCESS_SECRET');
        if (!secretKey) {
            throw new Error('JWT_ACCESS_SECRET is not defined in the environment variables');
        }

        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: secretKey,
        });
    }

    async validate(payload: any) {
        const user = await this.userModel.findById(payload.sub).exec();
        if (!user) {
            throw new UnauthorizedException('User not found');
        }

        return { id: payload.sub, email: payload.email, role: payload.role };
    }
}
