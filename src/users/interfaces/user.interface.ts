import {
  ChangePasswordDto,
  CreateUserDto,
  LoginDto,
  UpdateUserDto,
} from '../DTO/user.dto';

export interface User {
  _id: string;        // MongoDB
  id?: string;
  name: string;
  email: string;
  isVerified: boolean;
  role: string;
  refreshToken?: string;
  verificationCode?: string;
  verificationCodeExpires?: Date;
  createdAt?: Date;
  updatedAt?: Date;
}

export interface UserServiceInterface {
  create(createUserDto: CreateUserDto): Promise<User>;
  findAll(): Promise<User[]>;
  findOne(id: string): Promise<User>;
  findByEmail(email: string): Promise<User>;
  update(id: string, updateUserDto: UpdateUserDto): Promise<User>;
  remove(id: string): Promise<void>;
  verify(id: string): Promise<User>;
  login(
    loginDto: LoginDto,
  ): Promise<{ accessToken: string; refreshToken: string; user: User }>;
  refreshToken(
    refreshToken: string,
  ): Promise<{ accessToken: string; refreshToken: string }>;
  changePassword(
    id: string,
    changePasswordDto: ChangePasswordDto,
  ): Promise<void>;
}
