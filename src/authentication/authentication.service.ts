import * as bcrypt from 'bcrypt';
import { Response } from 'express';
import * as jwt from 'jsonwebtoken';
import Paseto from 'paseto.js';
import * as QRCode from 'qrcode';
import * as speakeasy from 'speakeasy';
import UserWithThatEmailAlreadyExistsException from '../exceptions/UserWithThatEmailAlreadyExistsException';
import DataStoredInToken from '../interfaces/dataStoredInToken';
import TokenData from '../interfaces/tokenData.interface';
import CreateUserDto from '../user/user.dto';
import User from '../user/user.interface';
import userModel from './../user/user.model';

class AuthenticationService {
  public user = userModel;

  public async register(userData: CreateUserDto) {
    if (await this.user.findOne({ email: userData.email })) {
      throw new UserWithThatEmailAlreadyExistsException(userData.email);
    }
    const hashedPassword = await bcrypt.hash(userData.password, 10);
    const user = await this.user.create({
      ...userData,
      password: hashedPassword,
    });
    user.password = undefined;
    const tokenData = this.createToken(user);
    const cookie = this.createCookie(tokenData);
    return {
      cookie,
      user,
    };
  }
  public getTwoFactorAuthenticationCode() {
    console.log(
      'process.env.TWO_FACTOR_AUTHENTICATION_APP_NAME,',
      process.env.TWO_FACTOR_AUTHENTICATION_APP_NAME,
    );

    const secretCode = speakeasy.generateSecret({
      name: process.env.TWO_FACTOR_AUTHENTICATION_APP_NAME,
    });
    return {
      otpauthUrl: secretCode.otpauth_url,
      base32: secretCode.base32,
    };
  }
  public verifyTwoFactorAuthenticationCode(
    twoFactorAuthenticationCode: string,
    user: User,
  ) {
    return speakeasy.totp.verify({
      secret: user.twoFactorAuthenticationCode,
      encoding: 'base32',
      token: twoFactorAuthenticationCode,
    });
  }
  public async respondWithQRCode(data: string, response: Response) {
    QRCode.toFileStream(response, data);
  }
  public createCookie(tokenData: TokenData) {
    return `Authorization=${tokenData.token}; HttpOnly; Max-Age=${tokenData.expiresIn}`;
  }
  public async createToken(
    user: User,
    isSecondFactorAuthenticated = false,
  ): Promise<TokenData> {
    const expiresIn = 60 * 60; // an hour
    const dataStoredInToken: DataStoredInToken = {
      isSecondFactorAuthenticated,
      _id: user._id,
    };

    const encoder = new Paseto.V2();
    const symmetricKey = await encoder.symmetric();

    const token = await encoder.encrypt(dataStoredInToken, symmetricKey);

    return {
      expiresIn,
      token,
    };
  }
}

export default AuthenticationService;
