import * as jwt from 'jsonwebtoken';
// core
import Config from 'Config';
// services
import UserService from 'app/services/UserService';
// types
import IAuthService from 'Contracts/Auth/AuthService';
import { Request, Response } from 'Contracts/Common';
// errors
import AuthError from 'Errors/AuthError';
import { type, code } from 'app/services/ErrorService';

class JWTAuth implements IAuthService {
	public static getToken(payload, cb?): any {
		payload = UserService.clearUser(payload);

		const options = {
			expiresIn: Config.env('auth:expiresIn', 3600),
			notBefore: Config.env('auth:notBefore', 0),
			audience: Config.env('auth:audience', ''),
			issuer: Config.env('auth:issuer', ''),
			subject: Config.env('auth:subject', ''),
		};

		if (cb) {
			jwt.sign(
				payload,
				Config.env('JWT_SECRET_KEY'),
				options,
				cb);
		} else {
			return new Promise((resolve, reject) => {
				jwt.sign(
					payload,
					Config.env('JWT_SECRET_KEY'),
					options,
					(err, token) => {
						if (err) {
							return reject(err);
						}

						return resolve(token);
					});
			});
		}
	}

	public static async authenticate(req: Request, res: Response) {
		if (!req.headers.authorization && !req.session.token) {
			throw new AuthError('Session expired', type.authentication, code.session_expired);
		}

		let tokenFromHeader;

		if (req.headers.authorization) {
			const splittedAuthHeader = req.headers.authorization.split(' ');

			tokenFromHeader = splittedAuthHeader.length ? splittedAuthHeader[1] : null;
		}

		const token = tokenFromHeader || req.session.token;

		if (!token) {
			throw new AuthError(
				`Can't get token from authorization header. Are you sure that authorization header in format "authorization: Bearer [token]"`,
				type.authentication,
				code.invalid_authentication,
			);
		}

		try {
			const decodedUser = jwt.verify(token, Config.env('JWT_SECRET_KEY'));

			req.session.user = UserService.clearUser(decodedUser);
			req.session.token = token;
		} catch (err) {
			if (err.name === 'TokenExpiredError' && Config.env('auth:autoRenewToken', false)) {
				req.session.token = await JWTAuth.getToken(req.session.user);
			} else {
				throw new AuthError(err.message);
			}
		}
	}

}

export default JWTAuth;
