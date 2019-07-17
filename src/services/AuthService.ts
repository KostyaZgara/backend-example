//services
import PaymentService from 'app/services/PaymentService';
// models
import User, { IUser } from 'app/models/User';
// helpers
import Crypto from 'Helpers/Crypto';

interface IGetNewPasswordResponse {
	password: string;
	salt: string;
}

export default class AuthService {
	public static async signUp(user): Promise<IUser> {
		const salt = Crypto.getSalt();
		const hashPassword = Crypto.getHash(user.password, salt);

		user = {
			...user,
			// set lower case for email
			email: user.email.toLowerCase(),
			password: hashPassword,
			salt,
		};

		const newUser = new User(user);
		await newUser.save();

		// create stripe customer
		newUser.stripeCustomer = await PaymentService.createCustomer(
			newUser,
			undefined,
			user.subscription
		);

		return newUser;
	}

	public static async resetPassword(user: IUser, newPassword: string): Promise<IUser> {
		const salt = Crypto.getSalt();
		const hashPassword = Crypto.getHash(newPassword, salt);

		user.password = hashPassword;
		user.salt = salt;

		return await user.save();
	}

	public static getNewPassword(password: string): IGetNewPasswordResponse {
		const salt = Crypto.getSalt();
		const hashPassword = Crypto.getHash(password, salt);

		return {
			password: hashPassword,
			salt,
		};
	}

}
