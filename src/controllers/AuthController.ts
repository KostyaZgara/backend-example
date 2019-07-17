// core
import { validate } from 'Validation/Validation';
import JWTAuth from 'Auth/JWTAuth';
import { Request, Response, DefaultBody, DefaultHeaders, DefaultParams, DefaultQuery } from 'Contracts/Common';
import Mail from 'Mail/Mail';
// services
import AuthService from 'app/services/AuthService';
import UserService from 'app/services/UserService';
import TokenService from 'app/services/TokenService';
import ChatService from 'app/services/ChatService';
import PaymentService from 'app/services/PaymentService';
import RequestService from 'app/services/RequestService';
// helpers
import String from 'Helpers/String';
import Crypto from 'Helpers/Crypto';
// mails
import ConfirmMail from 'app/mails/ConfirmEmail';
import ForgotPasswordEmail from 'app/mails/ForgotPasswordEmail';
// errors
import BadRequestError from 'Errors/BadRequestError';
import ForbiddenRequestError from 'Errors/ForbiddenRequestError';
import AuthError from 'Errors/AuthError';
import { type, code } from 'app/services/ErrorService';
// types
import { Api } from 'herheadquarters';
import { IUser } from 'app/models/User';

export default class AuthController {
	public static async checkHealthy() {
		return {
			success: true,
		};
	}

	@validate({
		body: {
			type: 'object',
			properties: {
				email: { type: 'string' },
				password: { type: 'string' },
			},
			required: ['email', 'password'],
			additionalProperties: false
		},
		response: {
			200: {
				type: 'object',
				properties: {
					success: { type: 'boolean' },
					data: {
						type: 'object',
						properties: {
							user: 'user#',
							token: { type: 'string' },
							rooms: {
								type: 'array',
								items: { type: 'string' },
							},
							unreadMessages: { type: 'number' },
							unviewedRequests: { type: 'number' },
						},
					},
				},
			},
			400: 'badResponse#',
			500: 'badResponse#',
		},
	})
	public static async login(
		req: Request<DefaultQuery, DefaultParams, DefaultHeaders, Api.Auth.ILoginBody>,
		res: Response,
	) {
		req.body = String.trimAllFields(req.body);

		const user: IUser = await UserService.getUserByEmail(req.body.email);

		// check password match
		if (!Crypto.verifyHash(req.body.password, user.password, user.salt)) {
			throw new AuthError(`Password doesn't match`);
		}

		// check if email confirmed
		if (!user.emailConfirmed) {
			throw new ForbiddenRequestError(`We are unable to approve your request to join without a confirmed email`, type.authentication, code.email_not_confirmed);
		}

		if (user.status !== 'approved') {
			throw new ForbiddenRequestError(`Your account is waiting for approval by our admin. It takes up to 72 hours`, type.authentication, code.not_approved);
		}

		const [ token, rooms, unreadMessages, unviewedRequests, ] = await Promise.all([
			// generate jwt token for user
			JWTAuth.getToken(user.toObject()),
			// get chat rooms for user
			ChatService.getUserRooms(user._id.toString()),
			ChatService.getCountOfUnreadMessages(user._id.toString()),
			RequestService.getUnviewedRequests(user._id.toString()),
		]);

		// save user and token to session
		req.session.token = token;
		req.session.user = UserService.clearUser(user.toObject());

		return {
			success: true,
			data: {
				token,
				user: JSON.parse(JSON.stringify(user)),
				rooms,
				unreadMessages,
				unviewedRequests,
			}
		};
	}

	@validate({
		body: {
			type: 'object',
			properties: {
				email: { type: 'string' },
				phone: { type: 'string' },
				password: { type: 'string' },
				firstName: { type: 'string' },
				lastName: { type: 'string' },
				companyName: { type: 'string' },
				industry: { type: 'string' },
				city: { type: 'string' },
				companyWebsite: { type: 'string' },
				socialLinks: {
					type: 'object',
					properties: {
						twitter: { type: 'string' },
						instagram: { type: 'string' },
						facebook: { type: 'string' },
					},
					additionalProperties: false
				},
				autoLogin: { type: 'boolean' },
				subscription: {
					type: 'object',
					properties: {
						plan: { type: 'string' },
						promocode: { type: 'string' },
					},
				},
			},
			required: [ 'email', 'phone', 'password', 'firstName', 'lastName' ],
			additionalProperties: false
		},
		response: {
			201: {
				type: 'object',
				properties: {
					success: { type: 'boolean' },
					data: {
						type: 'object',
						properties: {
							user: 'user#',
							token: { type: 'string' },
						},
					},
				},
			},
			400: 'badResponse#',
			500: 'badResponse#',
		},
	})
	public static async signUp(
		req: Request<DefaultQuery, DefaultParams, DefaultHeaders, Api.Auth.ISignupBody>,
		res: Response
	) {
		// Remove spaces from string fields
		req.body = String.trimAllFields(req.body);

		if (!String.isEmail(req.body.email)) {
			throw new BadRequestError('Email wrong');
		}

		String.validatePassword(req.body.password);

		let user;

		try {
			user = await AuthService.signUp(req.body);
		} catch (e) {
			if (e.message.includes('E11000 duplicate key error collection')) {
				const fromPattern = 'index: ';
				const toPattern = ' dup key';

				const from = e.message.search(fromPattern) + fromPattern.length;
				const to = e.message.search(toPattern) - 2;

				const duplicateKey = e.message.substring(from, to);

				throw new BadRequestError(`That ${duplicateKey} is taken. Try another.`);
			} else {
				throw new BadRequestError(e.message);
			}
		}

		// send email with confirmation
		const verificationToken = await TokenService.generateAndSaveToken(user);

		const url = `${req.backendUrl}/email/confirm/${verificationToken.token}`;

		try {
			await Mail.to(req.body.email).send(new ConfirmMail({
				url,
			}));
		} catch (e) {
			throw new BadRequestError(`Can't send email to ${req.body.email}`);
		}

		res.status(201);

		let token;

		if (req.body.autoLogin) {
			token = await JWTAuth.getToken(user.toObject());
			req.session.token = token;
			req.session.user = UserService.clearUser(user.toObject());
		}

		return {
			success: true,
			data: {
				user,
				token,
			},
		};
	}

	@validate({
		params: {
			type: 'object',
			properties: {
				token: { type: 'string' },
			},
			required: [ 'token' ],
			additionalProperties: false
		},
		response: {
			200: {
				type: 'object',
				properties: {
					success: { type: 'boolean' },
					data: {
						type: 'object',
						properties: {
							user: 'user#',
						}
					},
				}
			},
			400: 'badResponse#',
			500: 'badResponse#',
		},
	})
	public static async verifyEmail(
		req: Request<DefaultQuery, Api.Auth.IVerifyEmailParams>,
		res: Response
	) {
		const user = await TokenService.verifyToken(req.params.token);

		if (!user) {
			return res.redirect(302, `${req.frontUrl}/email/confirm/notfound`);
		}

		user.emailConfirmed = true;

		const [ { stripeCustomer }, token ] = await Promise.all([
			PaymentService.getStripeCustomer(user._id),
			JWTAuth.getToken(user.toObject()),
			user.save(),
		]);

		// auto log in user
		req.session.token = token;
		req.session.user = UserService.clearUser(user.toObject());

		if (stripeCustomer.preApprovePlan === 'Basic' && !stripeCustomer.defaultSource) {
			return res.redirect(302, `${req.frontUrl}/signup/checkout?coupon=${stripeCustomer.coupon}`);
		} else {
			return res.redirect(302, `${req.frontUrl}/signup/success`);
		}
	}

	@validate({
		body: {
			type: 'object',
			properties: {
				email: { type: 'string' },
			},
			required: ['email'],
			additionalProperties: false
		},
		response: {
			200: {
				type: 'object',
				properties: {
					success: { type: 'boolean' },
				}
			},
			400: 'badResponse#',
			500: 'badResponse#',
		}
	})
	public static async forgot(
		req: Request<DefaultQuery, DefaultParams, DefaultHeaders, Api.Auth.IForgotBody>,
		res: Response
	) {
		const user = await UserService.getUserByEmail(req.body.email, []);

		if (!user.emailConfirmed) {
			throw new ForbiddenRequestError('Email is not confirmed');
		}

		const result = await TokenService.generateAndSaveToken(user._id.toString());
		const url = `${req.backendUrl}/password/validate/${result.token}`;

		await Mail.to(user.email).send(new ForgotPasswordEmail({
			url,
		}));

		return {
			success: true,
		};
	}

	@validate({
		body: {
			type: 'object',
			properties: {
				oldPassword: { type: 'string' },
				newPassword: { type: 'string' },
				confirmPassword: { type: 'string' },
			},
			required: ['newPassword', 'oldPassword', 'confirmPassword'],
			additionalProperties: false
		},
		response: {
			200: {
				type: 'object',
				properties: {
					success: { type: 'boolean' },
				}
			},
			400: 'badResponse#',
			401: 'badResponse#',
			500: 'badResponse#',
		}
	})
	public static async changePassword(
		req: Request<DefaultQuery, DefaultParams, DefaultHeaders, Api.Auth.IChangePasswordBody>,
		res: Response
	) {
		if (req.body.newPassword !== req.body.confirmPassword) {
			throw new BadRequestError(`Confirm password doesn't match`);
		}

		String.validatePassword(req.body.newPassword);

		// check old password match
		const user = await UserService.getUserById(req.session.user._id, [], ['password', 'salt']);

		if (!Crypto.verifyHash(req.body.oldPassword, user.password, user.salt)) {
			throw new BadRequestError(`Wrong current password`);
		}

		const result = await AuthService.getNewPassword(req.body.newPassword);

		await UserService.updateUser(req.session.user._id, result);

		return {
			success: true,
		};
	}

	@validate({
		params: {
			type: 'object',
			properties: {
				token: { type: 'string' },
			},
			required: ['token'],
			additionalProperties: false
		},
		response: {
			400: 'badResponse#',
			500: 'badResponse#',
		},
	})
	public static async validate(
		req: Request<DefaultQuery, Api.Auth.IValidateParams>,
		res: Response
	) {
		const isValid = await TokenService.validatePasswordToken(req.params.token);

		if (!isValid) {
			return res.redirect(302, `${req.frontUrl}/error`);
		}

		return res.redirect(302, `${req.frontUrl}/password/reset/${req.params.token}`);
	}

	@validate({
		params: {
			type: 'object',
			properties: {
				token: { type: 'string' },
			},
			required: ['token'],
			additionalProperties: false,
		},
		body: {
			type: 'object',
			properties: {
				newPassword: { type: 'string' },
				confirmNewPassword: { type: 'string' },
			},
			required: ['newPassword', 'confirmNewPassword'],
			additionalProperties: false,
		},
	})
	public static async reset(
		req: Request<DefaultQuery, Api.Auth.IValidateParams, DefaultHeaders, Api.Auth.IResetBody>,
		res: Response
	) {
		if (req.body.newPassword !== req.body.confirmNewPassword) {
			throw new BadRequestError(`passwords do not match`);
		}

		const token = await TokenService.getTokenByValue(req.params.token);

		if (!token || !token.active || !token.validated) {
			throw new BadRequestError(`Token in invalid`);
		}

		token.active = false;

		const resetPassword = AuthService.resetPassword(token.user, req.body.newPassword);
		const updateToken = token.save();

		await Promise.all([resetPassword, updateToken]);

		return {
			success: true,
		};
	}

	public static async logout(
		req: Request<DefaultQuery, DefaultParams, DefaultHeaders, DefaultBody>,
	) {
		await req.destroySession();

		return {
			success: true,
		};
	}
}
