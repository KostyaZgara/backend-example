import * as chai from 'chai';
import getApplication from '../app';
import Crypto from 'Helpers/Crypto';
import Token from 'app/models/Token';
import Config from 'Config';
import * as moment from 'moment';
import {
	badCreateNewUser,
	successfullyCreateNewUser,
	removeUsers,
	removeTokens,
	user,
	userWithoutEmail,
	userWithoutPhone,
	userWithoutPassword,
	userWithoutFirstName,
	userWithoutLastName,
	conflictCreateNewUser,
	userWithWrongEmail,
	userForSignin,
	userForSigninWithWrongEmail,
	userForSigninWithWrongPassword,
	signInSuccessfully,
	signInFail,
	signInFailBadRequest,
	userForSigninWithoutEmail,
	userForSigninWithoutPassword,
	userForSigninWithWrongSpacePassword,
	userWithNonTrimmedFields,
	userWithSpaceInPassword,
	confirmEmail,
	badConfirmEmail,
	sendRequestOnResetPassword,
	sendRequestOnResetPasswordBad,
	validateTokenResetPassword,
	validateTokenResetPasswordBad,
	resetPassword,
	resetPasswordBad,
	getSimpleUser,
	changePassword,
	changePasswordBad,
	changePasswordUnauth,
	sendRequestOnResetPasswordForbidden,
} from './utils';
import {removeStripeCustomers} from '../Payment/utils';

const expect = chai.expect;

describe('Auth', () => {
	after(async () => {
		await removeStripeCustomers();
	});

	describe('sign up', () => {

		afterEach(async () => {
			await removeUsers();
		});

		it('should successfully create new user', async () => {
			const app = await getApplication();
			await successfullyCreateNewUser(app, user);
		});

		it('should not create new user without email', async () => {
			const app = await getApplication();
			await badCreateNewUser(app, userWithoutEmail);
		});

		it('should not create new user without phone', async () => {
			const app = await getApplication();
			await badCreateNewUser(app, userWithoutPhone);
		});

		it('should not create new user without password', async () => {
			const app = await getApplication();
			await badCreateNewUser(app, userWithoutPassword);
		});

		it('should not create new user without last name', async () => {
			const app = await getApplication();
			await badCreateNewUser(app, userWithoutLastName);
		});

		it('should not create new user without first name', async () => {
			const app = await getApplication();
			await badCreateNewUser(app, userWithoutFirstName);
		});

		it('should hash password and save in DB', async () => {
			const app = await getApplication();
			const res = await successfullyCreateNewUser(app, user);

			expect(res.db.password).not.equals(user.password);
		});

		it('should not save user if their email already exists', async () => {
			const app = await getApplication();
			await successfullyCreateNewUser(app, user);
			await conflictCreateNewUser(app, user);
		});

		it('should not create new user if email is wrong', async () => {
			const app = await getApplication();
			await badCreateNewUser(app, userWithWrongEmail);
		});

		it('should trim all fields', async () => {
			const app = await getApplication();
			const result = await successfullyCreateNewUser(app, userWithNonTrimmedFields);

			expect(result.db.firstName).not.equals(userWithNonTrimmedFields.firstName);
			expect(result.db.lastName).not.equals(userWithNonTrimmedFields.lastName);
		});

		it('password with spaces and deprecated symbols should fail sign up', async () => {
			const app = await getApplication();
			await badCreateNewUser(app, userWithSpaceInPassword);
		});

		it('new user should have status false of confirmation email', async () => {
			const app = await getApplication();
			const result = await successfullyCreateNewUser(app, user);

			expect(result.db.emailConfirmed).equals(false);
			expect(result.result.data.user.emailConfirmed).equals(false);
		});

		it('new user should be unapproved by default', async () => {
			const app = await getApplication();
			const result = await successfullyCreateNewUser(app, user);

			expect(result.db.status).equals('pending');
			expect(result.result.data.user.status).equals('pending');
		});

		it('should trim email and password in sign up without spaces', async () => {
			const userWithSpaces = {
				...user,
				email: '    test@test.com    ',
				password: '    testpassword1     ',
			};

			const app = await getApplication();
			await getSimpleUser(app, userWithSpaces);
			await signInSuccessfully(app, user);
		});

		it('should create stripe customer', async () => {
			const app = await getApplication();
			const createdUser = await successfullyCreateNewUser(app, user, [{ path: 'stripeCustomer' }]);

			expect(createdUser.db).property('stripeCustomer').property('customer');
			expect(createdUser.db.stripeCustomer).property('plan');
			expect(createdUser.db.stripeCustomer).property('credits').property('extra');
			expect(createdUser.db.stripeCustomer).property('credits').property('subscription');
		});

		it('should save subscription plan on sign up', async () => {
			const app = await getApplication();
			const createdUser = await successfullyCreateNewUser(app, {
				...user,
				subscription: {
					plan: 'Basic',
				}
			}, [{ path: 'stripeCustomer' }]);

			expect(createdUser.db.stripeCustomer).property('preApprovePlan').eq('Basic');
			expect(createdUser.db.stripeCustomer).property('coupon').eq(undefined);
		});

		// for this test please mock coupon with id "dev10" in Stripe
		it('should save subscription plan on sign up with coupon', async () => {
			const app = await getApplication();
			const createdUser = await successfullyCreateNewUser(app, {
				...user,
				subscription: {
					plan: 'Basic',
					promocode: 'dev10',
				}
			}, [{ path: 'stripeCustomer' }]);

			expect(createdUser.db.stripeCustomer).property('coupon').eq('dev10');
			expect(typeof createdUser.db.stripeCustomer.subscription).eq('string');
		});
	});

	describe('sign in', () => {
		afterEach(async () => {
			await removeUsers();
		});

		it('should sign in successfully', async () => {
			const app = await getApplication();

			await getSimpleUser(app, user);
			await signInSuccessfully(app, userForSignin);
		});

		it('should sign in successfully if email or password has spaces before or after word', async () => {
			const userForSignInWithSpaces = {
				email: '    test@test.com    ',
				password: '    testpassword1     ',
			};

			const app = await getApplication();
			await getSimpleUser(app, user);
			await signInSuccessfully(app, userForSignInWithSpaces);
		});

		it('sign in should be successfully if email contains letters with different case', async () => {
			const app = await getApplication();

			await getSimpleUser(app, user);

			const userWithEmailSensivity = {
				...userForSignin,
				email: userForSignin.email.toUpperCase(),
			};
			await signInSuccessfully(app, userWithEmailSensivity);
		});

		it('sign in should fail with wrong password', async () => {
			const app = await getApplication();

			const userResult = await successfullyCreateNewUser(app, user);
			await confirmEmail(app, userResult.db._id);
			await signInFail(app, userForSigninWithWrongPassword, 401);
		});

		it('sign in should fail with wrong space password', async () => {
			const app = await getApplication();

			const userResult = await successfullyCreateNewUser(app, user);
			await confirmEmail(app, userResult.db._id);
			await signInFail(app, userForSigninWithWrongSpacePassword);
		});

		it('sign in should fail with wrong email', async () => {
			const app = await getApplication();

			const userResult = await successfullyCreateNewUser(app, user);
			await confirmEmail(app, userResult.db._id);
			await signInFailBadRequest(app, userForSigninWithWrongEmail);
		});

		it('sign in should fail without email', async () => {
			const app = await getApplication();

			const userResult = await successfullyCreateNewUser(app, user);
			await confirmEmail(app, userResult.db._id);
			await signInFailBadRequest(app, userForSigninWithoutEmail);
		});

		it('sign in should fail without password', async () => {
			const app = await getApplication();

			const userResult = await successfullyCreateNewUser(app, user);
			await confirmEmail(app, userResult.db._id);
			await signInFailBadRequest(app, userForSigninWithoutPassword);
		});

		it('should not sign in if user didn\'t confirm email', async () => {
			const app = await getApplication();
			await successfullyCreateNewUser(app, user);
			await signInFail(app, userForSignin);
		});

	});

	describe('confirmation email', () => {
		afterEach(async () => {
			await removeUsers();
			await removeTokens();
		});

		it('should successfully confirm email', async () => {
			const app = await getApplication();
			const userResult = await successfullyCreateNewUser(app, user);
			await confirmEmail(app, userResult.db._id);
		});

		it('should not use token twice', async () => {
			const app = await getApplication();
			const userResult = await successfullyCreateNewUser(app, user);
			const confirmResult = await confirmEmail(app, userResult.db._id);
			await badConfirmEmail(app, confirmResult.token);
		});

		it('should return token was not found', async () => {
			const app = await getApplication();
			await successfullyCreateNewUser(app, user);
			await badConfirmEmail(app, 'asdfasdfsdlfnsdjfnksdnfksdlnfsd');
		});

		it('should confirm account but not approve', async () => {
			const app = await getApplication();
			const userResult = await successfullyCreateNewUser(app, user);
			const confirmResult = await confirmEmail(app, userResult.db._id);

			expect(confirmResult.db.status).equals('pending');
		});

	});

	describe('forgot password', () => {

		afterEach(async () => {
			await removeUsers();
			await removeTokens();
		});

		it('should successfully send url for reset password', async () => {
			const app = await getApplication();

			const userResult = await successfullyCreateNewUser(app, user);
			await confirmEmail(app, userResult.db._id);
			await sendRequestOnResetPassword(app, userResult.db);
		});

		it('should successfully validate token and redirect to front', async () => {
			const app = await getApplication();

			const userResult = await successfullyCreateNewUser(app, user);
			await confirmEmail(app, userResult.db._id);
			const result = await sendRequestOnResetPassword(app, userResult.db);
			await validateTokenResetPassword(app, result.token.token);
		});

		it('should successfully reset password and set new', async () => {
			const app = await getApplication();

			const userResult = await successfullyCreateNewUser(app, user);
			await confirmEmail(app, userResult.db._id);
			const result = await sendRequestOnResetPassword(app, userResult.db);
			await validateTokenResetPassword(app, result.token.token);
			await resetPassword(app, result.token.token, user);
		});

		it('shouldn\'t allow reset password if email is not confirmed', async () => {
			const app = await getApplication();

			const userResult = await successfullyCreateNewUser(app, user);
			await sendRequestOnResetPasswordForbidden(app, userResult.db);
		});

		it('shouldn\'t reset password if token are invalid', async () => {
			const app = await getApplication();

			const userResult = await successfullyCreateNewUser(app, user);
			await confirmEmail(app, userResult.db._id);
			await sendRequestOnResetPassword(app, userResult.db);

			const invalidToken = Crypto.getSalt(32);
			await validateTokenResetPasswordBad(app, invalidToken);
		});

		it('should not send link if email invalid or doesn\'t exists', async () => {
			const app = await getApplication();

			const userResult = await successfullyCreateNewUser(app, user);
			await confirmEmail(app, userResult.db._id);
			await sendRequestOnResetPasswordBad(app, userWithWrongEmail);
		});

		it('should send bad request if email doesn\'t sent', async () => {
			const app = await getApplication();

			const userResult = await successfullyCreateNewUser(app, user);
			await confirmEmail(app, userResult.db._id);
			await sendRequestOnResetPasswordBad(app, {
				email: undefined,
			});
		});

		it('should be expired', async () => {
			const app = await getApplication();

			const userResult = await successfullyCreateNewUser(app, user);
			await confirmEmail(app, userResult.db._id);
			await sendRequestOnResetPassword(app, userResult.db);

			// create token with expired date
			const now = moment();
			const timeForgotLink = Config.config('security:password:timeForgotLink');

			const token = new Token({
				user: userResult.db,
				token: Crypto.getSalt(50),
				createdAt: now.subtract(timeForgotLink + 10, 'seconds'),
			});
			await token.save();

			await validateTokenResetPasswordBad(app, token.token);
			await resetPasswordBad(app, token.token, user);
		});

		it('should not reset password if token active but not validated', async () => {
			const app = await getApplication();

			const userResult = await successfullyCreateNewUser(app, user);
			await confirmEmail(app, userResult.db._id);
			const result = await sendRequestOnResetPassword(app, userResult.db);
			await resetPasswordBad(app, result.token.token, user);
		});

		it('should not use token twice', async () => {
			const app = await getApplication();

			const userResult = await successfullyCreateNewUser(app, user);
			await confirmEmail(app, userResult.db._id);
			const result = await sendRequestOnResetPassword(app, userResult.db);
			await validateTokenResetPassword(app, result.token.token);
			await resetPassword(app, result.token.token, user);
			await resetPasswordBad(app, result.token.token, user, 'newpassword1');
		});
	});

	describe('change password', () => {
		afterEach(async () => {
			await removeUsers();
			await removeTokens();
		});

		it('should successfully change password', async () => {
			const app = await getApplication();

			const oldPassword = user.password;
			const newPassword = 'newpassword1';

			const simpleUser = await getSimpleUser(app, user);

			await changePassword(app, simpleUser.token, {
				newPassword,
				confirmPassword: newPassword,
				oldPassword,
			});

			await signInFail(app, {
				email: user.email,
				password: oldPassword,
			}, 401);

			await signInSuccessfully(app, {
				email: user.email,
				password: newPassword,
			});
		});

		it('should not change password without auth token', async () => {
			const app = await getApplication();

			const oldPassword = user.password;
			const newPassword = 'newpassword1';

			await getSimpleUser(app, user);

			await changePasswordUnauth(app, {
				newPassword,
				confirmPassword: newPassword,
				oldPassword,
			});

			await signInFail(app, {
				email: user.email,
				password: newPassword,
			}, 401);

			await signInSuccessfully(app, {
				email: user.email,
				password: oldPassword,
			});
		});

		it(`should return error if new password doesn't match criteria password`, async () => {
			const app = await getApplication();

			const oldPassword = user.password;
			const newPassword = 'newpas';

			const simpleUser = await getSimpleUser(app, user);

			await changePasswordBad(app, simpleUser.token, {
				newPassword,
				confirmPassword: newPassword,
				oldPassword,
			});

			await signInFail(app, {
				email: user.email,
				password: newPassword,
			}, 401);

			await signInSuccessfully(app, {
				email: user.email,
				password: oldPassword,
			});
		});

		it('should not change password if missing one of required field', async () => {
			const app = await getApplication();

			const oldPassword = user.password;
			const newPassword = 'newpas';

			const simpleUser = await getSimpleUser(app, user);

			await changePasswordBad(app, simpleUser.token, {
				confirmPassword: newPassword,
				oldPassword,
			});

			await changePasswordBad(app, simpleUser.token, {
				newPassword,
				oldPassword,
			});

			await changePasswordBad(app, simpleUser.token, {
				newPassword,
				confirmPassword: newPassword,
			});

			await signInSuccessfully(app, {
				email: user.email,
				password: oldPassword,
			});
		});

		it(`should not change password if old password doesn't match`, async () => {
			const app = await getApplication();

			const oldPassword = 'somethingelse';
			const newPassword = 'newpassword1';

			const simpleUser = await getSimpleUser(app, user);

			await changePasswordBad(app, simpleUser.token, {
				newPassword,
				confirmPassword: newPassword,
				oldPassword,
			});

			await signInFail(app, {
				email: user.email,
				password: newPassword,
			}, 401);

			await signInSuccessfully(app, {
				email: user.email,
				password: user.password,
			});
		});

		it(`should not change password if new password doesn't match with confirm`, async () => {
			const app = await getApplication();

			const oldPassword = user.password;
			const newPassword = 'newpassword1';

			const simpleUser = await getSimpleUser(app, user);

			await changePasswordBad(app, simpleUser.token, {
				newPassword,
				confirmPassword: 'somethingelse',
				oldPassword,
			});

			await signInFail(app, {
				email: user.email,
				password: newPassword,
			}, 401);

			await signInSuccessfully(app, {
				email: user.email,
				password: oldPassword,
			});
		});
	});
});
