import * as chai from 'chai';

// @ts-ignore
import * as chaiHttp from 'chai-http';
import User from 'app/models/User';
import Token from 'app/models/Token';
import Config from 'Config';
import Crypto from 'Helpers/Crypto';

chai.use(chaiHttp);

const expect = chai.expect;

export const user = {
	email: 'test@test.com',
	phone: '+380968995376',
	password: 'testpassword1',
	firstName: 'testFirstName',
	lastName: 'testLastName'
};

export const userWithNonTrimmedFields = {
	email: 'test@test.com',
	phone: '+380968995376',
	password: 'testpassword1',
	firstName: 'testFirstName ',
	lastName: ' testLastName'
};

export const userWithSpaceInPassword = {
	email: 'test@test.com',
	phone: '+380968995376',
	password: 'test s',
	firstName: 'testFirstName',
	lastName: 'testLastName'
};

export const userWithWrongEmail = {
	email: 'test',
	phone: '+380968995376',
	password: 'testpassword1',
	firstName: 'testFirstName',
	lastName: 'testLastName'
};

export const userWithoutEmail = {
	phone: '+380968995376',
	password: 'testpassword1',
	firstName: 'testFirstName',
	lastName: 'testLastName'
};

export const userWithoutPassword = {
	email: 'test@test.com',
	phone: '+380968995376',
	firstName: 'testFirstName',
	lastName: 'testLastName'
};

export const userWithoutLastName = {
	email: 'test@test.com',
	phone: '+380968995376',
	password: 'testpassword1',
	firstName: 'testFirstName',
};

export const userWithoutFirstName = {
	email: 'test@test.com',
	phone: '+380968995376',
	password: 'testpassword1',
	lastName: 'testLastName',
};

export const userWithoutPhone = {
	email: 'test@test.com',
	password: 'testpassword1',
	firstName: 'testFirstName',
	lastName: 'testLastName'
};

export const userForSignin = {
	email: 'test@test.com',
	password: 'testpassword1',
};

export const userForSigninWithoutEmail = {
	password: 'testpassword1',
};

export const userForSigninWithoutPassword = {
	email: 'test@test.com',
};

export const userForSigninWithWrongPassword = {
	email: 'test@test.com',
	password: 'wrongpassword',
};

export const userForSigninWithWrongSpacePassword = {
	email: 'test@test.com',
	password: 'testpassword1 ',
};

export const userForSigninWithWrongEmail = {
	email: 'wrong@test.com',
	password: 'testpassword1',
};


export const successfullyCreateNewUser = async (app, userPayload, populate = []) => {
	const result = await chai
		.request(app.server)
		.post('/signup')
		.send(userPayload);

	expect(result).to.have.status(201);
	expect(result.body).to.have.property('success').to.equals(true);
	expect(result.body).to.have.property('data').to.have.property('user');
	expect(result.body.data.user).to.have.property('_id');
	expect(result.body.data.user).to.have.property('email').to.equals(userPayload.email.trim());
	expect(result.body.data.user).to.have.property('phone').to.equals(userPayload.phone.trim());

	const userResult = await User.findById(result.body.data.user._id).populate(populate).exec();

	expect(userResult).to.be.an('object');
	expect(userResult).to.have.property('id');
	expect(userResult).to.have.property('email').to.equals(userPayload.email.trim());

	return {
		result: result.body,
		db: userResult,
	};
};

export const badCreateNewUser = async (app, userPayload) => {
	const result = await chai
		.request(app.server)
		.post('/signup')
		.send(userPayload);

	expect(result).to.have.status(400);
	expect(result.body).to.have.property('success').to.equals(false);
	expect(result.body).to.not.have.property('data');

	const userResult = await User.findOne({
		email: userPayload.email,
	});

	expect(userResult).to.be.not.an('object');

	return {
		result: result.body,
		db: userResult,
	};
};

export const conflictCreateNewUser = async (app, userPayload) => {
	const result = await chai
		.request(app.server)
		.post('/signup')
		.send(userPayload);

	expect(result).to.have.status(400);
	expect(result.body).to.have.property('success').to.equals(false);
	expect(result.body).to.not.have.property('data');

	const userResult = await User.find({
		email: userPayload.email,
	});

	expect(userResult).to.be.an('array');
	expect(userResult).to.length(1);

	return {
		result: result.body,
		db: userResult,
	};
};

export const removeUsers = async (users: any[] = []) => {
	if (users.length) {
		const promises = users.map((userTemp) => User.deleteOne({
			_id: userTemp._id,
		}));
		await Promise.all(promises);
	} else {
		await User.deleteMany({
			email: /^test*/
		});
	}
};

export const signInSuccessfully = async (app, userPayload) => {
	const result = await chai
		.request(app.server)
		.post('/signin')
		.send(userPayload);

	expect(result).to.have.status(200);
	expect(result.body).to.have.property('success').to.equals(true);
	expect(result.body).to.have.property('data');
	expect(result.body.data).to.have.property('token');
	expect(result.body.data).to.have.property('user').to.be.an('object');
	expect(result.body.data.user).to.have.property('_id');
	expect(result.body.data.user).to.not.have.property('password');
	expect(result.body.data.user).to.not.have.property('salt');

	const userResult = await User.findOne({
		email: userPayload.email.trim().toLowerCase(),
	});

	expect(userResult).to.be.an('object');
	expect(userResult._id.toString()).equals(result.body.data.user._id);

	return {
		result: result.body,
		db: userResult,
		cookie: result.get('set-cookie')[0],
	};
};

export const signInFail = async (app, userPayload, code = 403) => {
	const result = await chai
		.request(app.server)
		.post('/signin')
		.send(userPayload);

	expect(result).to.have.status(code);
	expect(result.body).to.have.property('success').to.equals(false);
	expect(result.body).to.have.property('error');
	expect(result.body).to.not.have.property('data');
	expect(result.body).to.not.have.property('token');
};

export const signInFailBadRequest = async (app, userPayload) => {
	const result = await chai
		.request(app.server)
		.post('/signin')
		.send(userPayload);

	expect(result).to.have.status(400);
	expect(result.body).to.have.property('success').to.equals(false);
	expect(result.body).to.have.property('error');
	expect(result.body).to.not.have.property('data');
	expect(result.body).to.not.have.property('token');
};

export const removeTokens = async () => {
	await Token.deleteMany({});
};

export const getTokenByIdUser = async (app, idUser) => {
	return  await Token.findOne({
		user: idUser,
	});
};

export const getTokenByValue = async (app, tokenValue) => {
	return await Token.findOne({
		token: tokenValue,
	});
};

export const confirmEmail = async (app, idUser, tokenUsed?) => {
	let token;

	if (!tokenUsed) {
		const tokenResult = await getTokenByIdUser(app, idUser);
		token = tokenResult.token;
	} else {
		token = tokenUsed;
	}

	const userRaw = await User.findById(idUser);

	expect(userRaw.emailConfirmed).equals(false);

	const result = await chai
		.request(app.server)
		.get('/email/confirm/' + token);

	expect(result).to.have.status(404);

	const updatedUser = await User.findById(idUser);
	expect(updatedUser).to.be.an('object');
	expect(updatedUser.emailConfirmed).equals(true);

	const updatedToken = await getTokenByIdUser(app, idUser);

	expect(updatedToken.active).equals(false);

	return {
		result: result.body,
		db: updatedUser,
		token,
	};
};

export const badConfirmEmail = async (app, token) => {
	const result = await chai
		.request(app.server)
		.get('/email/confirm/' + token);

	expect(result).to.have.status(404);
	expect(result.body).to.not.have.property('data');
};

export const sendRequestOnResetPassword = async (app, rawUser) => {
	const result = await chai
		.request(app.server)
		.post('/password/forgot')
		.send({
			email: rawUser.email,
		});

	expect(result).to.have.status(200);
	expect(result.body).to.have.property('success').to.equals(true);

	const token = await Token.find();

	expect(token).to.be.an('array').length(2);

	return {
		result: result.body,
		token: token[1],
	};
};

export const sendRequestOnResetPasswordBad = async (app, rawUser) => {
	const result = await chai
		.request(app.server)
		.post('/password/forgot')
		.send({
			email: rawUser.email,
		});

	expect(result).to.have.status(400);
	expect(result.body).to.have.property('success').to.equals(false);

	const token = await Token.find();

	expect(token).to.be.an('array').length(1);

	return {
		result: result.body,
	};
};

export const sendRequestOnResetPasswordForbidden = async (app, rawUser) => {
	const result = await chai
		.request(app.server)
		.post('/password/forgot')
		.send({
			email: rawUser.email,
		});

	expect(result).to.have.status(403);
	expect(result.body).to.have.property('success').to.equals(false);

	const token = await Token.find();

	expect(token).to.be.an('array').length(1);

	return {
		result: result.body,
	};
};

export const validateTokenResetPassword = async (app, token) => {
	const tokenBefore = await Token.findOne({
		token,
	});

	expect(tokenBefore.validated).equals(false);

	const result = await chai
		.request(app.server)
		.get('/password/validate/' + token);

	const frontUrl = Config.env('frontUrl', 'http://localhost');
	const redirectUrl = frontUrl + '/password/reset/' + token;
	expect(result).redirectTo(redirectUrl);

	const tokenAfter = await Token.findOne({
		token,
	});

	expect(tokenAfter.validated).equals(true);
};

export const validateTokenResetPasswordBad = async (app, token) => {
	const tokenBefore = await Token.findOne({
		token,
	});

	if (tokenBefore) {
		expect(tokenBefore.validated).equals(false);
	}

	const result = await chai
		.request(app.server)
		.get('/password/validate/' + token);

	const frontUrl = Config.env('frontUrl', 'http://localhost');
	const redirectUrl = frontUrl + '/error';
	expect(result).redirectTo(redirectUrl);

	const tokenAfter = await Token.findOne({
		token,
	});

	if (tokenAfter) {
		expect(tokenAfter.validated).equals(false);
	}
};

export const resetPassword = async (app, token, rawUser) => {
	const userBefore = await User.findOne({
		email: rawUser.email,
	});

	expect(Crypto.verifyHash(rawUser.password, userBefore.password, userBefore.salt)).equals(true);

	const tokenBefore = await Token.findOne({
		token,
	});

	expect(tokenBefore.validated).equals(true);
	expect(tokenBefore.active).equals(true);

	const newPassword = 'newpassword1';

	const result = await chai
		.request(app.server)
		.post('/password/reset/' + token)
		.send({
			newPassword,
			confirmNewPassword: newPassword,
		});

	expect(result).to.have.status(200);
	expect(result.body).to.have.property('success').to.equals(true);

	const userAfter = await User.findOne({
		email: rawUser.email,
	});

	expect(Crypto.verifyHash(newPassword, userAfter.password, userAfter.salt)).equals(true);

	const tokenAfter = await Token.findOne({
		token,
	});

	expect(tokenAfter.validated).equals(true);
	expect(tokenAfter.active).equals(false);
};

export const resetPasswordBad = async (app, token, rawUser, password?) => {
	const userBefore = await User.findOne({
		email: rawUser.email,
	});

	if (password) {
		expect(Crypto.verifyHash(password, userBefore.password, userBefore.salt)).equals(true);
	} else {
		expect(Crypto.verifyHash(rawUser.password, userBefore.password, userBefore.salt)).equals(true);
	}

	const newPassword = 'newpassword2';

	const result = await chai
		.request(app.server)
		.post('/password/reset/' + token)
		.send({
			newPassword,
			confirmNewPassword: newPassword,
		});

	expect(result).to.have.status(400);
	expect(result.body).to.have.property('success').to.equals(false);

	const userAfter = await User.findOne({
		email: rawUser.email,
	});

	expect(Crypto.verifyHash(newPassword, userAfter.password, userAfter.salt)).equals(false);
};

export const makeUserActive = async (rawUser, status: string = 'approved', subscription, extra) => {
	rawUser = await User.findById(rawUser._id).populate('stripeCustomer');

	rawUser.status = status;
	rawUser.emailConfirmed = true;
	rawUser.stripeCustomer.credits = {
		subscription,
		extra,
	};

	const [ updatedUser ] = await Promise.all([rawUser.save(), rawUser.stripeCustomer.save()]);
	return updatedUser;
};

export const getSimpleUser = async (
	app,
	userPayload: any[] | {},
	status: string = 'approved',
	subscription = 10,
	extra = 10,
) => {
	let result;

	if (!Array.isArray(userPayload)) {
		const createdUser = await successfullyCreateNewUser(app, userPayload);
		result = await makeUserActive(createdUser.db, status, subscription, extra);
		const signinResult = await signInSuccessfully(app, userPayload);
		result.token = signinResult.result.data.token;
		result.cookie = signinResult.cookie;
	} else {
		const users = userPayload as [];

		const promises = users.map( async (userTemp) => {
			const createdUser = await successfullyCreateNewUser(app, userTemp);
			const tempResult = await makeUserActive(createdUser.db, status, subscription, extra) as any;
			const signinResult = await signInSuccessfully(app, userTemp);
			tempResult.token = signinResult.result.data.token;
			tempResult.cookie = signinResult.cookie;

			return tempResult;
		});

		result = await Promise.all(promises);
	}

	return result;
};

export const changePassword = async (app, token, payload) => {
	const result = await chai
		.request(app.server)
		.post('/password/change')
		.send(payload)
		.set('Authorization', 'Bearer ' + token);

	expect(result).status(200);
	expect(result.body).property('success').eq(true);

	return result.body;
};

export const changePasswordBad = async (app, token, payload) => {
	const result = await chai
		.request(app.server)
		.post('/password/change')
		.send(payload)
		.set('Authorization', 'Bearer ' + token);

	expect(result).status(400);
	expect(result.body).property('success').eq(false);

	return result.body;
};

export const changePasswordUnauth = async (app, payload) => {
	const result = await chai
		.request(app.server)
		.post('/password/change')
		.send(payload);

	expect(result).status(401);
	expect(result.body).property('success').eq(false);

	return result.body;
};
