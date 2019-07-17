import { Schema, Document } from 'mongoose';
// core
import MongooseModel from 'Model/MongooseModel';
// enums
import { businessType, industry, state, userStatus } from 'app/libs/enums';
// types
import { IStripeCustomer } from 'app/models/StripeCustomer';
import { Models } from 'herheadquarters';

export interface IUser extends Models.User.IUser, Document {
	stripeCustomer?: IStripeCustomer;
}

class User extends MongooseModel<IUser> {
	public name: string = 'User';

	public initSchema(): Schema {
		const schema = new Schema({
			email: {
				type: Schema.Types.String,
				required: true,
				unique: true,
			},
			phone: {
				type: Schema.Types.String,
				unique: true,
			},
			password: {
				type: Schema.Types.String,
				required: true,
			},
			salt: {
				type: Schema.Types.String,
				required: true,
			},
			firstName: {
				type: Schema.Types.String,
				required: true,
			},
			lastName: {
				type: Schema.Types.String,
				required: true,
			},
			companyWebsite: {
				type: Schema.Types.String,
			},
			companyName: {
				type: Schema.Types.String,
			},
			avatar: {
				type: Schema.Types.ObjectId,
				ref: 'File',
			},
			city: {
				type: Schema.Types.String,
			},
			state: {
				type: Schema.Types.String,
				enum: state,
			},
			socialLinks: {
				twitter: {
					type: Schema.Types.String,
				},
				instagram: {
					type: Schema.Types.String,
				},
				facebook: {
					type: Schema.Types.String,
				},
			},
			yearsInBusiness: {
				type: Schema.Types.Number,
			},
			industry: {
				type: Schema.Types.String,
				enum: industry,
			},
			businessType: {
				type: Schema.Types.String,
				enum: businessType,
			},
			about: {
				type: Schema.Types.String,
			},
			seeking: {
				type: Schema.Types.String,
			},
			portfolio: [{
				type: Schema.Types.ObjectId,
				ref: 'File',
			}],
			collaborations: [{
				type: Schema.Types.ObjectId,
				ref: 'Collaboration',
			}],
			favorites: {
				profiles: [{
					type: Schema.Types.ObjectId,
					ref: this.name,
				}],
				collaborations: [{
					type: Schema.Types.ObjectId,
					ref: 'Collaboration',
				}],
			},
			isAdmin: {
				type: Schema.Types.Boolean,
				default: false,
			},
			emailConfirmed: {
				type: Schema.Types.Boolean,
				default: false,
			},
			status: {
				type: Schema.Types.String,
				enum: userStatus,
				default: 'pending',
			},
			stripeCustomer: {
				type: Schema.Types.ObjectId,
				ref: 'StripeCustomer',
			},
			notification: {
				email: {
					messages: {
						type: Schema.Types.Boolean,
						default: true,
					},
					newRequests: {
						type: Schema.Types.Boolean,
						default: true,
					},
					changedRequests: {
						type: Schema.Types.Boolean,
						default: true,
					},
					removedCollaboration: {
						type: Schema.Types.Boolean,
						default: true,
					}
				},
				push: {
					messages: {
						type: Schema.Types.Boolean,
						default: true,
					},
					newRequests: {
						type: Schema.Types.Boolean,
						default: true,
					},
					changedRequests: {
						type: Schema.Types.Boolean,
						default: true,
					},
					removedCollaboration: {
						type: Schema.Types.Boolean,
						default: true,
					}
				}
			},
			tokens: [{
				type: Schema.Types.String,
			}],
			rating: {
				total: {
					type: Schema.Types.Number,
					default: 0,
					min: [0, 'Rating should be in range from 0 to 5'],
					max: [5, 'Rating should be in range from 0 to 5'],
				},
				communication: {
					type: Schema.Types.Number,
					default: 0,
				},
				deadlinesMet: {
					type: Schema.Types.Number,
					default: 0,
				},
				brandValue: {
					type: Schema.Types.Number,
					default: 0,
				},
				fulfilledObligations: {
					type: Schema.Types.Number,
					default: 0,
				},
				overallExperience: {
					type: Schema.Types.Number,
					default: 0,
				},
			},
			reviews: [{
				type: Schema.Types.ObjectId,
				ref: 'Review',
			}],
		}, {
			timestamps: true
		});

		schema.index({
			'$**': 'text',
		});

		return schema;
	}

	public initJsonSchema(): object[] | object {
		return [
			{
				$id: 'notificationSettings',
				type: 'object',
				properties: {
					push: {
						type: 'object',
						properties: {
							messages: { type: 'boolean' },
							newRequests: { type: 'boolean' },
							changedRequests: { type: 'boolean' },
							removedCollaboration: { type: 'boolean' },
						},
					},
					email: {
						type: 'object',
						properties: {
							messages: { type: 'boolean' },
							newRequests: { type: 'boolean' },
							changedRequests: { type: 'boolean' },
							removedCollaboration: { type: 'boolean' },
						},
					},
				},
			},
			{
				$id: 'user',
				type: ['object', 'string', 'null'],
				properties: {
					_id: { type: 'string' },
					email: {
						type: 'string',
						format: 'email',
					},
					phone: { type: 'string' },
					firstName: { type: 'string' },
					lastName: { type: 'string' },
					companyWebsite: { type: 'string' },
					companyName: { type: 'string' },
					avatar: 'file#',
					city: { type: 'string' },
					state: { type: 'string' },
					socialLinks: 'socialLinks#',
					yearsInBusiness: { type: 'string' },
					industry: { type: 'string' },
					businessType: { type: 'string' },
					about: { type: 'string' },
					seeking: { type: 'string' },
					isAdmin: { type: 'boolean' },
					emailConfirmed: { type: 'boolean' },
					status: { type: 'string' },
					rating: 'criterias#',
					reviews: {
						type: 'array',
						items: 'review#',
					},
					createdAt: { type: 'string' },
					updatedAt: { type: 'string' },
					portfolio: {
						type: 'array',
						items: 'file#',
					},
					collaborations: {
						type: 'array',
						items: 'favoriteCollaboration#'
					},
					favorites: {
						type: 'object',
						properties: {
							profiles: {
								type: 'array',
								items: 'favoriteUser#',
							},
							collaborations: {
								type: 'array',
								items: 'favoriteCollaboration#',
							},
						},
					},
					notification: 'notificationSettings#',
					stripeCustomer: 'stripeCustomer#',
				},
				additionalProperties: false,
			},
			{
				$id: 'chatUser',
				type: ['object', 'string', 'null'],
				properties: {
					_id: { type: 'string' },
					email: {
						type: 'string',
						format: 'email',
					},
					firstName: { type: 'string' },
					lastName: { type: 'string' },
					avatar: 'file#',
					createdAt: { type: 'string' },
					updatedAt: { type: 'string' },
				},
			},
			{
				$id: 'lightUser',
				type: ['object', 'string', 'null'],
				properties: {
					_id: { type: 'string' },
					email: {
						type: 'string',
						format: 'email',
					},
					phone: { type: 'string' },
					firstName: { type: 'string' },
					lastName: { type: 'string' },
					companyName: { type: 'string' },
					avatar: 'file#',
					city: { type: 'string' },
					state: { type: 'string' },
					industry: { type: 'string' },
					createdAt: { type: 'string' },
					updatedAt: { type: 'string' },
				},
				additionalProperties: false,
			},
			{
				$id: 'favoriteUser',
				type: ['object', 'string', 'null'],
				properties: {
					_id: { type: 'string' },
					email: {
						type: 'string',
						format: 'email',
					},
					phone: { type: 'string' },
					firstName: { type: 'string' },
					lastName: { type: 'string' },
					companyWebsite: { type: 'string' },
					companyName: { type: 'string' },
					avatar: 'file#',
					city: { type: 'string' },
					state: { type: 'string' },
					socialLinks: 'socialLinks#',
					yearsInBusiness: { type: 'number' },
					industry: { type: 'string' },
					businessType: { type: 'string' },
					createdAt: { type: 'string' },
					updatedAt: { type: 'string' },
				},
				additionalProperties: false,
			},
			{
				$id: 'safeUser',
				type: ['object', 'string', 'null'],
				properties: {
					phone: { type: 'string' },
					firstName: { type: 'string' },
					lastName: { type: 'string' },
					companyWebsite: { type: 'string' },
					companyName: { type: 'string' },
					city: { type: 'string' },
					state: { type: 'string' },
					socialLinks: 'socialLinks#',
					yearsInBusiness: { type: 'number' },
					industry: { type: 'string' },
					businessType: { type: 'string' },
					about: { type: 'string' },
					seeking: { type: 'string' },
					notification: 'notificationSettings#',
				},
				additionalProperties: false,
			},
			{
				$id: 'socialLinks',
				type: 'object',
				properties: {
					twitter: { type: 'string' },
					instagram: { type: 'string' },
					facebook: { type: 'string' },
				},
				additionalProperties: false
			},
			{
				$id: 'messageUser',
				type: ['object', 'string', 'null'],
				properties: {
					_id: { type: 'string' },
					email: { type: 'string' },
					avatar: 'file#',
					firstName: { type: 'string' },
					lastName: { type: 'string' },
				},
				additionalProperties: false,
			}
		];
	}
}

export default new User().getModel();
