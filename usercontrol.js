// author: saibotsivad
// url: https://github.com/saibotsivad/usercontrol
// description: Mildly opinionated dnode compliant user authentication, using leveldb.

'use strict'

var hash    = require('password-hash')
  , atomic  = require('level-atomic')
  , emitter = new (require('events').EventEmitter)
  , uuid    = require('./uuid-wrapper.js')

var db
var log
var fields
var min_password_length
var min_username_length
var email_required
var token_expiration_hours
var reset_token_expiration_hours
var require_password_with_reset_authentication

var is_valid_url = function(url) {
	return (typeof url == 'string' || url instanceof String) && url.lastIndexOf('http', 0) === 0
}

var emit = function(action, cb) {
	emitter.on(action, cb)
}

var give = function(method, message, data) {
	log(method, message, data)
	emitter.emit(method, {
		message: message,
		data: data
	})
}

var generate_token = function(expiration_offset) {
	var token = {
		id: uuid.generate(),
		expires: new Date()
	}
	token.expires.setUTCHours(token.expires.getUTCHours() + expiration_offset)
	return token
}

/**
 * =========
 * The rest of these are dnode compliant functions, and are
 * what is exported in the module.
 * =========
*/

// returns only the username
var is_user = function(input, cb) {
	var key = (input.user && input.user.username) || undefined
	if (typeof key !== 'string') {
		give('is_user', 'username invalid', input)
		cb({ err: { invalidUsername: true } })
	} else {
		db.get(key, function(err, data) {
			if (err) {
				give('is_user', 'username not found', input)
				cb({ err: { userNotFound: true } })
			} else {
				give('is_user', 'username found', input)
				cb({ user: { username: key } })
			}
		})
	}
}

// When a user is created, a session token is created and handed back
var create_user = function(input, cb) {
	var username = (input.fields && input.fields.username) || undefined
	var password = (input.fields && input.fields.password) || undefined
	var email    = (input.fields && input.fields.email)    || undefined

	if (!password || password.length < min_password_length) {
		give('create_user', 'password invalid', input)
		cb({ err: { badPassword: true } })
	} else if (!username || !email) {
		give('create_user', 'username or email invalid', input)
		cb({ err: { badUsernameOrEmail: true } })
	} else {
		db.lock(username, function(atomic_db, done) {
			atomic_db.get(username, function(user_not_found) {
				if (user_not_found) {
					var new_user = {
						created: new Date(),
						username: username,
						password_hash: hash.generate(password),
						emails: {},
						session: {}
					}

					new_user.emails[email] = {
						email: email,
						verified: false
					}

					var token = generate_token(token_expiration_hours)
					new_user.session[token.id] = token

					atomic_db.put(username, new_user, function(err) {
						done()
						give('create_user', 'user created', input)
						cb({
							user: {
								token: token,
								username: username,
								emails: new_user.emails
							}
						})
					})
				} else {
					done()
					give('create_user', 'user already exists', input)
					cb({ err: { userExists: true } })
				}
			})
		})
	}
}

// Given a session token and username, see if that session token is valid. If so, return the user data.
var is_user_authenticated = function(input, cb) {
	var username = (input.user && input.user.username) || null
	var token    = (input.user && input.user.token)    || null
	if (!username || !uuid.isValid(token)) {
		give('is_user_authenticated', 'username or token invalid', input)
		cb({ err: { authentication: true } })
	} else {
		db.get(username, function(err, data) {
			if (err) {
				give('is_user_authenticated', 'user authentication failed', input)
				cb({ err: true })
			} else {
				if (data.session === undefined || data.session[token] === undefined || new Date(data.session[token]) < new Date()) {
					give('is_user_authenticated', 'invalid or expired session', input)
					cb({ err: true })
				} else {
					give('is_user_authenticated', 'user authenticated', input)
					cb ({
						user: {
							username: data.username,
							token: data.session[token],
							emails: data.emails,
							fields: data.fields
						}
					})
				}
			}
		})
	}
}

// Given a user's password, generate and store a session token and return user data.
var authenticate_user = function(input, cb) {
	var username = (input.user && input.user.username) || undefined
	var password = (input.user && input.user.password) || undefined
	if (!password || !username) {
		give('authenticate_user', 'invalid username or token', input)
		cb({ err: { authentication: true } })
	} else {
		db.lock(username, function(atomic_db, done) {
			atomic_db.get(username, function(user_not_found, data) {
				if (user_not_found) {
					done()
					give('authenticate_user', 'user not found', input)
					cb({ err: true })
				} else if (hash.verify(password, data.password_hash)) {
					if (!data.session) {
						data.session = {}
					}
					var token = generate_token(token_expiration_hours)
					data.session[token.id] = token
					atomic_db.put(username, data, function(err) {
						done()
						give('authenticate_user', 'user logged in', input)
						cb({
							user: {
								username: data.username,
								token: token,
								emails: data.emails,
								fields: data.fields
							}
						})
					})
				} else {
					done()
					give('invalidate_session', 'bad password', input)
					cb({ err: true })
				}
			})
		})
	}
}

// Given a username and session token, delete that token from the database.
var invalidate_session = function(input, cb) {
	var username = (input.user && input.user.username) || undefined
	var token    = (input.user && input.user.token)    || undefined
	if (!username || !uuid.isValid(token)) {
		give('invalidate_session', 'invalid username or token', input)
		cb({ err: { authentication: true } })
	} else {
		db.lock(username, function(atomic_db, done) {
			atomic_db.get(username, function(user_not_found, data) {
				if (user_not_found) {
					done()
					give('invalidate_session', 'user not found', input)
					cb({ err: { userNotFound: true }})
				} else {
					delete data.session[token]
					atomic_db.put(username, data, function(err) {
						done()
						give('invalidate_session', 'logging out user', input)
						cb({ user: null })
					})
				}
			})
		})
	}
}

// Given a username, session token, and new password, reset the password for the user.
var set_password = function(input, cb) {
	var username = (input.user && input.user.username) || undefined
	var token    = (input.user && input.user.token)    || undefined
	var password = (input.fields && input.fields.password) || undefined
	if (!token || !username || !password || !uuid.isValid(token)) {
		give('set_password', 'invalid username or password or token', input)
		cb({ err: { authentication: true } })
	} else if (password.length < min_password_length) {
		give('set_password', 'invalid password length', input)
		cb({ err: { passwordLength: min_password_length } })
	} else {
		db.lock(username, function(atomic_db, done) {
			atomic_db.get(username, function(err, data) {
				if (err) {
					done()
					give('set_password', 'username not found', input)
					cb({ err: true })
				} else if (!(new Date(data.session[token])) > new Date()) {
					done()
					give('set_password', 'session token expired', input)
					cb({ err: true })
				} else {
					data.password_hash = hash.generate(password)
					atomic_db.put(username, data, function(err) {
						done()
						give('set_password', 'password reset', input)
						cb({
							user: {
								username: data.username,
								token: token,
								emails: data.emails,
								fields: data.fields
							}
						})
					})
				}
			})

		})
	}
}

// Given a username, session token, and new username, change the username for the user.
var set_username = function(input, cb) {
	var old_username = (input.user && user.username)    || undefined
	var token        = (input.user && input.user.token) || undefined
	var new_username = (input.fields && input.fields.username) || undefined
	if (!old_username || !new_username || !token || !uuid.isValid(token)) {
		give('set_username', 'username or token bad', input)
		cb({ err: { authentication: true } })
	} else if (new_username.length < min_username_length) {
		give('set_username', 'username too short', input)
		cb({ err: { badUsername: true } })
	} else {

		db.lock(new_username, function(atomic_new, new_done) {
			db.lock(old_username, function(atomic_old, old_done) {

				atomic_new.get(new_username, function(user_does_not_exist) {
					if (user_does_not_exist) {

						atomic_old.get(old_username, function(err, old_user_data) {
							if (err || new Date(old_user_data.session[token]) < new Date()) {
								old_done()
								new_done()
								give('set_username', 'authentication failure', input)
								cb({ err: { loggedOut: true } })
							} else {

								atomic_new.put(new_username, old_user_data, function(err) {
									if (err) {
										old_done()
										new_done()
										give('set_username', 'user already exists', input)
										cb({ err: { userExists: true } })
									} else {
										atomic_old.del(old_username, function() {
											old_done()
											new_done()
											old_user_data.username = new_username
											give('set_username', 'username changed', input)
											cb({
												user: {
													username: new_username,
													token: token,
													emails: old_user_data.emails,
													fields: old_user_data.fields
												}
											})
										})
									}
								})

							}
						})
					} else {
						old_done()
						new_done()
						give('set_username', 'old user not found', input)
						cb({ err: { userExists: true } })
					}
				})
			})
		})
	}
}

// given username, generate token which is not handed back to client (typically sent via email)
var create_reset_token = function(input, cb) {
	var username = (input.user && input.user.username) || undefined
	if (!username) {
		give('create_reset_token', 'invalid username', input)
		cb({ err: { invalidUser: true } })
	} else {
		db.lock(username, function(atomic_db, done) {
			atomic_db.get(username, function(user_not_found, data) {
				if (user_not_found) {
					done()
					give('create_reset_token', 'user not found', input)
					cb({ user: true })
				} else {
					data.resetToken = generate_token(reset_token_expiration_hours)
					atomic_db.put(username, data, function(err) {
						done()
						give('create_reset_token', 'token generated', data)
						cb({ user: true })
					})
				}
			})
		})
	}
}

var authenticate_using_reset_token = function(input, cb) {
	var username = (input.user && input.user.username)   || undefined
	var password = (input.user && input.fields.password) || undefined
	var resetToken    = (input.user && input.user.resetToken) || undefined
	if (!username || !resetToken || (!password && require_password_with_reset_authentication)) {
		give('authenticate_using_reset_token', 'invalid username or token', input)
		cb({ err: { authentication: true } })
	} else {
		db.lock(username, function(atomic_db, done) {
			atomic_db.get(username, function(user_not_found, data) {
				if (user_not_found) {
					done()
					give('authenticate_using_reset_token', 'user not found', input)
					cb({ err: true })
				} else if (data.resetToken && data.resetToken.id === resetToken && new Date(data.resetToken.expires) > new Date()) {
					if (require_password_with_reset_authentication) {
						data.password_hash = hash.generate(password)
					}
					if (!data.session) {
						data.session = {}
					}
					var token = generate_token(token_expiration_hours)
					data.session[token.id] = token
					delete data['resetToken']
					atomic_db.put(username, data, function(err) {
						done()
						give('authenticate_using_reset_token', 'user logged in', input)
						cb({
							user: {
								username: data.username,
								token: token,
								emails: data.emails,
								fields: data.fields
							}
						})
					})
				} else {
					done()
					give('authenticate_using_reset_token', 'token expired', resetToken)
					cb({ err: true })
				}
			})
		})
	}
}

module.exports = function(opts) {
	db = atomic(opts.db)
	fields = opts.fields || {}
	min_password_length = opts.minPasswordLength || 4
	min_username_length = opts.minUsernameLength || 4
	email_required = opts.emailRequired || true
	token_expiration_hours = opts.tokenExpirationHours || 720
	reset_token_expiration_hours = opts.resetTokenExpirationHours || 24
	require_password_with_reset_authentication = opts.requirePasswordWithResetAuthentication || true
	log = opts.logging || function() {}

	return {
		on: emit,
		isUser: is_user,
		createUser: create_user,
		isUserAuthenticated: is_user_authenticated,
		authenticateUser: authenticate_user,
		invalidateSession: invalidate_session,
		setPassword: set_password,
		createResetToken: create_reset_token,
		authenticateUsingResetToken: authenticate_using_reset_token
	}
}