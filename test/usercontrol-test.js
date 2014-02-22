'use strict'

var test  = require('tap').test
  , level = require('level-mem')
  , uuid  = require('../uuid-wrapper.js')
  , users = require('../usercontrol.js')

test('correctly creating a user returns user data', function(t) {
	var user_db  = level('test_users', { valueEncoding: 'json' })
	var api = users({ db: user_db })

	var input = { fields: {
		username: 'bob',
		email: 'bob@bob.com',
		password: 'abc123qwe'
	}}

	api.createUser(input, function(data) {
		t.notOk(data.err, 'should not generate an error')
		t.ok(data.user, 'should hand back the user object')
		t.ok(data.user.token, 'should hand back a token')
		t.ok(uuid.isValid(data.user.token.id), 'should hand back token as valid uuid')
		t.ok(data.user.emails, 'should hand back a list of emails')
		t.ok(data.user.emails[input.fields.email].email === input.fields.email, 'should hand back correct email')
		t.ok(Object.keys(data.user.emails).length === 1, 'should hand only the one email')
		t.end()
	})
})

test('creating a user without username returns error', function(t) {
	var user_db  = level('test_users', { valueEncoding: 'json' })
	var api = users({ db: user_db })

	var user = { fields: {
		// username: 'bob', // no username: not allowed
		email: 'bob@bob.com',
		password: 'abc123'
	}}

	api.createUser(user, function(data) {
		t.ok(data.err, 'should generate an error')
		t.ok(data.err.badUsernameOrEmail, 'should generate specific error')
		t.end()
	})
})

test('creating a user without email returns error', function(t) {
	var user_db  = level('test_users', { valueEncoding: 'json' })
	var api = users({ db: user_db })

	var user = { fields: {
		username: 'bob',
		// email: 'bob@bob.com', // no email: not allowed
		password: 'abc123'
	}}

	api.createUser(user, function(data) {
		t.ok(data.err, 'should generate an error')
		t.ok(data.err.badUsernameOrEmail, 'should generate specific error')
		t.end()
	})
})

test('creating a user with bad password returns error', function(t) {
	var user_db  = level('test_users', { valueEncoding: 'json' })
	var api = users({ db: user_db })

	var user = { fields: {
		username: 'bob',
		email: 'bob@bob.com'
		// password: 'abc123' // no password: not allowed
	}}

	api.createUser(user, function(data) {
		t.ok(data.err, 'should generate an error')
		t.ok(data.err.badPassword, 'should generate specific error')
		t.end()
	})
})

test('non-existant user will not exist', function(t) {
	var user_db  = level('test_users', { valueEncoding: 'json' })
	var api = users({ db: user_db })

	var user = { user: {
		username: 'bob'
	}}

	api.isUser(user, function(data) {
		t.ok(data.err, 'the error flag should be thrown')
		t.ok(data.err.userNotFound, 'the user should not exist yet')
		t.end()
	})
})

test('creating a user of the same id will create an error', function(t) {
	var user_db  = level('test_users', { valueEncoding: 'json' })
	var api = users({ db: user_db })

	var user = {
		fields: {
			username: 'bob',
			email: 'bob@bob.com',
			password: 'abc123'
		}
	}

	api.createUser(user, function(data) {
		t.notOk(data.err, 'creating a user should not generate errors')
		api.createUser(user, function(data) {
			t.ok(data.err, 'creating a user with the same id is an error')
			t.ok(data.err.userExists, 'should return specific error')
			t.end()
		})
	})
})

test('a user will not be authenticated if they do not exist', function(t) {
	var user_db  = level('test_users', { valueEncoding: 'json' })
	var api = users({ db: user_db })

	var user = { user: {
		username: 'bob'
	}}

	api.isUserAuthenticated(user, function(data) {
		t.ok(data.err, 'the user does not exist and should not be authenticated')
		t.end()
	})
})

test('a user is authenticated if they pass the appropriate password', function(t) {
	var user_db  = level('test_users', { valueEncoding: 'json' })
	var api = users({ db: user_db })

	var create_user = {
		fields: {
			username: 'bobbob',
			email: 'bob@bob.com',
			password: 'totes a secret'
		}
	}

	var fake_user = {
		user: {
			username: 'bobbob',
			password: 'l33t h4x0r5'
		}
	}

	var real_user = {
		user: {
			username: 'bobbob',
			password: 'totes a secret'
		}
	}

	api.createUser(create_user, function(d) {
		api.authenticateUser(fake_user, function(bad_data) {
			t.ok(bad_data.err, 'fake password should generate an error')
			api.authenticateUser(real_user, function(data) {
				t.notOk(data.err, 'correct password should authenticate')
				t.ok(uuid.isValid(data.user.token.id), 'session token should be in the form of a uuid')
				t.end()
			})
		})
	})
})

test('generate reset token', function(t) {
	var user_db  = level('test_users', { valueEncoding: 'json' })
	var api = users({ db: user_db })

	api.on('create_reset_token', function(out) {
		t.ok(out.data, 'should get back a data packet')
		t.ok(out.data.username, 'should include username')
		t.ok(out.data.emails, 'should include email list')
		t.ok(out.data.resetToken, 'should include reset token')
		t.ok(out.data.resetToken.id, 'token should have id')
		t.ok(uuid.isValid(out.data.resetToken.id), 'token id should be a uuid')
		t.ok(out.data.resetToken.expires, 'token should expire')
		t.ok(new Date(out.data.resetToken.expires) > new Date(), 'token should expire in the future')
		t.end()
	})

	var user = { fields: {
		email: 'name@email.com',
		username: 'uniquename',
		password: 'secret phrase'
	}}

	api.createUser(user, function(data) {
		t.notOk(data.err, 'creating a user should not generate errors')
		var reset_user = { user: { username: 'uniquename' }}
		api.createResetToken(reset_user, function(data) {
			t.notOk(data.err, 'resetting the password should not generate errors')
			t.ok(data.user === true, 'generating a reset token should only give a boolean')
		})
	})

})

test('reset password using reset token', function(t) {
	var user_db  = level('test_users', { valueEncoding: 'json' })
	var api = users({ db: user_db })

	api.on('create_reset_token', function(out) {
		var reset_user = {
			user: {
				username: out.data.username,
				resetToken: out.data.resetToken.id
			},
			fields: {
				password: 'mynewpassword'
			}
		}
		api.authenticateUsingResetToken(reset_user, function(data) {
			t.notOk(data.err, 'logging in with a reset token')
			t.ok(data.user, 'should return user data')
			t.ok(data.user.token, 'should return a token')
			t.notOk(data.user.token.id === reset_user.user.resetToken, 'should return a session token different than reset token')
			api.authenticateUsingResetToken(reset_user, function(data) {
				t.ok(data.err, 'using reset token twice should give an error')
				t.end()
			})
		})
	})

	var user = { fields: {
		email: 'name@email.com',
		username: 'bobbob',
		password: 'secret phrase'
	}}

	api.createUser(user, function() {
		var reset_user = { user: { username: 'bobbob' } }
		api.createResetToken(reset_user, function(data) {
			t.notOk(data.err, 'resetting the password should not generate errors')
			t.ok(data.user === true, 'generating a reset token should only give a boolean')
		})
	})

})
