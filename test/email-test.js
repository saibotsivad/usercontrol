'use strict'

var test  = require('tap').test
  , level = require('level-mem')
  , uuid  = require('../uuid-wrapper.js')
  , users = require('../usercontrol.js')

test('creating a user emits an email verify token', function(t) {
	t.plan(5)
	var user_db  = level('test_users', { valueEncoding: 'json' })
	var api = users({ db: user_db })

	var input = { fields: {
		username: 'bob',
		email: 'bob@bob.com',
		password: 'abc123qwe'
	}}

	api.on('create_user', function(out) {
		t.ok(out.data.verify, 'the verifyEmail should exist')
		t.ok(out.data.verify['bob@bob.com'], 'the verifyEmail should match to the email')
		t.ok(uuid.isValid(out.data.verify['bob@bob.com'].id), 'the verifyEmail should give a token')
		t.ok(new Date(out.data.verify['bob@bob.com'].expires) > new Date(), 'the token expiration should be in the future')
	})

	api.createUser(input, function(data) {
		t.notOk(data.err, 'should not generate an error')
	})
})

test('adding an email emits a verify token', function(t) {
	t.plan(6)
	var user_db  = level('test_users', { valueEncoding: 'json' })
	var api = users({ db: user_db })

	var input = { fields: {
		username: 'bob',
		email: 'bob@bob.com',
		password: 'abc123qwe'
	}}

	api.on('add_email', function(out) {
		t.ok(out.data.verify, 'the verifyEmail should exist')
		t.ok(out.data.verify['bob@bob.com'], 'the verifyEmail should match to the email')
		t.ok(uuid.isValid(out.data.verify['bob@bob.com'].id), 'the verifyEmail should give a token')
		t.ok(new Date(out.data.verify['bob@bob.com'].expires) > new Date(), 'the token expiration should be in the future')
	})

	api.createUser(input, function(data_one) {
		t.notOk(data_one.err, 'should not generate an error')
		data_one.fields = {}
		data_one.fields.email = 'mail@email.com'
		api.addEmail(data_one, function(data_two) {
			t.notOk(data_two.err)
		})
	})
})

test('verify an email from a token', function(t) {
	t.plan(6)
	var user_db  = level('test_users', { valueEncoding: 'json' })
	var api = users({ db: user_db })

	var input = { fields: {
		username: 'bob2',
		email: 'bob@bob.com',
		password: 'abc123qwe'
	}}

	api.on('add_email', function(out_one) {
		// console.log(out_one.data)
		// console.log('-----')
		// console.log(out_one.data.verify[Object.keys(out_one.data.verify)[1]])
		var data = {
			user: {
				username: 'bob2',
				// this is a hack to get the session token of the logged in user
				token: out_one.data.session[Object.keys(out_one.data.session)[0]]
			},
			fields: {
				email: 'mail@email.com',
				emailToken: out_one.data.verify[Object.keys(out_one.data.verify)[1]]
			}
		}
		api.verifyEmail(data, function(out_two) {
			// console.log(out_two)
		})
	})

	api.createUser(input, function(data) {
		t.notOk(data.err, 'should not generate an error')
		data.fields = {}
		data.fields.email = 'mail@email.com'
		api.addEmail(data, function(data_two) {
			t.notOk(data_two.err, 'no errors on adding email')
		})
	})
})
