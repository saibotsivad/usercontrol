'use strict'

var test  = require('tap').test
  , level = require('level-mem')
  , users = require('../usercontrol.js')

test('defining filters for user data', function(t) {

	var user_db  = level('test_users', { valueEncoding: 'json' })

	var userdata_filter = function(new_data, old_data, cb) {
		var filtered_data = {}
		if (new_data.beep) {
			filtered_data.beep = new_data.beep.toUpperCase()
		}
		if (new_data.boop) {
			if (old_data.fields && old_data.fields.userdata && old_data.fields.userdata.boop) {
				filtered_data.boop = old_data.fields.userdata.boop + "," + new_data.boop.toLowerCase()
			} else {
				filtered_data.boop = 'list:' + new_data.boop.toLowerCase()
			}
		}
		cb(null, filtered_data)
	}

	var api = users({
		db: user_db,
		userdataFilter: userdata_filter
	})

	var new_user = { fields: {
		username: 'bob',
		email: 'bob@bob.com',
		password: 'abc123qwe'
	} }

	api.createUser(new_user, function(data_one) {
		t.notOk(data_one.err, 'no errors allowed')
		var update_one = {
			user: {
				username: 'bob',
				token: data_one.user.token.id
			},
			fields: {
				data: {
					beep: 'smallbeep',
					boop: 'FIRSTBOOP'
				}
			}
		}
		api.setData(update_one, function(data_two) {
			t.notOk(data_two.err, 'no errors allowed here either')
			t.ok(data_two.user.fields.userdata, 'userdata should now be present')
			t.ok(data_two.user.fields.userdata.beep === 'SMALLBEEP', 'filter on data')
			t.ok(data_two.user.fields.userdata.boop === 'list:firstboop', 'filter on data')
			var update_two = {
				user: {
					username: 'bob',
					token: data_one.user.token.id
				},
				fields: {
					data: {
						beep: 'bigbeep',
						boop: 'SECONDBOOP'
					}
				}
			}
			api.setData(update_two, function(data_three) {
				t.notOk(data_three.err, 'no errors allowed here either')
				t.ok(data_three.user.fields.userdata, 'userdata should now be present')
				t.ok(data_three.user.fields.userdata.beep === 'BIGBEEP', 'filter on data')
				t.ok(data_three.user.fields.userdata.boop === 'list:firstboop,secondboop', 'filter on data')
				t.end()
			})
		})
	})
})

test('throwing public errors in the userdata filter', function(t) {

	var user_db  = level('test_users', { valueEncoding: 'json' })

	var filter_booping = function(new_data, old_data, cb) {
		if (new_data.boop) {
			cb({ public: 'no booping' })
		} else {
			cb(null, new_data)
		}
	}

	var api = users({
		db: user_db,
		userdataFilter: filter_booping
	})

	var new_user = { fields: {
		username: 'bob',
		email: 'bob@bob.com',
		password: 'abc123qwe'
	} }

	api.createUser(new_user, function(data_one) {
		t.notOk(data_one.err, 'no errors allowed')
		var update_one = {
			user: {
				username: 'bob',
				token: data_one.user.token.id
			},
			fields: {
				data: {
					boop: 'plz boop'
				}
			}
		}
		api.setData(update_one, function(data_two) {
			t.ok(data_two.err, 'booping throws an error')
			t.ok(data_two.err === 'no booping', 'filter error message is passed')
			t.end()
		})
	})
})


test('throwing private errors in the userdata filter', function(t) {
	t.plan(5)

	var user_db  = level('test_users', { valueEncoding: 'json' })

	var filter_booping = function(new_data, old_data, cb) {
		if (new_data.boop) {
			cb({ public: 'try again', private: 'stupid boopers' })
		} else {
			cb(null, new_data)
		}
	}

	var api = users({
		db: user_db,
		userdataFilter: filter_booping
	})

	api.on('set_data', function(out) {
		t.ok(out.data.filterErr.public === 'try again', 'the public message is included in the emitter')
		t.ok(out.data.filterErr.private === 'stupid boopers', 'the private message is included in the emitter')
	})

	var new_user = { fields: {
		username: 'bob',
		email: 'bob@bob.com',
		password: 'abc123qwe'
	} }

	api.createUser(new_user, function(data_one) {
		t.notOk(data_one.err, 'no errors allowed')
		var update_one = {
			user: {
				username: 'bob',
				token: data_one.user.token.id
			},
			fields: {
				data: {
					boop: 'plz boop'
				}
			}
		}
		api.setData(update_one, function(data_two) {
			t.ok(data_two.err, 'booping throws an error')
			t.ok(data_two.err === 'try again', 'public filter error message is passed')
		})
	})
})