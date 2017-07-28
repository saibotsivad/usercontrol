usercontrol
===========

[![Greenkeeper badge](https://badges.greenkeeper.io/saibotsivad/usercontrol.svg)](https://greenkeeper.io/)


A dnode compliant user authentication system, using leveldb.

Calls to the exported functions expect the following
object, more or less:

	var input = {
		user: { // identifies an existing user
			token: 'a v4 uuid',
			username: 'a username, like "saibotsivad" (see docs for implemenations not using usernames)',
			password: 'used here only when logging in, essentially in place of the token',
			resetToken: 'when resetting the password or logging in over email, this is the single-use token'
		},
		fields: { // identifies changing data
			password: 'when setting a new password or creating a user',
			username: 'when changing the username or creating a user',
			email: 'when adding, deleting, or verifying an email, or creating a user'
		}
	}

Responses from the exported functions contain
some of the following fields:

	var output = {
		err: {
			msg: 'if there is a message it will be here'
			// each exported function may have a testable error, which
			// is just a convenience field, it either exists as true
			// or is undefined. Check each method for it's own errors.
		},
		user: { // the user data that was sent in, after modification
			token: {
				id: 'generated token or existing one',
				expires: 'the date the token expires'
			},
			username: 'the username',
			emails: [
				{
					email: 'email address',
					verified: 'the date the email was verified, otherwise undefined'
				}
			]
		},
		fields: {} // fields added using the addField() method
	}

Data stored in the database is organized like this:

	var db = {
		'username': {
			created: 'date of user creation',
			username: 'repeated here for convenience',
			password_hash: 'the hashed password, using normal password hashing methods',
			reset_token: {
				
			}
			emails: {
				'email address': {
					email: 'email address repeated for convenience',
					verified: 'the date the email was verified, otherwise this field will not exist'
				}
			},
			session: {
				'token id': {
					id: 'token id repeated for convenience',
					expires: 'date the session expires'
				}
			},
			fields: {
				'key': 'value of field'
			}
		}
	}

## API

### isUser

Used to verify if the user exists. Returns username or

* `err.invalidUsername`
* `err.userNotFound`


### createUser

When a user is created, a session token is created and handed back. Returns user data or

* `badPassword`
* `badUsernameOrEmail`
* `userExists`


### isUserAuthenticated

Given a session token and username, see if that session token is valid. If so, return
the user data, otherwise hands back `err.authentication`


### authenticateUser

Given a user's password, generate and store a session token and return user data or `err.authentication`


### invalidateSession

Given a username and session token, delete that token from the database. Returns `user:true` or `err.authentication`


### setPassword

Given a username, session token, and new password, reset the password for the user. Returns user data
or `err.authenitcation` or `err.passwordLength` if not above minimum length.


### setUsername

Given a username, session token, and new username, change the username for the user or
hand back `err.authenitcation` or `err.badUsername` or `err.loggedOut`


### createResetToken

Given a username, generates a session token which can be used to bypass security
to reset the password. Typically this would be emailed to a user on a primary email
and when they visit the website some logic would take the GET parameter and pass it
back to the server as the normal session token. On the server, use the emitter
to get the token and send the reset email.
