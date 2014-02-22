'use strict'

var uuid = require('uuid')

var generate = function() {
	return uuid.v4()
}

var is_valid = function(uuid) {
	return uuid !== undefined && uuid !== null && uuid.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i)
}

module.exports = {
	generate: generate,
	isValid: is_valid
}