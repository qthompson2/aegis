local Base = require("aegis.base")
local Database = require("aegis.db"):new()

local ALink = {}

ALink.open = function(side)
	rednet.open(side)
end

ALink.close = function(side)
	rednet.close(side)
end

ALink.isOpen = function(side)
	return rednet.isOpen(side)
end

local function decrypt_message(sender_id, ciphertext)
	local sender_key = Database:getRemoteKey(sender_id, nil)
	local personal_key = Database:getPrivateKey()
	if sender_key and personal_key and type(ciphertext) == "string" then
		local sender_key_decrypted = Base.decrypt(ciphertext, sender_key)
		local personal_key_decrypted = Base.decrypt(sender_key_decrypted, personal_key)

		local plaintext = textutils.unserialise(personal_key_decrypted)

		return plaintext
	end
end

local function decrypt_and_queue(sender_id, ciphertext, protocol)
	local plaintext = decrypt_message(sender_id, ciphertext)
	if plaintext ~= nil then
		local return_protocol = nil
		if protocol ~= "alink" then
			return_protocol = protocol:sub(#"alink:" + 1)
		end
		os.queueEvent("alink_message", sender_id, plaintext, return_protocol)
	end
end

local function request_key(receiver_id)
	rednet.send(receiver_id, {
		["type"] = "key_request",
		["public_key"] = Database:getPublicKey()
	}, "alink:krrs")

	local timer = os.startTimer(2)

	while true do
		local event_data = {os.pullEvent()}
		local event = event_data[1]

		if event == "rednet_message" then
			local sender_id, message, protocol = event_data[2], event_data[3], event_data[4]

			if protocol == "alink:krrs" and type(message) == "table" and message["type"] == "key_response" then
				if type(message["public_key"]) == "table" and receiver_id == sender_id then
					if type(message["public_key"][1]) == "number" and type(message["public_key"][2]) == "number" then
						Database:insertRemoteKey(sender_id, message["public_key"])
						os.cancelTimer(timer)
						break
					end
				end
			end
		elseif event == "timer" then
			local timer_id = event_data[2]
			if timer_id == timer then
				break
			end
		end
	end
end

ALink.send = function (receiver_id, message, protocol)
	local serialized_message = textutils.serialise(message)

	local receiver_key = Database:getRemoteKey(receiver_id)
	local personal_key = Database:getPrivateKey()

	if receiver_key ~= nil then
		local personal_key_encrypted = Base.encypt(serialized_message, personal_key)
		local receiver_key_encrypted = Base.encypt(personal_key_encrypted, receiver_key)

		local rednet_protocol = "alink"
		if protocol then
			rednet_protocol = rednet_protocol .. ":" .. protocol
		end

		rednet.send(receiver_id, {
			["type"] = "data",
			["data"] = receiver_key_encrypted,
		}, rednet_protocol)
	else
		request_key(receiver_id)
		ALink.send(receiver_id, message, protocol)
	end
end

ALink.receive = function(protocol_filter, timeout)
	local timer = nil
	if timeout then
		timer = os.startTimer(timeout)
	end

	while true do
		local event_data = {os.pullEvent()}
		local event = event_data[1]

		if event == "alink_message" then
			local sender_id, message, protocol = event_data[1], event_data[2], event_data[3]
			if protocol_filter == nil or protocol == protocol_filter then
				if timer then os.cancelTimer(timer) end
				return sender_id, message, protocol
			end
		elseif event == "timer" then
			local timer_id = event_data[2]
			if timer_id == timer then
				return nil
			end
		end
	end
end

ALink._run = function ()
	local event_cache = {}
	local function cache_incoming_events()
		while true do
			local event_data = {os.pullEvent()}
			table.insert(event_cache, event_data)
		end
	end

	local function process_event(event_data)
		local event = event_data[1]

		if event == "rednet_message" then
			local sender_id, message, protocol = event_data[2], event_data[3], event_data[4]

			if protocol:find("^alink") then
				if type(message) == "table" then
					if message["type"] == "key_request" then
						rednet.send(sender_id, {
							["type"] = "key_response",
							["public_key"] = Database:getPublicKey(),
						}, "alink:krrs")
					elseif message["type"] == "data" then
						parallel.waitForAny(cache_incoming_events, function() decrypt_and_queue(sender_id, message["data"]) end)
					end
				end
			end
		elseif event == "event_cache" then
			process_event(table.remove(event_cache, 1))
		end

		if #event_cache > 0 then
			os.queueEvent("event_cache")
		end
	end

	while true do
		local event_data = {os.pullEvent()}
		process_event(event_data)
	end
end

return ALink