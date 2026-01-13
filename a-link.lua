Base = require("base")
Database = require("db"):new()

ALink = {}

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

			if protocol == "alink" then
				if type(message) == "table" then
					if message["type"] == "key_request" then
						rednet.send(sender_id, {
							["type"] = "lookup_response",
							["public_key"] = Database:get(), -- Need to get public key
						})
					elseif message["type"] == "key_response" then
						
					end
				end
			end
		end
	end

	while true do
		local event_data = {os.pullEvent()}
		process_event(event_data)
	end
end

return ALink