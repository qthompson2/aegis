local Database = require("aegis.db"):new()

local _running = false
local Ash = {}

function Ash.isRunning()
	return _running
end

function Ash.run()
	_running = true

	-- Temporary Functionality
	os.run({}, "rom/programs/shell.lua")
end

return Ash