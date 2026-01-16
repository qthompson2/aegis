local ALink = require("aegis.alink")
local Ash = require("aegis.ash")

local function startup()
	if not ALink.isRunning() and not Ash.isRunning() then
		parallel.waitForAny(ALink.run, Ash.run) -- Run Ash and ALink
		os.shutdown() -- Shutdown the computer if Ash is terminated (as ALink will always run)
	end
end

return startup