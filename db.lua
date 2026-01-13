Database = {}

function Database:new()
	if self._db then
		return self._db
	end

	local obj = {}

	setmetatable(obj, {__index = self})
	self._db = obj
	return obj
end

return Database