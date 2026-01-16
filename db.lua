local Base = require("aegis.base")

local Database = {}

local BASE_PATH = ".aegis-db"
local REMOTE_KEYS_PATH = fs.combine(BASE_PATH, "remote_keys.table")
local LOCAL_USERS_PATH = fs.combine(BASE_PATH, "local_users.table")
local KEY_PATH = fs.combine(BASE_PATH, "key.txt")

function Database:new()
	if self._db then
		return self._db
	end

	local obj = {}

	obj.tables = {
		["local_users"] = {},
		["remote_keys"] = {},
		["key"] = ""
	}

	setmetatable(obj, {__index = self})
	self._db = obj

	obj:loadRemoteKeys()
	obj:loadLocalUsers()
	obj:loadKey()

	return obj
end

function Database:insertRemoteKey(id, public_key)
	if type(id) ~= "number" then return false, "invalid sender_id type" end
	if type(public_key) ~= "table" then return false, "invalid public_key type" end
	if type(public_key[1]) ~= "number" or type(public_key[2]) ~= "number" then return false, "invalid public_key format" end

	if self.tables.remote_keys[id] then
		local file = fs.open(REMOTE_KEYS_PATH, "w")
		if file then
			self.tables.remote_keys[id] = public_key
			for sid, key in pairs(self.tables.remote_keys) do
				file.writeLine(tostring(sid) .. "=" .. tostring(key[1]) .. ":" .. tostring(key[2]))
			end
			file.close()
		else
			return false, "cannot open remote keys table"
		end
	else
		local file = fs.open(REMOTE_KEYS_PATH, "r+")
		if file then
			file.seek("end", 0)
			file.writeLine(tostring(id) .. "=" .. tostring(public_key[1]) .. ":" .. tostring(public_key[2]))
			file.close()
			self.tables.remote_keys[id] = public_key
		else
			return false, "cannot open remote keys table"
		end
	end

	return true, "insert successful"
end

function Database:getRemoteKey(id, default)
	return self.tables.remote_keys[id] or default
end

function Database:loadRemoteKeys()
	if fs.exists(REMOTE_KEYS_PATH) then
		local file = fs.open(REMOTE_KEYS_PATH, "r")

		if file then
			local line = file.readLine()
			while line do
				line = line .. "\n"
				local _, _, raw_id, raw_key, raw_n = line:find("(.-)=(.-):(.-)\n")
				local proc_id, proc_key, proc_n = tonumber(raw_id), tonumber(raw_key), tonumber(raw_n)

				if proc_id and proc_key and proc_n then
					self.tables.remote_keys[proc_id] = {proc_key, proc_n}
				end
				line = file.readLine()
			end
			file.close()
		else
			return false, "cannot open remote keys table"
		end
	else
		fs.open(REMOTE_KEYS_PATH, "w").close() -- Creates file.
	end

	return true, "load successful"
end

function Database:userExists(username) return self.tables.local_users[username] ~= nil end

function Database:insertLocalUser(username, password)
	if type(username) ~= "string" then return false, "invalid username type" end
	if type(password) ~= "string" then return false, "invalid password type" end
	if self:userExists(username) then return false, "user exists" end

	local password_hash = Base.hash(password)

	local file = fs.open(LOCAL_USERS_PATH, "r+")
	if file then
		file.seek("end", 0)
		file.writeLine(username .. "=" .. password_hash)
		file.close()
		self.tables.local_users[username] = password_hash
	else
		return false, "cannot open local users table"
	end

	return true, "insert successful"
end

function Database:checkLocalUser(username, password)
	if type(username) ~= "string" then return false, "invalid username type" end
	if type(password) ~= "string" then return false, "invalid password type" end
	if not self:userExists(username) then return false, "user does not exist" end

	local password_hash = self.tables.local_users[username]
	return Base.compare_hash(password_hash, password), "check successful"
end

function Database:deleteLocalUser(username)
	if type("username") ~= "string" then return false, "invalid username type" end
	if not self:userExists(username) then return false, "user does not exist" end

	local file = fs.open(LOCAL_USERS_PATH, "w")
	if file then
		self.tables.local_users[username] = nil
		for user, password_hash in pairs(self.tables.local_users) do
			file.writeLine(user .. "=" .. password_hash)
		end
		file.close()
	else
		return false, "cannot open local users table"
	end

	return true, "delete successful"
end

function Database:loadLocalUsers()
	if fs.exists(LOCAL_USERS_PATH) then
		local file = fs.open(LOCAL_USERS_PATH, "r")

		if file then
			local line = file.readLine()
			while line do
				line = line .. "\n"
				local _, _, username, password_hash = line:find("(.-)=(.-)\n")

				if type(username) == "string" and type(password_hash) == "string" then
					if #username > 0 and #password_hash > 0 then
						self.tables.local_users[username] = password_hash
					end
				end
				line = file.readLine()
			end
			file.close()
		else
			return false, "cannot open local users table"
		end
	else
		fs.open(LOCAL_USERS_PATH, "w").close()
	end

	return true, "load successful"
end

function Database:getPublicKey()
	local _, _, raw_public_key, _, raw_n = self.tables.key:find("(.-):(.-):(.-)\n")
	return {tonumber(raw_public_key), tonumber(raw_n)}
end

function Database:getPrivateKey()
	local _, _, _, raw_private_key, raw_n = self.tables.key:find("(.-):(.-):(.-)\n")
	return {tonumber(raw_private_key), tonumber(raw_n)}
end

function Database:loadKey()
	if fs.exists(KEY_PATH) then
		local file = fs.open(KEY_PATH, "r")
		if file then
			local _, _, raw_public_key, raw_private_key, raw_n = file.readAll():find("(.-):(.-):(.-)\n")
			local public_key, private_key, n = tonumber(raw_public_key), tonumber(raw_private_key), tonumber(raw_n)

			if public_key and private_key and n then
				self.tables.key = tostring(public_key) .. ":" .. tostring(private_key) .. ":" .. tostring(n) .. "\n"
			end

			file.close()
		end
	else
		local file = fs.open(KEY_PATH, "w")
		if file then
			local public_key, private_key, n = Base.generate_keys()
			self.tables.key = tostring(public_key) .. ":" .. tostring(private_key) .. ":" .. tostring(n) .. "\n"
			file.write(self.tables.key)
			file.close()
		else
			return false, "cannot open key file"
		end
	end

	return true, "load successful"
end

return Database