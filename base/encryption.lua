local function power(base, exponent, m)
	local result = 1
	base = base % m

	while exponent > 0 do
		if bit.band(exponent, 1) ~= 0 then
			result = (result * base) % m
		end
		base = (base * base) % m
        exponent = bit.brshift(exponent, 1)
	end

	return result
end

local function encrypt_char(plaintext, key)
	return power(plaintext, key[1], key[2])
end

local function encrypt(plaintext, key)
	local res = {}
	for _, char in ipairs(plaintext) do
		table.insert(res, encrypt_char(char, key))
	end
	return res
end

local function decrypt_char(ciphertext, key)
	return power(ciphertext, key[1], key[2])
end

local function decrypt(ciphertext, key)
	local res = {}
	for _, char in ipairs(ciphertext) do
		table.insert(res, decrypt_char(char, key))
	end
	return res
end

local function mod_inverse(e, phi)
	for d = 2, phi do
		if (e * d) % phi == 1 then
			return d
		end
	end
	return -1
end

local function greatest_common_denominator(a, b)
    while b ~= 0 do
		a, b = b, a % b
	end
	return a
end

local function is_prime(n)
    if n < 2 then return false end
    if n % 2 == 0 then return n == 2 end

    -- Miller–Rabin
    local d = n - 1
    local s = 0
    while bit.band(d, 1) == 0 do
        d = bit.brshift(d, 1)
        s = s + 1
    end

    local function trial(a)
        local x = power(a, d, n)
        if x == 1 or x == n - 1 then return true end
        for _ = 1, s - 1 do
            x = (x * x) % n
            if x == n - 1 then return true end
        end
        return false
    end

    -- deterministic bases for n < 2^32
    local bases = {2, 7, 61}
    for _, a in ipairs(bases) do
        if a < n and not trial(a) then
            return false
        end
    end

    return true
end

local function random_prime()
	math.randomseed(os.time() + tonumber(tostring({}):sub(8), 16))

    while true do
        local n = math.random(2^11, 2^12)  -- 11–12 bit values ('cause if I go higher the power function breaks)
        if n % 2 == 0 then n = n + 1 end
        if is_prime(n) then
            return n
        end
    end
end

local function generate_keys(p, q)
	p = p or random_prime()
	q = q or random_prime()

	local n = p * q
	local phi = (p - 1) * (q - 1)

	local e = 0
	for _e = 2, phi do
		if greatest_common_denominator(_e, phi) == 1 then
			e = _e
			break
		end
	end

	local d = mod_inverse(e, phi)

	return e, d, n
end

return {
	encrypt = encrypt,
	decrypt = decrypt,
	generate_keys = generate_keys
}