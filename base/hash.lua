local function rrotate(x, n)
    return bit.band(bit.bor(bit.brshift(x, n), bit.blshift(x, 32 - n)), 0xffffffff)
end

local function add32(...)
    local sum = 0
    for i = 1, select("#", ...) do
        sum = (sum + select(i, ...)) % 2^32
    end
    return sum
end

local SHA256_CONSTANTS = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
}

local function preprocess(msg)
    local bitlen = #msg * 8
    msg = msg .. "\128"
    while (#msg % 64) ~= 56 do
        msg = msg .. "\0"
    end

    -- append 64-bit length (high 32 bits are zero)
    msg = msg
        .. string.char(0,0,0,0)
        .. string.char(
            bit.band(bit.brshift(bitlen,24),0xff),
            bit.band(bit.brshift(bitlen,16),0xff),
            bit.band(bit.brshift(bitlen,8),0xff),
            bit.band(bitlen,0xff)
        )

    return msg
end

local function sha256(message)
    local H = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    }

    message = preprocess(message)

    for chunk = 1, #message, 64 do
        local w = {}

        for i = 0, 15 do
            local j = chunk + i*4
            w[i] = bit.bor(
                bit.blshift(message:byte(j),24),
                bit.blshift(message:byte(j+1),16),
                bit.blshift(message:byte(j+2),8),
                message:byte(j+3)
            )
        end

        for i = 16, 63 do
            local s0 = bit.bxor(
                rrotate(w[i-15],7),
                rrotate(w[i-15],18),
                bit.brshift(w[i-15],3)
            )
            local s1 = bit.bxor(
                rrotate(w[i-2],17),
                rrotate(w[i-2],19),
                bit.brshift(w[i-2],10)
            )
            w[i] = add32(w[i-16], s0, w[i-7], s1)
        end

        local a,b,c,d,e,f,g,h = table.unpack(H)

        for i = 0, 63 do
            local S1 = bit.bxor(
                rrotate(e,6),
                rrotate(e,11),
                rrotate(e,25)
            )
            local ch = bit.bxor(bit.band(e,f), bit.band(bit.bxor(e,0xffffffff), g))
            local temp1 = add32(h, S1, ch, SHA256_CONSTANTS[i+1], w[i])
            local S0 = bit.bxor(
                rrotate(a,2),
                rrotate(a,13),
                rrotate(a,22)
            )
            local maj = bit.bxor(bit.band(a,b), bit.band(a,c), bit.band(b,c))
            local temp2 = add32(S0, maj)

            h = g
            g = f
            f = e
            e = add32(d, temp1)
            d = c
            c = b
            b = a
            a = add32(temp1, temp2)
        end

        H[1] = add32(H[1], a)
        H[2] = add32(H[2], b)
        H[3] = add32(H[3], c)
        H[4] = add32(H[4], d)
        H[5] = add32(H[5], e)
        H[6] = add32(H[6], f)
        H[7] = add32(H[7], g)
        H[8] = add32(H[8], h)
    end

    return string.format(
        "%08x%08x%08x%08x%08x%08x%08x%08x",
        H[1],H[2],H[3],H[4],H[5],H[6],H[7],H[8]
    )
end

local function sha256_compare(hash, message)
	return hash == sha256(message)
end

return {
	hash = sha256,
	compare_hash = sha256_compare
}