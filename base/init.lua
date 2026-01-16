Encryption = require("aegis.base.encryption")
Hash = require("aegis.base.hash")

return {
	encypt = Encryption.encrypt,
	decrypt = Encryption.decrypt,
	generate_keys = Encryption.generate_keys,
	hash = Hash.hash,
	compare_hash = Hash.compare_hash
}