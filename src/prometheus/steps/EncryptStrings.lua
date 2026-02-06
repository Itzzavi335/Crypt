-- Prometheus Obfuscator
-- EncryptStrings.lua (Hardened)

local Step = require("prometheus.step")
local Ast = require("prometheus.ast")
local Scope = require("prometheus.scope")
local RandomStrings = require("prometheus.randomStrings")
local Parser = require("prometheus.parser")
local Enums = require("prometheus.enums")
local visitast = require("prometheus.visitast")
local util = require("prometheus.util")

local AstKind = Ast.AstKind
local EncryptStrings = Step:extend()

EncryptStrings.Description = "Encrypts strings with hardened PRNG, lazy decode and anti-dump logic"
EncryptStrings.Name = "Encrypt Strings+"
EncryptStrings.SettingsDescriptor = {}

function EncryptStrings:init(settings) end

-- ============================================
-- ENCRYPTION SERVICE
-- ============================================
function EncryptStrings:CreateEncryptionService()
	local usedSeeds = {}

	local K1 = math.random(1, 255)
	local K2 = math.random(1, 2^31 - 1)
	local K3 = math.random(1, 2^24)
	local K4 = math.random(1, 255)

	local function genSeed()
		local s
		repeat
			s = math.random(1, 2^31 - 1)
		until not usedSeeds[s]
		usedSeeds[s] = true
		return s
	end

	-- 32‑bit LCG + feedback
	local function encrypt(str)
		local seed = genSeed()
		local state = (seed ~ K2) % 2^31
		local prev = K4
		local out = {}

		for i = 1, #str do
			state = (state * 1103515245 + 12345 + K3) % 2^31
			local rnd = (state % 256)
			local b = string.byte(str, i)
			out[i] = string.char((b - rnd - prev) % 256)
			prev = b
		end

		return table.concat(out), seed
	end

	local function genRuntimeCode()
		local code = [[
do
	local floor = math.floor
	local char = string.char
	local byte = string.byte
	local stateCache = {}
	local real = {}
	local poisoned = false

	local STRINGS = setmetatable({}, {
		__index = function(_, k)
			if poisoned then
				while true do end
			end
			return real[k]
		end,
		__metatable = false
	})

	local function DECRYPT(enc, seed)
		if real[seed] then
			return seed
		end

		-- integrity trap
		if type(enc) ~= "string" or type(seed) ~= "number" then
			poisoned = true
			return seed
		end

		local state = (seed ~ ]] .. K2 .. [[) % 2147483648
		local prev = ]] .. K4 .. [[
		local out = {}

		for i = 1, #enc do
			state = (state * 1103515245 + 12345 + ]] .. K3 .. [[) % 2147483648
			local rnd = state % 256
			local b = (byte(enc, i) + rnd + prev) % 256
			out[i] = char(b)
			prev = b
		end

		real[seed] = table.concat(out)
		return seed
	end

	_G["]] .. RandomStrings.randomString() .. [["] = STRINGS
	_G["]] .. RandomStrings.randomString() .. [["] = DECRYPT
end
]]
		return code
	end

	return {
		encrypt = encrypt,
		genCode = genRuntimeCode
	}
end

-- ============================================
-- APPLY STEP
-- ============================================
function EncryptStrings:apply(ast)
	local Encryptor = self:CreateEncryptionService()

	local code = Encryptor.genCode()
	local newAst = Parser:new({
		LuaVersion = Enums.LuaVersion.Lua51
	}):parse(code)

	local doStat = newAst.body.statements[1]
	local root = ast.body.scope

	local decryptVar = root:addVariable()
	local stringsVar = root:addVariable()

	doStat.body.scope:setParent(root)

	-- bind runtime symbols
	visitast(newAst, nil, function(node, data)
		if node.kind == AstKind.FunctionDeclaration then
			data.scope:removeReferenceToHigherScope(node.scope, node.id)
			data.scope:addReferenceToHigherScope(root, decryptVar)
			node.scope = root
			node.id = decryptVar
		end

		if node.kind == AstKind.VariableExpression then
			data.scope:removeReferenceToHigherScope(node.scope, node.id)
			data.scope:addReferenceToHigherScope(root, stringsVar)
			node.scope = root
			node.id = stringsVar
		end
	end)

	-- replace string literals
	visitast(ast, nil, function(node, data)
		if node.kind == AstKind.StringExpression then
			data.scope:addReferenceToHigherScope(root, decryptVar)
			data.scope:addReferenceToHigherScope(root, stringsVar)

			local enc, seed = Encryptor.encrypt(node.value)
			return Ast.IndexExpression(
				Ast.VariableExpression(root, stringsVar),
				Ast.FunctionCallExpression(
					Ast.VariableExpression(root, decryptVar),
					{
						Ast.StringExpression(enc),
						Ast.NumberExpression(seed)
					}
				)
			)
		end
	end)

	table.insert(ast.body.statements, 1, doStat)
	table.insert(
		ast.body.statements,
		1,
		Ast.LocalVariableDeclaration(root, util.shuffle{decryptVar, stringsVar}, {})
	)

	return ast
end

return EncryptStrings
