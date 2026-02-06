-- Prometheus Obfuscator
-- ConstantArray.lua (Hardened)

local Step = require("prometheus.step")
local Ast = require("prometheus.ast")
local Scope = require("prometheus.scope")
local visitast = require("prometheus.visitast")
local util = require("prometheus.util")
local Parser = require("prometheus.parser")
local enums = require("prometheus.enums")

local LuaVersion = enums.LuaVersion
local AstKind = Ast.AstKind

local ConstantArray = Step:extend()
ConstantArray.Description = "Extracts constants into encoded, sharded, runtime-decoded arrays"
ConstantArray.Name = "Constant Array+"

ConstantArray.SettingsDescriptor = {
	Treshold = { type="number", default=1, min=0, max=1 },
	StringsOnly = { type="boolean", default=false },
	Shuffle = { type="boolean", default=true },
	Rotate = { type="boolean", default=true },
	Encoding = {
		type="enum",
		default="base64",
		values={"none","base64"}
	},
	ShardCount = {
		type="number",
		default=3,
		min=1,
		max=8
	},
	FakeConstants = {
		type="number",
		default=5,
		min=0,
		max=128
	}
}

function ConstantArray:init(settings)
	self.ShardCount = settings.ShardCount or 3
	self.FakeConstants = settings.FakeConstants or 5
end

-- ===============================
-- ENCODING (BASE64 + XOR)
-- ===============================
function ConstantArray:encode(str)
	if self.Encoding ~= "base64" then
		return str
	end

	local key = self.xorKey
	str = str:gsub(".", function(c)
		return string.char(bit32.bxor(c:byte(), key))
	end)

	return ((str:gsub('.', function(x)
		local r,b='',x:byte()
		for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
		return r
	end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
		if #x < 6 then return '' end
		local c=0
		for i=1,6 do
			c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0)
		end
		return self.base64chars:sub(c+1,c+1)
	end)..({ '', '==', '=' })[#str%3+1])
end

-- ===============================
-- ARRAY CREATION (SHARDED)
-- ===============================
function ConstantArray:createArrays()
	local arrays = {}
	for i = 1, self.ShardCount do
		arrays[i] = {}
	end

	for _, v in ipairs(self.constants) do
		local shard = math.random(1, self.ShardCount)
		table.insert(arrays[shard], Ast.ConstantNode(v))
	end

	-- Inject fake constants
	for i = 1, self.FakeConstants do
		local shard = math.random(1, self.ShardCount)
		table.insert(arrays[shard],
			Ast.ConstantNode(util.randomString(math.random(5,15))))
	end

	local nodes = {}
	for i = 1, self.ShardCount do
		nodes[i] = Ast.TableConstructorExpression(
			util.map(arrays[i], function(v)
				return Ast.TableEntry(v)
			end)
		)
	end

	return nodes
end

-- ===============================
-- INDEX OBFUSCATION
-- ===============================
function ConstantArray:maskedIndex(idx)
	local m = self.indexMask
	return Ast.AddExpression(
		Ast.NumberExpression(idx),
		Ast.NumberExpression(m)
	)
end

-- ===============================
-- APPLY
-- ===============================
function ConstantArray:apply(ast)
	self.rootScope = ast.body.scope
	self.arrIds = {}
	self.constants = {}
	self.lookup = {}

	self.indexMask = math.random(-50000,50000)
	self.xorKey = math.random(1,255)

	self.base64chars = table.concat(util.shuffle{
		"A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P",
		"Q","R","S","T","U","V","W","X","Y","Z",
		"a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p",
		"q","r","s","t","u","v","w","x","y","z",
		"0","1","2","3","4","5","6","7","8","9","+","/"
	})

	-- Collect constants
	visitast(ast, nil, function(node)
		if node.kind == AstKind.StringExpression then
			local enc = self:encode(node.value)
			if not self.lookup[enc] then
				table.insert(self.constants, enc)
				self.lookup[enc] = #self.constants
			end
			node.__replace = enc
		end
	end, function(node, data)
		if node.__replace then
			local idx = self.lookup[node.__replace]
			local shard = ((idx - 1) % self.ShardCount) + 1
			data.scope:addReferenceToHigherScope(self.rootScope, self.arrIds[shard])
			return Ast.IndexExpression(
				Ast.VariableExpression(self.rootScope, self.arrIds[shard]),
				self:maskedIndex(idx)
			)
		end
	end)

	-- Declare arrays
	local arrayNodes = self:createArrays()
	for i = 1, self.ShardCount do
		local id = self.rootScope:addVariable()
		self.arrIds[i] = id
		table.insert(ast.body.statements, 1,
			Ast.LocalVariableDeclaration(
				self.rootScope,
				{id},
				{arrayNodes[i]}
			)
		)
	end

	-- Runtime unmask + decode
	local runtime = [[
do
	local mask = ]]..self.indexMask..[[ 
	local key = ]]..self.xorKey..[[

	local function decode(s)
		local out = {}
		for i=1,#s do
			out[i] = string.char(bit32.bxor(s:byte(i), key))
		end
		return table.concat(out)
	end

	for _, ARR in pairs({...}) do
		for i=1,#ARR do
			if type(ARR[i])=="string" then
				ARR[i] = decode(ARR[i])
			end
		end
	end
end
]]

	local parser = Parser:new({LuaVersion=LuaVersion.Lua51})
	local rtAst = parser:parse(runtime)
	local doStat = rtAst.body.statements[1]
	doStat.body.scope:setParent(ast.body.scope)

	for _, id in ipairs(self.arrIds) do
		doStat.body.scope:addReferenceToHigherScope(self.rootScope, id)
	end

	table.insert(ast.body.statements, 1, doStat)

	-- cleanup
	self.constants = nil
	self.lookup = nil
	self.arrIds = nil
end

return ConstantArray
