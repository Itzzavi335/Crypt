-- Prometheus Obfuscator
-- NumbersToExpressions.lua (HELLA Hardened)

unpack = unpack or table.unpack

local Step = require("prometheus.step")
local Ast = require("prometheus.ast")
local Scope = require("prometheus.scope")
local visitast = require("prometheus.visitast")
local util = require("prometheus.util")

local AstKind = Ast.AstKind

local NumbersToExpressions = Step:extend()
NumbersToExpressions.Description = "Converts number literals to complex, runtime expressions"
NumbersToExpressions.Name = "Numbers To Expressions+"

NumbersToExpressions.SettingsDescriptor = {
	Treshold = { type = "number", default = 1, min = 0, max = 1 },
	InternalTreshold = { type = "number", default = 0.3, min = 0, max = 0.8 },
	MaxDepth = { type = "number", default = 20, min = 1, max = 50 },
}

function NumbersToExpressions:init(settings)
	self.ExpressionGenerators = {
		-- addition
		function(val, depth)
			local v2 = math.random(-2^20, 2^20)
			local diff = val - v2
			if tonumber(tostring(diff)) + tonumber(tostring(v2)) ~= val then return false end
			return Ast.AddExpression(self:CreateNumberExpression(diff, depth), self:CreateNumberExpression(v2, depth))
		end,
		-- subtraction
		function(val, depth)
			local v2 = math.random(-2^20, 2^20)
			local diff = val + v2
			if tonumber(tostring(diff)) - tonumber(tostring(v2)) ~= val then return false end
			return Ast.SubExpression(self:CreateNumberExpression(diff, depth), self:CreateNumberExpression(v2, depth))
		end,
		-- multiplication
		function(val, depth)
			if val == 0 then return Ast.NumberExpression(0) end
			local factor = math.random(1, 1000)
			local base = val / factor
			if math.abs(base * factor - val) > 1e-6 then return false end
			return Ast.MulExpression(self:CreateNumberExpression(base, depth), self:CreateNumberExpression(factor, depth))
		end,
		-- integer division
		function(val, depth)
			local divisor = math.random(1, 50)
			local numerator = val * divisor
			return Ast.FloorDivExpression(self:CreateNumberExpression(numerator, depth), self:CreateNumberExpression(divisor, depth))
		end,
		-- modulo trick
		function(val, depth)
			local mod = math.random(1, 100)
			local base = val - val % mod
			return Ast.ModExpression(self:CreateNumberExpression(base, depth), self:CreateNumberExpression(mod, depth))
		end,
		-- exponentiation
		function(val, depth)
			if val == 0 then return Ast.NumberExpression(0) end
			local exp = math.random(1, 6)
			local base = val^(1/exp)
			if base^exp ~= val then return false end
			return Ast.PowExpression(self:CreateNumberExpression(base, depth), Ast.NumberExpression(exp))
		end,
	}
end

function NumbersToExpressions:CreateNumberExpression(val, depth)
	if depth > self.MaxDepth or (depth > 0 and math.random() > self.InternalTreshold) then
		return Ast.NumberExpression(val)
	end

	local generators = util.shuffle({unpack(self.ExpressionGenerators)})

	for _, gen in ipairs(generators) do
		local node = gen(val, depth + 1)
		if node then
			-- add random decoy math (ignored, for obfuscation)
			if math.random() < 0.4 then
				local decoy = math.random(-50,50)
				node = Ast.AddExpression(node, Ast.NumberExpression(0 + decoy - decoy))
			end
			return node
		end
	end

	return Ast.NumberExpression(val)
end

function NumbersToExpressions:apply(ast)
	visitast(ast, nil, function(node, data)
		if node.kind == AstKind.NumberExpression and math.random() <= self.Treshold then
			return self:CreateNumberExpression(node.value, 0)
		end
	end)
end

return NumbersToExpressions
