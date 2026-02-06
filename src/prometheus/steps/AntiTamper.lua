-- Modified by Avi
--
-- AntiTamper.lua
--
-- Hardened Anti-Tamper Step (VM-focused)

local Step = require("prometheus.step")
local Ast = require("prometheus.ast")
local Scope = require("prometheus.scope")
local RandomStrings = require("prometheus.randomStrings")
local Parser = require("prometheus.parser")
local Enums = require("prometheus.enums")
local logger = require("logger")

local AntiTamper = Step:extend()
AntiTamper.Description = "Breaks execution if the script is modified or inspected. Strongest when used with VM."
AntiTamper.Name = "Anti Tamper"

AntiTamper.SettingsDescriptor = {
    UseDebug = {
        type = "boolean",
        default = true,
        description = "Uses debug library for advanced tamper detection."
    }
}

function AntiTamper:init(settings)
    self.UseDebug = settings.UseDebug
end

function AntiTamper:apply(ast, pipeline)
    if pipeline.PrettyPrint then
        logger:warn(string.format(
            "\"%s\" cannot be used with PrettyPrint, ignoring \"%s\"",
            self.Name,
            self.Name
        ))
        return ast
    end

    local secret = RandomStrings.randomString()

    local code = [[
do
    local valid = true
    local err = function()
        error("Tamper Detected!", 0)
    end

    -- ==============================
    -- CORE FUNCTION INTEGRITY CHECK
    -- ==============================
    do
        local funcs = {pcall, string.char, debug and debug.getinfo, string.dump}
        for i = 1, #funcs do
            local f = funcs[i]
            if type(f) ~= "function" then
                valid = false
                break
            end

            local info = debug.getinfo(f)
            if not info or info.what ~= "C" then
                valid = false
                break
            end

            if debug.getupvalue(f, 1) then
                valid = false
                break
            end

            if pcall(string.dump, f) then
                valid = false
                break
            end
        end
    end

    -- ==============================
    -- BYTECODE HASH CHECK
    -- ==============================
    do
        local function marker()
            return ]] .. math.random(100000, 999999) .. [[
        end

        local dump1 = string.dump(marker)
        local h1 = 0
        for i = 1, #dump1 do
            h1 = (h1 + dump1:byte(i) * i) % 2147483647
        end

        local dump2 = string.dump(marker)
        local h2 = 0
        for i = 1, #dump2 do
            h2 = (h2 + dump2:byte(i) * i) % 2147483647
        end

        if h1 ~= h2 then
            valid = false
        end
    end

    -- ==============================
    -- DEBUGGER / SLOW EXECUTION DETECT
    -- ==============================
    if debug then
        local ticks = 0
        local start = os.clock()

        debug.sethook(function()
            ticks = ticks + 1
            if ticks > 6000 then
                debug.sethook()
            end
        end, "", 1)

        for i = 1, 3000 do end
        debug.sethook()

        if os.clock() - start > 0.2 then
            valid = false
        end
    end

    -- ==============================
    -- TRACEBACK CONSISTENCY CHECK
    -- ==============================
    do
        local function trace(arg)
            return debug.traceback(arg)
        end

        local tb = trace("]] .. secret .. [[")
        local first = tb:match("^(.-)\n")
        if first ~= "]] .. secret .. [[" then
            valid = false
        end

        local last
        for line in tb:gmatch(":(%d+):") do
            if last and line ~= last then
                valid = false
                break
            end
            last = line
        end
    end

    -- ==============================
    -- ENVIRONMENT FINGERPRINT
    -- ==============================
    do
        if getmetatable(_G) ~= nil then
            valid = false
        end

        if rawget(_G, "_ENV") then
            valid = false
        end
    end

    -- ==============================
    -- CONTROLLED FAILURE (CORRUPT STATE)
    -- ==============================
    if not valid then
        local a, b = 1, 2
        while true do
            a, b = b, a + b
            if a % 7 == 0 then
                err()
            end
        end
    end

    -- ==============================
    -- FINAL SANITY LOOP
    -- ==============================
    repeat until valid
end
]]

    local parsed = Parser:new({
        LuaVersion = Enums.LuaVersion.Lua51
    }):parse(code)

    local doStat = parsed.body.statements[1]
    doStat.body.scope:setParent(ast.body.scope)
    table.insert(ast.body.statements, 1, doStat)

    return ast
end

return AntiTamper
