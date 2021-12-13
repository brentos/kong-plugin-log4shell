local kong = kong
local ngx = ngx

local plugin = {
  PRIORITY = 3000, -- set the plugin priority, which determines plugin execution order
  VERSION = "0.1",
}

local function check_header_value(k,v)
    local s = tostring(v)
    s=string.gsub(s, "${lower:(%a+)}", "%1")
    s=string.gsub(s, "${upper:(%a+)}", "%1")
    s=string.gsub(s, "${env:[%a_-]+:%-([%a:])}", "%1")
    s=string.gsub(s, "${::%-(%a+)}", "%1")
    kong.log.debug(s)
    if string.match(string.lower(s), "{jndi:") then
      ngx.log(ngx.ERR, 'Found potential log4j attack in header ' .. k .. ':' .. tostring(v))
      ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end

-- runs in the 'access_by_lua_block'
function plugin:access(plugin_conf)

  local headers = kong.request.get_headers()

  local req_headers = "Headers: "
  for k, v in pairs(headers) do
    req_headers = req_headers .. k .. ": " .. tostring(v) .. "\n";

    if v then
      if type(v) == "string" then
        check_header_value(k, v)
        elseif type(v) == "table" then
        for _,v in ipairs(v) do
          check_header_value(k, v)
        end
        else
          -- Error
      end
    end
  end


end

-- return our plugin object
return plugin
