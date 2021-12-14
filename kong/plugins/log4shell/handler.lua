--Copyright 2021 Infiniroot
--Copyright 2021 Brent Yarger
--
--Licensed under the Apache License, Version 2.0 (the "License");
--you may not use this file except in compliance with the License.
--You may obtain a copy of the License at
--
--http://www.apache.org/licenses/LICENSE-2.0
--
--Unless required by applicable law or agreed to in writing, software
--distributed under the License is distributed on an "AS IS" BASIS,
--WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--See the License for the specific language governing permissions and
--limitations under the License.

local kong = kong

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
    if string.match(string.lower(s), "{jndi:") then
      kong.log.err('Found potential log4j attack in header ' .. k .. ':' .. tostring(v))
      return kong.response.exit(403, "Forbidden")
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
      end
    end
  end


end

-- return our plugin object
return plugin
