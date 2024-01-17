local _M = {}
local resty_sha256 = require "resty.sha256"
local str = require "resty.string"
local json = require('cjson.safe')
local kong = kong
local json_navigator = require("kong.enterprise_edition.transformations.plugins.json_navigator") or nil

local DATE_MATCHER = "\\d{4}\\-(0?[1-9]|1[012])\\-(0?[1-9]|[12][0-9]|3[01])T\\d{2}:\\d{2}:00Z"

local function sha256aValue(value)
  local sha256 = resty_sha256:new()
  sha256:update(value)
  return str.to_hex(sha256:final())
end

local function virtualResponse(conf)
  local body = ""
  local status = 200

  if conf.response and conf.responseContentType then
    local decodedResponse = ngx.decode_base64(conf.response)
    ngx.header["Content-Type"] = conf.responseContentType
    ngx.header["Content-Length"] = #decodedResponse
    body = decodedResponse
  end

  if conf.responseHttpStatus then
    status = conf.responseHttpStatus
    if type(conf.responseHttpStatus) == "string" then
      status = tonumber(status)
    end
  end

  if conf.setAllDatesToNow then
    -- update all datetimes in the template, to NOW
    local datetime_now = os.date("%Y-%m-%dT%H:%M:%SZ")
    body = ngx.re.gsub(body, DATE_MATCHER, datetime_now)
  end

  kong.response.exit(status, body)
end

local function virtualNoMatch(expectedSha256, foundSha256)
  if expectedSha256 and foundSha256 then
    return kong.response.exit(404, { message = "No virtual request match found, your request yeilded: " .. foundSha256 .. " expected " .. expectedSha256 })
  else
    return kong.response.exit(404, { message = "No matching virtual request found!" })
  end
end

local function deep_compare(tbl1, tbl2)
	if tbl1 == tbl2 then
		return true
	elseif type(tbl1) == "table" and type(tbl2) == "table" then
		for key1, value1 in pairs(tbl1) do
			local value2 = tbl2[key1]

			if value2 == nil then
				-- avoid the type call for missing keys in tbl2 by directly comparing with nil
				return false
			elseif value1 ~= value2 then
				if type(value1) == "table" and type(value2) == "table" then
					if not deep_compare(value1, value2) then
						return false
					end
				else
					return false
				end
			end
		end

		-- check for missing keys in tbl1
		for key2, _ in pairs(tbl2) do
			if tbl1[key2] == nil then
				return false
			end
		end

		return true
	end

	return false
end

local function check_table_value(table, key, val)
  local opts = {
    dots_in_keys = false,
  }

  local matched = false
  json_navigator.navigate_and_apply(table, key, function(o, p, ctx)
    if o[p] == val then
      kong.log.inspect("-> matching: '", o, "' against '", key, "=", val, "'")
      matched = true
    end
  end, opts)

  return matched
end

local function check_url_params(key, val)
  local found = false
  local captures = kong.request.get_uri_captures()

  for name, value in pairs(captures.named) do
    if (name == key) and (val == value) then
      kong.log.debug("-> matching '", name, "=", value, "' against '", key, "=", val, "'")

      found = true
      break
    end
  end

  return found
end

function _M.execute(conf)
  --Get the List of Virtual Test Cases
  local virtualTests = json.decode(conf.virtual_tests)

  if ngx.req.get_headers()["X-VirtualRequest"] then
    for i in pairs(virtualTests) do
      if (ngx.req.get_headers()["X-VirtualRequest"] == virtualTests[i].name and virtualTests[i].requestHttpMethod == ngx.req.get_method()) then
        if virtualTests[i].matchAllRequests then
          virtualResponse(virtualTests[i])
        end

        if virtualTests[i].requestJSON then
          local virtualJSON, err = json.decode(virtualTests[i].requestJSON)
          if err then
            return kong.response.exit(500, { error = true, message = "could not decode 'requestJSON' in template: " .. err })
          end

          local requestJSON = kong.request.get_body("application/json")
          if not requestJSON then
            return kong.response.exit(400, { error = true, message = "plugin only supports application/json content-type" })
          end

          if not deep_compare(requestJSON, virtualJSON) then
            return kong.response.exit(404, { error = true, message = "request JSON does not match requested template" })
          end

        elseif virtualTests[i].requestHash then
          local foundQueryParameters
          if ngx.var.request_uri:find('?') then --Is this a URL QUERY based request?
            foundQueryParameters = ngx.var.request_uri:sub(ngx.var.request_uri:find('?') + 1, ngx.var.request_uri:len())
          end

          if foundQueryParameters and foundQueryParameters:len() > 2 then -- minimum a=b 3 chars for a URL QUERY based request
            local sha256foundQueryParameters = sha256aValue(foundQueryParameters)
            if virtualTests[i].requestHash ~= sha256foundQueryParameters then
              virtualNoMatch(virtualTests[i].requestHash, sha256foundQueryParameters)
            end
          else
            ngx.req.read_body()
            local req_body  = ngx.req.get_body_data()
            local sha256FoundHttpBody = ""
            if req_body == nil then
              virtualNoMatch(virtualTests[i].requestHash, sha256FoundHttpBody)
            end

            sha256FoundHttpBody = sha256aValue(req_body)
            if virtualTests[i].requestHash ~= sha256FoundHttpBody then
              virtualNoMatch(virtualTests[i].requestHash, sha256FoundHttpBody)
            end
          end

        end

        return virtualResponse(virtualTests[i])
      end
    end
    return virtualNoMatch(nil, nil)
  else
    -- specific logic for user
    for i, v in ipairs(virtualTests) do
      if v.requestCaptureName
          and v.requestCaptureValue
          and type(v.requestCaptureName) == "string"
          and type(v.requestCaptureValue) == "string"
      then
        -- use request capture mode
        local found = check_url_params(v.requestCaptureName, v.requestCaptureValue)
        if found then
          return virtualResponse(v)
        end
      end

      if v.requestJSONFieldPath
          and v.requestJSONFieldValue
          and type(v.requestJSONFieldPath) == "string"
          and type(v.requestJSONFieldValue) == "string"
      then
        local requestJSON = kong.request.get_body("application/json")
        if not requestJSON then
          return kong.response.exit(400, { error = true, message = "'requestJSONField[Path/Value]' mode only supports application/json requests" })
        end

        -- use jsonpath capture mode
        if not json_navigator then return kong.response.exit(500, "JSON field matching requires Kong Enterprise Edition") end

        local found = check_table_value(requestJSON, v.requestJSONFieldPath, v.requestJSONFieldValue)
        if found then
          return virtualResponse(v)
        end
      end
    end
  end

  return
end

return _M
