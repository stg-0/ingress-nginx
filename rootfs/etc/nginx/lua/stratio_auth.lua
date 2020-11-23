-- Rendered in /etc/nginx/lua/stratio_auth.lua
local ngx = ngx
local http = require "resty.http"
local ck = require "resty.cookie"
local cjson = require "cjson.safe"

local _M = {}


local function create_jwt(oauth2_cookie, userinfo_url, stratio_key)

    -- Get User info

    local httpc = http.new()
    local res, err = httpc:request_uri(userinfo_url, {
        method = "GET",
        headers = {
        ["Content-Type"] = "application/json",
        ["Cookie"] = "_oauth2_proxy=" .. oauth2_cookie,
        }
    })

    if not res then
        ngx.log(ngx.STDERR, 'Unexpected error obtaining the user information: ', err)
        return 403
    end

    local json_decoder = cjson.decode
    local userinfo, err = json_decoder(res.body)

    -- Create JWT

    local jwt = require "resty.jwt"
    local stratio_jwt = jwt:sign(
        stratio_key,
        {
            header = {
                alg="HS256",
                kid="secret",
                typ="JWT"
            },
            payload = {
                iss = "stratio",
                nbf = os.time(),
                exp = os.time() + 21600,
                cn = userinfo["cn"],
                groups = userinfo["groups"],
                mail = userinfo["email"],
                tenant = userinfo["tenant"],
                uid = userinfo["uid"]
            }
        }
    )
    return stratio_jwt
end

function _M.create_cookie(userinfo_url, oauth2_cookie_name, stratio_cookie_name, stratio_key)

    -- Get request's cookies
    
    local req_cookie, err = ck:new()
    if not req_cookie then
        ngx.log(ngx.STDERR, 'Unexpected error obtaining the request cookies: ', err)
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
        return
    end

    -- Get oauth2-proxy cookie

    local oauth2_cookie, err = req_cookie:get(oauth2_cookie_name)
    if not oauth2_cookie then
        ngx.log(ngx.STDERR, 'Unexpected error obtaining the _oauth2_proxy cookie')
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
        return
    end

    -- If there's no Stratio cookie in the request, add it

    local jwt = require "resty.jwt"

    local stratio_cookie, err = req_cookie:get(stratio_cookie_name)
    if not stratio_cookie then
        
        ngx.log(ngx.STDERR, '[STG] statio-cookie NOT FOUND in request [END]')

        stratio_jwt = create_jwt(oauth2_cookie, userinfo_url, stratio_key)
        
        -- Add cookie to response
        local ok, err = req_cookie:set({
            key = "stratio-cookie", 
            value = stratio_jwt,
            expires = os.time() + 21600
        })

        if not ok then
            ngx.log(ngx.STDERR, 'Unexpected error setting the Stratio cookie: ', err)
            return 403
        end

        -- Redirect to self so the service gets the cookie in the first request
        -- return ngx.redirect(ngx.var.request_uri)

        ngx.log(ngx.STDERR, '[STG] stratio_jwt: ' .. stratio_jwt .. ' [END]')
        ngx.log(ngx.STDERR, '[STG] ngx.var.http_cookie: ' .. ngx.var.http_cookie .. ' [END]')

        -- Add cookie to request
        ngx.req.set_header("Cookie", stratio_cookie_name .. "=" .. stratio_jwt .. ";" .. ngx.var.http_cookie);

        -- return stratio_cookie_name .. "=" .. stratio_jwt
    else
        ngx.log(ngx.STDERR, '[STG] statio-cookie FOUND in request [END]')

        -- Validate Stratio JWT
        local jwt_obj = jwt:verify(stratio_key, stratio_cookie, {
            lifetime_grace_period = 120,
            require_exp_claim = true,
            valid_issuers = { "stratio" }
        })

        if not jwt_obj["verified"] then
            
            -- ngx.log(ngx.STDERR, 'Unexpected error validating the JWT: ', jwt_obj["reason"])
            ngx.log(ngx.STDERR, '[STG] invalid jwt, generating a new one [END]')
            stratio_jwt = create_jwt(oauth2_cookie, userinfo_url, stratio_key)
            
            -- Add cookie to response
            local ok, err = req_cookie:set({
                key = "stratio-cookie", 
                domain = ngx.var.http_host,
                secure = true,
                samesite = "Strict",
                value = stratio_jwt,
                expires = os.time() + 21600
            })
    
            if not ok then
                ngx.log(ngx.STDERR, 'Unexpected error setting the Stratio cookie: ', err)
                return 401
            end

            ngx.log(ngx.STDERR, '[STG] stratio_jwt: ' .. stratio_jwt .. ' [END]')

            local cookies, err = req_cookie:get_all()

            if not cookies then
                ngx.log(ngx.STDERR, 'Unexpected error getting the request cookies: ', err)
                return
            end
            -- cookies.stratio_cookie_name = nil
            -- local cookie_jar = {}

            -- for k, v in pairs(cookies) do
            --     ngx.log(ngx.STDERR, '[STG] k: ' .. k .. ' - v: ' .. v .. ' [END]')
            -- end

            local mycookiestr = ''
            for k, v in pairs(cookies) do
                if k == stratio_cookie_name then
                    -- cookies[k] = stratio_jwt
                    v = stratio_jwt
                end
                mycookiestr = mycookiestr .. k .. "=" .. v .. ";"
            end

            -- for k, v in pairs(cookies) do
            --     ngx.log(ngx.STDERR, '[STG] k: ' .. k .. ' - v: ' .. v .. ' [END]')
            -- end
            
            -- Add cookies to request

            ngx.log(ngx.STDERR, '[STG] mycookiestr: ' .. mycookiestr .. ' [END]')
            ngx.req.set_header("Cookie", stratio_cookie_name .. "=" .. stratio_jwt .. ";" .. mycookiestr);
            -- ngx.req.set_header("Cookie", stratio_cookie_name .. "=" .. stratio_jwt .. ";" .. cookie_jar);

            -- ngx.status = ngx.HTTP_UNAUTHORIZED
            -- ngx.exit(ngx.HTTP_UNAUTHORIZED)
            -- return 

            -- return stratio_cookie_name .. "=" .. stratio_jwt
        else
            ngx.log(ngx.STDERR, '[STG] JWT VALID, moving on.. [END]')
            --ngx.req.set_header("Cookie", stratio_cookie_name .. "=" .. stratio_cookie .. ";" .. ngx.var.http_cookie);
            return 
        end
    end
end

function _M.authorize(gosec_url)

end


-- from open.lua

local function is_admin(user, group_list)
    if user == ADMIN_USER then
        ngx.log(ngx.DEBUG, "[stratio-authz] user: " .. user .. " is admin - authorized ")
        return true
    end
    if type(group_list) == "table" then
        for _,group in ipairs(group_list) do
            if group == ADMIN_GROUP then
                ngx.log(ngx.DEBUG, "[stratio-authz] group: " .. group .. " is admin - authorized ")
                return true
            end
        end
    end
    return false
end

local function authorize_endpoint(user, group_list, action, uri)
    if is_admin(user, group_list)  then
        return true
    end
    if uri.match(uri, "%s+") then
        uri = uri:gsub("%s+","%%20")
    end
    if uri.match(uri,"ñ") then
        uri = uri:gsub("ñ","%%C3%%B1")
    end
    if uri.match(uri,"Ñ")  then
        uri = uri:gsub("Ñ","%%C3%%91")
    end
    if action == "DELETE" then
        action = "HTTPDELETE"
    end

    local cache_key = user.. "|" .. action .. "|" .. uri

    if _authz_cache.enabled then
        ngx.log(ngx.DEBUG, "[stratio-authz] Getting authz result from cache: " .. cache_key)
        local cache_value = _authz_cache.instance:get(cache_key)
        if cache_value ~= nil then
            if (cache_value == "true") then
                ngx.log(ngx.DEBUG, "[stratio-authz] Cache - Authorized " .. cache_key)
                return true
            else
                ngx.log(ngx.DEBUG, "[stratio-authz] Cache - Not authorized " .. cache_key)
                return false
            end
        end
    end

    local request_params = 'action='.. action.. '&service=Admin-Router&version='.. ADMIN_ROUTER_VERSION ..'&instance=Admin-Router&resourceType=url&value='..uri

    ngx.log(ngx.NOTICE, "Perform request: " .. gosec_authz_url .. "/" .. user .. "?"..request_params)
    local response_body = {}

    local res, code, response_headers = https.request
    {
        url = gosec_authz_url .. "/" .. user .. "?".. request_params,
        method = "GET",
        headers =
        {
            ["Content-Type"] = "application/json";
        },
        source = ltn12.source.string(request_body),
        sink = ltn12.sink.table(response_body),
        key="/opt/mesosphere/etc/pki/node.key",
        certificate="/opt/mesosphere/etc/pki/node.pem",
        cafile="/opt/mesosphere/etc/pki/ca-bundle.pem"
    }

    ngx.log(ngx.NOTICE, "Request result " .. code)

    if response_body[1] == "true" then
        ngx.log(ngx.DEBUG, "[stratio-authz] Authorized " .. user .. " Action:" .. action .. " Resource:" .. uri)
        if _authz_cache.enabled then
            _authz_cache.instance:set(cache_key, "true", _authz_cache.cache_ttl)
        end
        return true
    else
        ngx.log(ngx.DEBUG, "[stratio-authz] Not authorized " .. user .. " Action:" .. action .. " Resource:" .. uri)
        if _authz_cache.enabled then
            _authz_cache.instance:set(cache_key, "false", _authz_cache.cache_ttl)
        end
        return false
    end
end

return _M