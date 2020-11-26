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
        
        ngx.log(ngx.STDERR, 'statio-cookie NOT FOUND in request')

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

        -- Add cookie to request
        ngx.req.set_header("Cookie", stratio_cookie_name .. "=" .. stratio_jwt .. ";" .. ngx.var.http_cookie);
    else
        ngx.log(ngx.STDERR, 'statio-cookie FOUND in request')

        -- Validate Stratio JWT
        local jwt_obj = jwt:verify(stratio_key, stratio_cookie, {
            lifetime_grace_period = 120,
            require_exp_claim = true,
            valid_issuers = { "stratio" }
        })

        if not jwt_obj["verified"] then
            
            ngx.log(ngx.STDERR, 'invalid jwt, generating a new one')
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

            local cookies, err = req_cookie:get_all()

            if not cookies then
                ngx.log(ngx.STDERR, 'Unexpected error getting the request cookies: ', err)
                return
            end

            local mycookiestr = ''
            for k, v in pairs(cookies) do
                if k == stratio_cookie_name then
                    v = stratio_jwt
                end
                mycookiestr = mycookiestr .. k .. "=" .. v .. ";"
            end
            -- Add cookies to request

            ngx.req.set_header("Cookie", stratio_cookie_name .. "=" .. stratio_jwt .. ";" .. mycookiestr);
        else
            ngx.log(ngx.STDERR, 'JWT VALID, moving on..')
            return 
        end
    end
end

function _M.authorize(gosec_url)

end

return _M