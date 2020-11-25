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

    local jwt = require "resty.jwt"

    -- Evaluate cert

    if ngx.var.ssl_client_s_dn then
        ngx.log(ngx.STDERR, '[STG] create_cookie - ssl_client_s_dn defined [END]')

        local cert_cn = string.match(ngx.var.ssl_client_s_dn, "CN=([^,]+)")
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
                    cn = cert_cn,
                    --groups = userinfo["groups"],
                    uid = cert_cn
                }
            }
        )

        ngx.req.set_header("Cookie", stratio_cookie_name .. "=" .. stratio_jwt .. ";" .. ngx.var.http_cookie);

        return
    end
    
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
            --return 
        end
    end
end

function _M.authorize(gosec_url)

end

local function getCertCN(cert)
    ngx.log(ngx.DEBUG, "[stratio-tls] Client certificate is:" .. ngx.var.certificate_client_dn)

    uid, groups, err = authcommon.validate_jwt(SECRET_KEY)  
    if err ~= nil then

    end

    ngx.log(ngx.DEBUG, "[stratio-tls] UID is:" .. uid)
end

return _M
