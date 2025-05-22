-- kong/plugins/jws-auth-v2/handler.lua

local cjson        = require "cjson.safe"
local http         = require "resty.http"
local jwt          = require "resty.jwt"
local ngx_re_gsub  = ngx.re.gsub
local ngx_encode_base64 = ngx.encode_base64
local ngx_sha256   = ngx.sha256_bin
local kong         = kong

local JwsAuthHandler = {
  PRIORITY = 1000,
  VERSION  = "1.0.0",
}

function JwsAuthHandler:access(conf)
  -- 1) Verifica consumidor
  local consumer = kong.client.get_consumer()
  if not consumer then
    return kong.response.exit(403, { message = "Consumidor não identificado" })
  end

  local app_config = conf.applications[consumer.id]
  if not app_config or not app_config.jws_enabled then
    return kong.response.exit(403, { message = "JWS não habilitado para esta aplicação" })
  end

  -- 2) Pega body e limpa whitespace
  local body, err = kong.request.get_raw_body()
  if err then
    return kong.response.exit(400, { message = "Erro ao ler o corpo da requisição" })
  end
  local cleaned_body = ngx_re_gsub(body, [[[\s\t\r\n]+]], "", "jo")

  -- 3) Calcula digest
  local digest = ngx_encode_base64(ngx_sha256(cleaned_body))

  -- 4) Busca JWKS
  local httpc = http.new()
  local res, jwk_err = httpc:request_uri(conf.jwks_uri, { method = "GET" })
  if not res or res.status ~= 200 then
    return kong.response.exit(500, { message = "Erro ao obter JWKS" })
  end

  local jwks = cjson.decode(res.body)
  if not jwks or not jwks.keys then
    return kong.response.exit(500, { message = "Formato inválido do JWKS" })
  end

  -- 5) Encontra a chave certa
  local chosen = nil
  for _, key in ipairs(jwks.keys) do
    if key.kid == conf.kid then
      chosen = key
      break
    end
  end
  if not chosen then
    return kong.response.exit(400, { message = "Chave JWK não encontrada" })
  end

  -- 6) Gera o token JWS
  local private_key = conf.private_key
  if not private_key then
    return kong.response.exit(500, { message = "Chave privada não configurada" })
  end
  local token_obj = jwt:sign(
    private_key,
    {
      header  = { alg = "RS256", typ = "JWT", kid = chosen.kid },
      payload = { digest = digest },
    }
  )
  if not token_obj or not token_obj.token then
    return kong.response.exit(500, { message = "Erro ao gerar o JWS" })
  end

  -- 7) Injeta o header e segue
  kong.service.request.set_header("custom.header.x_itau_msg_sign", token_obj.token)
end

return JwsAuthHandler
