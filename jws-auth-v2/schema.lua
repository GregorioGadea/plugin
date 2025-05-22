-- kong/plugins/jws-auth-v2/schema.lua

return {
  name = "jws-auth-v2",
  fields = {
    {
      config = {
        type = "record",
        fields = {
          { jwks_uri = { type = "string", required = true, description = "URL do JWKS" } },
          { kid = { type = "string", required = true, description = "Key ID (kid) usada para buscar a JWK no JWKS" } },
          { private_key = { type = "string", required = true, description = "Chave privada RSA em PEM usada para assinar o JWS" } },
          {
            applications = {
              type = "map",
              required = true,
              keys = { type = "string" },
              values = {
                type = "record",
                fields = {
                  { jws_enabled = { type = "boolean", default = false } }
                }
              },
              description = "Mapa de aplicações com permissão para uso de JWS"
            }
          }
        }
      }
    }
  }
}