class SamlController < ApplicationController
  skip_before_action :verify_authenticity_token
  def init
    request = OneLogin::RubySaml::Authrequest.new
    redirect_to(request.create(saml_settings))
  end

  def consume
    response = OneLogin::RubySaml::Response.new(params[:SAMLResponse])
    request = OneLogin::RubySaml::Authrequest.new
    response.settings = saml_settings
    if response.is_valid?
      session[:authorized] = true
      redirect_to root_path
    else
      redirect_to(request.create(saml_settings))
    end
  end

  private
  def saml_settings
    idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
    settings = idp_metadata_parser.parse(idp_metadata)
    settings.assertion_consumer_service_url = "http://localhost:3000/saml/consume"
    settings.issuer = 'http://localhost:3000/saml/consume'
    settings
  end

  def idp_metadata
    '<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://www.okta.com/exk5vvy4p1YA3gyPI0h7"><md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAVMEnmvMMA0GCSqGSIb3DQEBBQUAMIGSMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi03MzI0OTQxHDAaBgkqhkiG9w0BCQEWDWluZm9Ab2t0YS5jb20wHhcNMTYwMjIxMTYxNTQ0WhcNMjYwMjIxMTYxNjQ0WjCBkjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtNzMyNDk0MRwwGgYJKoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAja/UFn98FW5EUjCgL+NheLOqI3YLvlsE3OROoMWLQJJTeDkOyq1+aBe5VPzwekxwFc2NotD/0n/yXCr1FMZ6n5WBMSwl8AXBmpJZfJc38mO3hVX0gpcXmSYWNSb1JVP6UavMX6YcCQoxJkoLOhDC77IGvc6w2cIXYpTkqsMpgpf5doNbAqzlKm4qAOxuY4XMJiA85NtSCfWGCfSDvAzplVOWudLcLe5v6lrsQtIJEy/Uj/AAs2EeZ/FEn72/hxu5GDTHJ/j6uScGhPcRDSRSmeGXAmrUGbDVgf5AuPnmjCsV3ghHs0Ak+ThbmRn4vdYapP0OVxYZ9PA7CUOiIb7W7wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQAT09jq8uba2vvjTmH6fJ5G/oT/4SaQ9aTMnCh18nC0XlFA4MDEGMZzcwaWR4pFn5/iAh8vBcuoEr0+QnIdbXOqOlHf8plSMTA+zLeCa0COXLPjO+nU35p0KZiJdCHKJ/ohwJ50FASZeGigXTXk29YqyEWFZjaCeHjoZ1jufaNtQa3tPqS4rSM2d38kKrX7RPIBGFTn3Xk3GZL4vNigGKLOoOyzaAzskr7cjGaI2FaqEV7hmiJDV2bLZgRiE/0hNbtkmaIDRO4n0yllnwBnop3dMKJmVY1XqKHc4hJR5bQTMCiVpwIuMWH55fG2uFOYAZ7uRRMYJRPtAWequk+U71Sr</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://dev-732494.oktapreview.com/app/thoughtworksdev732494_oktademo_1/exk5vvy4p1YA3gyPI0h7/sso/saml"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://dev-732494.oktapreview.com/app/thoughtworksdev732494_oktademo_1/exk5vvy4p1YA3gyPI0h7/sso/saml"/></md:IDPSSODescriptor></md:EntityDescriptor>'
  end
end
