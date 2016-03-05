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
    settings = idp_metadata_parser.parse(ENV['OKTA_METADATA'])
    settings.assertion_consumer_service_url = "http://localhost:3000/saml/consume"
    settings.issuer = 'http://localhost:3000/saml/consume'
    settings
  end
end
