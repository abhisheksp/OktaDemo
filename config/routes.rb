Rails.application.routes.draw do  
  root 'helloworld#index'
  get 'saml/init'
  post 'saml/consume'
end
