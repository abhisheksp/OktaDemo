class HelloworldController < ApplicationController
	def index
		render :text => "Hello World!"
	end
end