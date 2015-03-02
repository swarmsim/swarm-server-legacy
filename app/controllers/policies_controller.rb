require 'net/http'

class PoliciesController < ApplicationController
  skip_before_filter :verify_authenticity_token

  def new
    # no-op, this is just an input form for create
  end

  def create
    #render plain: params[:policy].inspect ; return
    #render plain: Rails.application.secrets.inspect ; return
    policy = params[:policy]
    # http://developers.kongregate.com/docs/kongregate-apis/authentication
    # https://stackoverflow.com/questions/4581075/how-make-a-http-get-request-using-ruby-on-rails
    url = URI.parse('https://api.kongregate.com/api/authenticate.json')
    url.query = URI.encode_www_form({
      :user_id => policy[:user_id],
      :game_auth_token => policy[:game_auth_token],
      :api_key => Rails.application.secrets.kongregate_api_key})
    #render plain: url ; return
    req = Net::HTTP::Get.new(url.to_s)
    res = Net::HTTP.start(url.host, url.port, :use_ssl => true) {|http|
      http.request(req)
    }
    body = JSON.parse res.body
    #render plain: body ; return
    if not body["success"]
      render plain: body.inspect ; return
    end
    # valid user! give them a policy document.
    # http://docs.aws.amazon.com/sdkforruby/api/index.html
    # use ENV['AWS_ACCESS_KEY_ID'] and ENV['AWS_SECRET_ACCESS_KEY'] and ENV['AWS_REGION']
    signer = Aws::S3::Presigner.new
    key = "saves/#{policy[:game_auth_token]}_#{policy[:user_id]}.json"
    expires_in = 1.day
    bucket = Rails.application.secrets.bucket
    policy = {
      :expiration => expires_in.from_now.utc.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
      :conditions => [
        {:bucket => bucket},
        {:key => key},
        {:acl => 'private'},
        {"Content-Type" => 'application/json'},
        ["content-length-range", 0, 8192]
      ]
    }
    #render plain: policy.inspect; return
    policy_json = JSON.generate(policy)
    #render plain: policy_json; return
    # https://aws.amazon.com/articles/1434
    policy_encoded = Base64.encode64(policy_json).gsub("\n","")
    signature = Base64.encode64(
        OpenSSL::HMAC.digest(
            OpenSSL::Digest::Digest.new('sha1'), 
            ENV['AWS_SECRET_ACCESS_KEY'], policy_encoded)
        ).gsub("\n","")
    #render plain: policy.inspect; return
    #render plain: signer.presigned_url(:put_object, bucket: bucket, key: key) ; return
    ret = {}
    ret[:get] = signer.presigned_url(:get_object, bucket: bucket, key: key, expires_in:expires_in)
    ret[:delete] = signer.presigned_url(:delete_object, bucket: bucket, key: key, expires_in:expires_in)
    ret[:post] = {
      :url => "https://#{bucket}.s3.amazonaws.com/",
      :params => {
        :key => key,
        :AWSAccessKeyId => ENV['AWS_ACCESS_KEY_ID'],
        :acl => 'private',
        :policy => policy_encoded,
        :signature => signature,
        "Content-type" => 'application/json',
      }
    }
    render json: ret ; return
  end
end
