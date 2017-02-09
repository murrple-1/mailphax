require 'sinatra'
require 'phaxio'
require 'mail'
require 'pony'
require 'tempfile'
require 'openssl'
require 'to_regexp'
require 'thread'
# require 'tinnef'

if not ENV['PHAXIO_KEY'] or not ENV['PHAXIO_SECRET'] or not ENV['MAILGUN_KEY']
  raise "You must specify the required environment variables"
end

get '/' do
  "MailPhax v1.0 - Visit a mail endpoint: (/mailgun)"
end

get '/mailgun' do
  [400, "Mailgun supported, but callbacks must be POSTs"]
end

$_recipient_whitelist = nil

def get_recipient_whitelist
  if $_recipient_whitelist.nil?
    if ENV['RECIPIENT_WHITELIST_FILE']
      $_recipient_whitelist = File.read(ENV['RECIPIENT_WHITELIST_FILE']).split
    end
  end
  return $_recipient_whitelist
end

$_sender_whitelist = nil

def get_sender_whitelist
  if $_sender_whitelist.nil?
    if ENV['SENDER_WHITELIST_FILE']
      $_sender_whitelist = File.read(ENV['SENDER_WHITELIST_FILE']).split
    end
  end
  return $_sender_whitelist
end

$_body_regex = nil

def get_body_regex
  if $_body_regex.nil?
    if ENV['BODY_REGEX']
      $_body_regex = ENV['BODY_REGEX'].to_regexp
    end
  end
  return $_body_regex
end

def verify_mailgun(apiKey, token, timestamp, signature)
  calculated_signature = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, apiKey, [timestamp, token].join)
  signature == calculated_signature
end

$_mailgun_token_cache = []
MAILGUN_TOKEN_CACHE_MAX_LENGTH = 50
TIMESTAMP_THRESHOLD_SECONDS = 30.0

post '/mailgun' do
  sender = params['sender']
  if not sender
    return _log_and_response(400, "Must include a sender", logger)
  end

  sender_whitelist = get_sender_whitelist
  if not sender_whitelist.nil? and not sender_whitelist.include? sender
    return _log_and_response(401, "sender blocked", logger)
  end

  recipient = params['recipient']
  if not recipient
    return _log_and_response(400, "Must include a recipient", logger)
  end

  recipient_whitelist = get_recipient_whitelist
  if not recipient_whitelist.nil? and not recipient_whitelist.include? recipient
    return _log_and_response(401, "recipient blocked", logger)
  end

  token = params['token']
  if not token
    return _log_and_response(400, "Must include a token", logger)
  end

  signature = params['signature']
  if not signature
    return _log_and_response(400, "Must include a signature", logger)
  end

  timestamp = params['timestamp']
  if not timestamp
    return _log_and_response(400, "Must include a timestamp", logger)
  end

  if $_mailgun_token_cache.include?(token)
    return _log_and_response(400, "duplicate token", logger)
  end

  $_mailgun_token_cache.push(token)
  while $_mailgun_token_cache.length > MAILGUN_TOKEN_CACHE_MAX_LENGTH
    $_mailgun_token_cache.pop
  end

  timestamp_seconds = timestamp.to_f
  now_seconds = Time.now.to_f
  if (timestamp_seconds - now_seconds).abs > TIMESTAMP_THRESHOLD_SECONDS
    return _log_and_response(400, "timestamp unsafe", logger)
  end

  if not verify_mailgun(ENV['MAILGUN_KEY'], token, timestamp, signature)
    return _log_and_response(400, "signature does not verify", logger)
  end

  attachment_files = []

  attachment_count = params['attachment-count'].to_i
  (1...(attachment_count + 1)).each do |i|
    filename = params["attachment-#{i}"][:filename]
    data = params["attachment-#{i}"][:tempfile].read

    filenames, datas = acceptable_data(filename, data)

    if filenames.nil? || datas.nil?
      return _log_and_response(401, "attachment type not accepted", logger)
    end

    filenames.each_index do |j|
      t_file = Tempfile.new(['', filenames[j]])
      t_file.write(datas[j])
      t_file.close

      # use the whole file to ensure GC cannot release it yet
      attachment_files.push(t_file)
    end
  end

  if params['body-plain']
    data = params['body-plain']
    body_regex = get_body_regex
    if body_regex.nil? || body_regex.match(data)
      t_file = Tempfile.new(['', 'email-body.txt'])
      t_file.write(data)
      t_file.close

      # use the whole file to ensure GC cannot release it yet
      attachment_files.push(t_file)
    else
      return _log_and_response(401, "body not accepted", logger)
    end
  end

  send_fax(sender, recipient, attachment_files)

  attachment_files.each do |attachment_file|
    begin
      attachment_file.unlink
    rescue
      # do nothing
    end
  end

  [200, "OK"]
end

# via https://www.phaxio.com/faq#11
ACCEPTED_FILENAME_REGEXES = [/\.doc$/i, /\.docx$/i, /\.pdf$/i, /\.tif$/i, /\.jpg$/i, /\.jpeg$/i, /\.odt$/i, /\.txt$/i, /\.html$/i, /\.png$/i]

def acceptable_data(filename, data)
  ACCEPTED_FILENAME_REGEXES.each do |regex|
    if regex.match(filename)
      return [filename], [data]
    end
  end

  if /^winmail\.dat$/.match(filename)
    # converted_filenames = []
    # converted_data = []
    # temp = TNEF.convert(data) do |temp_file|
    #   _filename = File.basename(temp_file.path)
    #   _data = temp_file.read

    #   _filenames, _datas = acceptable_data(_filename, _data)

    #   _filenames.each_index do |i|
    #     converted_filenames.push(_filenames[i])
    #     converted_data.push(_datas[i])
    #   end
    # end

    # return converted_filenames, converted_data
    return [], []
  end

  return nil, nil
end

def _log_and_response(response_code, message, logger)
  logger.info(message)
  return [response_code, message]
end

$_fax_mutex = Mutex.new

def send_fax(from_email, to_email, attachment_files)
  Phaxio.config do |config|
    config.api_key = ENV["PHAXIO_KEY"]
    config.api_secret = ENV["PHAXIO_SECRET"]
  end

  number = Mail::Address.new(to_email).local

  options = {to: number, callback_url: "mailto:#{from_email}" }

  attachment_files.each_index do |idx|
    options["filename[#{idx}]"] = File.new(attachment_files[idx].path)
  end

  result = nil
  $_fax_mutex.synchronize do
    logger.info("#{from_email} is attempting to send #{attachment_files.length} files to #{number}...")
    result = Phaxio.send_fax(options)
    sleep 2
  end

  result = JSON.parse(result.body)

  if result['success']
    logger.info("Fax queued up successfully: ID #" + result['data']['faxId'].to_s)
  else
    logger.warn("Problem submitting fax: " + result['message'])

    if ENV['SMTP_HOST']
      #send mail back to the user telling them there was a problem

      Pony.mail(
        :to => from_email,
        :from => (ENV['SMTP_FROM'] || 'mailphax@example.com'),
        :subject => 'Mailfax: There was a problem sending your fax',
        :body => "There was a problem faxing your #{attachment_files.length} files to #{number}: " + result['message'],
        :via => :smtp,
        :via_options => {
          :address                => ENV['SMTP_HOST'],
          :port                   => (ENV['SMTP_PORT'] || 25),
          :enable_starttls_auto   => ENV['SMTP_TLS'],
          :user_name              => ENV['SMTP_USER'],
          :password               => ENV['SMTP_PASSWORD'],
          :authentication         => :login
        }
      )
    end
  end
end
