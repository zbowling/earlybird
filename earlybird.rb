# TODO
#  switch to xauth
#    ask for u/p once, then save token (https://gist.github.com/304123/17685f51b5ecad341de9b58fb6113b4346a7e39f)

$KCODE = 'u'

%w[rubygems couchrest mongo digest/sha1 oauth/client/net_http net/https oauth/signature/plaintext pp net/http  twitter-text term/ansicolor twitter highline/import getoptlong tempfile open-uri json].each{|l| require l}

include Term::ANSIColor

class EarlyBird

  def initialize(consumer_token, consumer_secret, access_token, access_secret, filter, track, inreply)
    twoauth = Twitter::OAuth.new(consumer_token, consumer_secret)
    twoauth.authorize_from_access(access_token, access_secret)
    @client = Twitter::Base.new(twoauth)
    @friends = []
    @filter = filter
    @screen_name = @client.verify_credentials["screen_name"]
    puts "Welcome #{@screen_name}!"
    @track = Array(track) + Array(@screen_name)
    @icons = {}
    @inreply = inreply
  end

  def highlight(text)
    text.gsub("\r\n"," ").gsub("\n"," ").
      gsub(Twitter::Regex::REGEXEN[:extract_mentions], ' ' + cyan('@\2')).
      gsub(Twitter::Regex::REGEXEN[:auto_link_hashtags], ' ' + yellow('#\3'))
  end

  def search_highlight(text)
    highlight(text)
    @track.inject(text) do |newtext, term|
      newtext.gsub /#{term}/i do |match|
        green(match)
      end
    end
  end

  def fetch_icon_for_user(user)
    user_id = user['id'].to_i
    unless @icons.has_key?(user_id)
      Tempfile.open(user['screen_name']) do |file|
        file.print open(user['profile_image_url']).read
        @icons[user_id] = file.path
      end
    end
    @icons[user_id]
  end

  def growl_tweet(data)
    return unless $growl

    icon_path = fetch_icon_for_user(data['user'])
    Growl.notify(data['text'], :title => data['user']['screen_name'], :icon => icon_path)
  end

  def print_tweet(sn, text)
    print sn(sn) , ': ', highlight(text), "\n"
  end

  def print_search(sn, text)
    print sn(sn) , ': ', search_highlight(text), "\n"
  end

  def sn(sn)
    red(bold(sn))
  end

  def l(l)
    blue(bold(l))
  end

  def user_and_status(user_id, status_id)
    u = @client.user(user_id)
    s = @client.status(status_id)
    [u, s]
  rescue Twitter::General => e
    raise e unless e.message =~ /403/
  end
  
  def status_post(tweet,annotation)
    begin
      jsondata = annotation.to_json
      @client.update("#{tweet} #TANHF",:annotations=>jsondata)
    rescue Twitter::General => e
      print e
    end
  end

  # If it's an @reply but not to somebody you follow (or to you), then we drop it
  def passes_filter(data)
    # If it's sent by you, then it passes
    if data['user']['screen_name'] == @screen_name
      return true
    end

    in_reply_to = data['user']['in_reply_to_user_id']

    if in_reply_to
      # If it's sent to a friend of yours or to you then it passes
      @friends.include?(in_reply_to) or (data['user']['in_reply_to_screen_name'] == @screen_name)
    else
      # If it's not an @reply then it passes.
      true
    end
  end

  def print_tweet_from_data(data)
    if $filter
      if passes_filter(data)
        print_tweet(data['user']['screen_name'], data['text'])
        growl_tweet(data)
      end
    else
      print_tweet(data['user']['screen_name'], data['text'])
      growl_tweet(data)
    end
  end

  def print_retweet_from_data(data)
    print sn(data['user']['screen_name']), " retweeted: " + "\n\t"
    print_tweet(data['retweeted_status']['user']['screen_name'], data['retweeted_status']['text'])
    growl_tweet(data)
  end

  def process(data)
    if $couch_enabled
      @db = CouchRest.database!($couch)
      @db.save_doc(data)
    end
    if data['friends']
      # initial dump of friends
      @friends = data['friends']
      if $mongo_enabled
        $mdb["friends"].insert(data)
      end   
    elsif data['direct_message'] #dm
      if $mongo_enabled
        $mdb['direct_message'].insert(data)
      end
      print "direct message: \n\t"
      print_tweet(data['direct_message']['sender_screen_name'], data['direct_message']['text'])
    elsif data['text'] #tweet
      # If it's from a friend or from yourself, treat as a tweet.
      if data['retweeted_status']
      elsif (@friends.include?(data['user']['id']) or (data['user']['screen_name'] == @screen_name))
        if $mongo_enabled
          $mdb['tweet'].insert(data)
        end
        print_tweet_from_data(data)
        if @inreply #show in reply too tweets
          reply_status_id = data['in_reply_to_status_id']
          reply_user_id = data['in_reply_to_user_id']
          if reply_status_id 
            u, s = user_and_status(reply_user_id,reply_status_id)
            if u and s
              print "\t in reply to: "
              print_tweet(s.user.screen_name, s.text)
            end
          end
        end
      elsif not data['retweeted_status']
        print "search result: \n\t"
        if $mongo_enabled
          $mdb['tweet'].insert(data)
        end
        print_search(data['user']['screen_name'], data['text'])
      else
        #a retweet. ignore because we get that with the retweet event 
      end
    elsif data['event']
      if $mongo_enabled
        $mdb['event'].insert(data)
      end
      case data['event']
      when 'favorite', 'unfavorite', 'retweet'
        d = 'd'
        if data['event'] == 'retweet'
          d = 'ed'
        end
        print sn(data['source']['screen_name']), ' ', data['event'], d, "\n"
        print "\t"
        print_tweet(data['target_object']['user']['screen_name'], data['target_object']['text'])
      when 'unfollow', 'follow', 'block'
        s = data['source']
        t = data['target']
        print sn(s['screen_name']), ' ', data['event'], 'ed', ' ', sn(t['screen_name']), "\n"
      when 'list_member_added', 'list_member_removed'
        act = [' added ', ' to the ']
        if data['event'] == 'list_member_removed'
          act = [' removed ', ' from the ']
        end
        s = data['source']
        t = data['target']
        to = data['target_object']
        print sn(s['screen_name']), act[0], sn(t['screen_name']), act[1], l(to['name']), ' list', "\n"
      when 'list_destroyed', 'list_created', 'list_updated'
        act = ' destroyed the '
        if data['event'] == 'list_created'
          act = ' created the '
        elsif data['event'] == 'list_updated'
          act = ' updated the '
        end
        s = data['source']
        t = data['target']
        to = data['target_object']
        print sn(s['screen_name']), act, l(to['name']), ' list', "\n"
      else
        puts "unknown event: #{data['event']}"
        if $debug
          pp data
          puts '=========='
        end
      end
    elsif data['limit'] && data['limit']['track']
      puts bold("rate limited on track...")
    elsif data['delete']
      # ignore deletes
    else
      puts "unknown message: #{data['event']}"
      if $debug
        p data
        puts '=========='
      end
    end
  rescue Twitter::RateLimitExceeded
    puts "event dropped due to twitter rate limit (reset in #{@client.rate_limit_status['reset_time_in_seconds'] - Time.now} seconds)"
    p @client.rate_limit_status
  end

  def cleanup_icons
    @icons.each_value do |path|
      File.delete(path) rescue nil
    end
    @icons = {}
  end
end

class Hose
  KEEP_ALIVE  = /\A3[\r][\n][\n][\r][\n]/
  DECHUNKER   = /\A[0-F]+[\r][\n]/
  NEWLINE     = /[\n]/
  CRLF        = /[\r][\n]/
  EOF         = /[\r][\n]\Z/

  def unchunk(data)
    data.gsub(/\A[0-F]+[\r][\n]/, '')
  end

  def keep_alive?(data)
    data =~ KEEP_ALIVE
  end

  def extract_json(lines)
    # lines.map {|line| Yajl::Stream.parse(StringIO.new(line)).to_mash rescue nil }.compact
    lines.map {|line| JSON.parse(line).to_hash rescue nil }.compact
  end

  # filter determines whether you remove @replies from users you don't follow
  def run(consumer, token, host, path, debug=false, filter=false)
    if debug
      $stdin.each_line do |line|
        process(line)
      end
    else
      begin
        Net::HTTP.start(host) {|http|
          req = Net::HTTP::Get.new(path)
          req.oauth!(http,consumer,token)
          http.request(req) do |response|
            buffer = ''
            raise response.inspect unless response.code == '200'
            response.read_body do |data|
              unless keep_alive?(data)
                buffer << unchunk(data)

                if buffer =~ EOF
                  lines = buffer.split(CRLF)
                  buffer = ''
                else
                  lines = buffer.split(CRLF)
                  buffer = lines.pop
                end
                extract_json(lines).each {|line| yield(line)}
              end
            end
          end
        }
      rescue Errno::ECONNRESET, EOFError
        puts "disconnected from streaming api, reconnecting..."
        sleep 5
        retry
      end
    end
  end
end

trap("INT", "EXIT")

#user = ask("Enter your username:  ")
#pass = ask("Enter your password:  ") { |q| q.echo = '*' }

def usage
  puts "usage: earlybird.rb -c consumer_token -s consumer_secret -a access_token -S access_secret [-d] [-f] [-t key,words] [-u url] [-h host]"
  puts "options: "
  puts "  -c   --consumer_token   consumer token" 
  puts "  -s   --consumer_secret  consumer secret" 
  puts "  -a   --access_token     access token" 
  puts "  -S   --access_secret    access secret" 
  puts "  -r                      show in reply too (takes a lot of API requests)"
  puts "  -d                      debug mode, read json from stdin"
  puts "  -f                      filter out @replies from users you don't follow"
  puts "  -g                      growl notifications for new tweets"
  puts "  -t                      track keywords separated by commas."
  puts "  -u                      userstream path. Default: /2b/user.json"
  puts "  -h                      userstream hostname: Default: betastream.twitter.com"
  puts "  --couch                 enable couchdb logging. Default: http://127.0.0.1:5984/earlybird-test"
end

opts = GetoptLong.new(
      [ '--consumer-token','-c', GetoptLong::REQUIRED_ARGUMENT ],
      [ '--consumer-secret','-s', GetoptLong::REQUIRED_ARGUMENT ],
      [ '--access-token','-a', GetoptLong::REQUIRED_ARGUMENT ],
      [ '--access-secret','-S', GetoptLong::REQUIRED_ARGUMENT ],
      [ '--mongo', GetoptLong::OPTIONAL_ARGUMENT ],
      [ '--couch', GetoptLong::OPTIONAL_ARGUMENT ],
      [ '--help', GetoptLong::NO_ARGUMENT ],
      [ '-d', GetoptLong::OPTIONAL_ARGUMENT ],
      [ '-r', GetoptLong::OPTIONAL_ARGUMENT ],
      [ '-f', GetoptLong::OPTIONAL_ARGUMENT ],
      [ '-g', GetoptLong::OPTIONAL_ARGUMENT ],
      [ '-t', GetoptLong::OPTIONAL_ARGUMENT],
      [ '-h', GetoptLong::OPTIONAL_ARGUMENT]
    )

$debug = false
$filter = false
$growl = false
$inreply = false
$track = []
$url = '/2b/user.json'
$host = 'betastream.twitter.com'
$consumer_token = ''
$consumer_secret = ''
$ac_token = ''
$ac_secret = ''
$couch = ''
$mongo_enabled = false
$mongo = 'twitter'

opts.each do |opt, arg|
  case opt
  when '--help'
    usage
    exit 0
  when '-f'
    $filter = true
  when '-g'
    require 'growl'
    $growl = true
  when '-d'
    $debug = true
  when '-t'
    $track = arg.split(",")
  when '-u'
    $url = arg
  when '-h'
    $host = arg
  when '-r'
    require 'twitter'
    $inreply = true
  when '--consumer-token'
    $consumer_token = arg
  when '--consumer-secret'
    $consumer_secret = arg
  when '--access-token'
    $ac_token = arg
  when '--access-secret'
    $ac_secret = arg
  when '--couch'
    $couch_enabled = true
    $couch = arg
  when '--mongo'
    $mongo_enabled = true
    if not arg.empty?
      $mongo = arg
    end 
    $mdb = Mongo::Connection.new.db($mongo) 
  end
end

if $couch.empty?
  $couch = 'http://127.0.0.1:5984/earlybird-test'
end


unless $track.empty?
  puts "tracking term #{$track}"
  $url << "?track=" + CGI::escape($track.join(","))
end

puts "connecting to https://#{$host}#{$url}"

eb = EarlyBird.new($consumer_token, $consumer_secret, $ac_token, $ac_secret, $filter, $track, $inreply)
trap("EXIT") { eb.cleanup_icons }

consumer = OAuth::Consumer.new($consumer_token, $consumer_secret)
token = OAuth::Token.new($ac_token, $ac_secret)

Hose.new.run(consumer, token, $host, $url, $debug){|line| eb.process(line)}