# encoding: utf-8

require 'tempfile'
require 'typhoeus'
require 'bloomfilter-rb'
require 'nokogiri'
require 'domainatrix'
require 'addressable/uri'

class Arachnid

  def initialize(urls, options = {})
    @start_urls = urls.is_a?(Array) ? urls : [urls]
    @debug = options[:debug]
    @domain = Arachnid.parse_domain(@start_urls[0])
    @split_url_at_hash = options[:split_url_at_hash]
    @exclude_urls_with_hash = options[:exclude_urls_with_hash]
    @exclude_urls_with_extensions = options[:exclude_urls_with_extensions]
    @proxy_list = options[:proxy_list]
    @cookies_enabled = options[:enable_cookies]
  end

  def crawl(options = {})
    threads = options[:threads] || 1
    max_urls = options[:max_urls]
    crawl_filter = options[:filter]

    @hydra = Typhoeus::Hydra.new(:max_concurrency => threads)
    @global_visited = BloomFilter::Native.new(:size => 1000000, :hashes => 5, :seed => 1, :bucket => 8, :raise => true)
    @global_queue = []

    puts "ARACHNID DEBUG - adding #{@start_urls} to global queue" if @debug
    @global_queue.concat @start_urls

    while not @global_queue.empty?
      puts "ARACHNID DEBUG - global queue: #{@global_queue}" if @debug

      @global_queue.size.times do
        q = @global_queue.shift

        puts "ARACHNID DEBUG - max_urls: #{max_urls}"
        puts "ARACHNID DEBUG - global_visited: #{@global_visited.size}" if @debug
        puts "ARACHNID DEBUG - global_queue: #{@global_queue.size}" if @debug

        if !max_urls.nil? && @global_visited.size >= max_urls
          puts "ARACHNID DEBUG - DONE! VISITED (#{@global_visited.size}) > MAX_URLS (#{max_urls})"
          @global_queue = []
          break
        end

        next unless crawl_filter.call(q) if crawl_filter

        puts "ARACHNID DEBUG - Processing link: #{q}" if @debug
        @global_visited.insert(q)

        ip,port,user,pass = grab_proxy

        options = {timeout: 10000, followlocation:true}
        options[:proxy] = "#{ip}:#{port}" unless ip.nil?
        options[:proxy_username] = user unless user.nil?
        options[:proxy_password] = pass unless pass.nil?

        if @cookies_enabled
          cookie_file = Tempfile.new 'cookies'
          options[:cookiefile] = cookie_file
          options[:cookiejar] = cookie_file
        end

        request = Typhoeus::Request.new(q, options)

        request.on_complete do |response|
          next unless Arachnid.parse_domain(response.effective_url) == @domain

          yield response

          puts "ARACHNID DEBUG - page body: #{response.body}" if @debug

          puts "ARACHNID DEBUG - processing page links from #{response.effective_url}" if @debug
          elements = Nokogiri::HTML.parse(response.body).css('a')
          links = elements.map {|link| link.attribute('href').to_s}.uniq.sort.delete_if {|href| href.empty? }
          puts "ARACHNID DEBUG - links: #{links}" if @debug

          links.each do |link|
            next if link.match(/^\(|^javascript:|^mailto:|^#|^\s*$|^about:/)
            begin

              absolute_link = make_absolute(split_url_at_hash(link), response.effective_url)

              puts "ARACHNID DEBUG - got link: #{link}" if @debug
              puts "ARACHNID DEBUG - absolute link: #{absolute_link}" if @debug
              puts "ARACHNID DEBUG - internal link? #{internal_link?(link, response.effective_url)}" if @debug
              puts "ARACHNID DEBUG - no hash? #{no_hash_in_url?(absolute_link)}" if @debug
              puts "ARACHNID DEBUG - extension not ignored? #{extension_not_ignored?(absolute_link)}" if @debug
              puts "ARACHNID DEBUG - visited? #{@global_visited.include?(absolute_link)}" if @debug

              if internal_link?(link, response.effective_url) &&
                !@global_visited.include?(absolute_link) && no_hash_in_url?(absolute_link) && extension_not_ignored?(link)

                puts "ARACHNID DEBUG - Got one! -> #{absolute_link}" if @debug

                unless @global_queue.include?(absolute_link)
                  puts "ARACHNID DEBUG - Adding to global_queue: #{absolute_link}" if @debug
                  @global_queue << absolute_link
                end
              end
            rescue Addressable::URI::InvalidURIError => e
              puts "ARACHNID DEBUG - #{e.class}: Ignored link #{link} (#{e.message}) on page #{q}" if @debug
            end
          end
          puts "ARACHNID DEBUG - @global_queue: #{@global_queue}" if @debug
        end

        @hydra.queue request
      end

      puts "ARACHNID DEBUG - running the hydra" if @debug
      @hydra.run
    end

  end

  def grab_proxy
    return nil unless @proxy_list

    @proxy_list.sample.split(':')
  end

  def self.parse_domain(url)
    parsed_domain = Domainatrix.parse(url)

    if(parsed_domain.subdomain != "")
      parsed_domain.subdomain + '.' + parsed_domain.domain + '.' + parsed_domain.public_suffix
    else
      parsed_domain.domain + '.' + parsed_domain.public_suffix
    end
  end

  def internal_link?(url, effective_url)
    absolute_url = make_absolute(url, effective_url)
    parsed_url = Arachnid.parse_domain(absolute_url)
    @domain == parsed_url
  end

  def split_url_at_hash(url)
    return url unless @split_url_at_hash

    url.split('#')[0]
  end

  def no_hash_in_url?(url)
    !@exclude_urls_with_hash || url.scan(/#/).empty?
  end

  def extension_not_ignored?(url)
    return true if url.empty?
    return true unless @exclude_urls_with_extensions

    @exclude_urls_with_extensions.find { |e| url.downcase.end_with? e.downcase }.nil?
  end

  def make_absolute(href, root)
    Addressable::URI.parse(root).join(Addressable::URI.parse(href)).to_s
  end

end
