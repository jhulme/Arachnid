# encoding: utf-8

require 'tempfile'
require 'typhoeus'
require 'bloomfilter-rb'
require 'nokogiri'
require 'domainatrix'
require 'addressable/uri'

class Arachnid

  attr_accessor :crawl_log

  def initialize(urls, options = {})
    @start_urls = urls.is_a?(Array) ? urls : [urls]
    @domain = Arachnid.parse_domain(@start_urls[0])
    @split_url_at_hash = options[:split_url_at_hash]
    @exclude_urls_with_hash = options[:exclude_urls_with_hash]
    @exclude_urls_with_extensions = options[:exclude_urls_with_extensions]
    @proxy_list = options[:proxy_list]
    @cookies_enabled = options[:enable_cookies]
    @crawl_log = []
  end

  def crawl(options = {})
    threads = options[:threads] || 1
    max_urls = options[:max_urls] || 10
    crawl_filter = options[:filter]

    @hydra = Typhoeus::Hydra.new(:max_concurrency => threads)
    @global_visited = BloomFilter::Native.new(:size => 1000000, :hashes => 5, :seed => 1, :bucket => 8, :raise => true)
    @global_queue = []

    @crawl_log << "ARACHNID adding #{@start_urls} to global queue"
    @global_queue.concat @start_urls

    while not @global_queue.empty?
      #@crawl_log << "ARACHNID global queue: #{@global_queue}"

      @crawl_log << "ARACHNID max_urls: #{max_urls}"
      @crawl_log << "ARACHNID global_visited: #{@global_visited.size}"
      @crawl_log << "ARACHNID global_queue: #{@global_queue.size}"

      @global_queue.size.times do
        q = @global_queue.shift

        if !max_urls.nil? && @global_visited.size >= max_urls
          @crawl_log << "ARACHNID DONE! VISITED (#{@global_visited.size}) > MAX_URLS (#{max_urls})"
          @global_queue = []
          break
        end

        next unless crawl_filter.call(q) if crawl_filter

        #@crawl_log << "ARACHNID Processing link: #{q}"
        @global_visited.insert(q)

        # Set default options
        options = {
          timeout: 10000,
          followlocation:true
        }

        # Configure Proxy
        ip,port,user,pass = grab_proxy
        options[:proxy] = "#{ip}:#{port}" unless ip.nil?
        options[:proxy_username] = user unless user.nil?
        options[:proxy_password] = pass unless pass.nil?

        # Configure cookie
        if @cookies_enabled
          cookie_file = Tempfile.new 'cookies'
          options[:cookiefile] = cookie_file
          options[:cookiejar] = cookie_file
        end

        request = Typhoeus::Request.new(q, options)

        request.on_complete do |response|
          #@crawl_log << "ARACHNID Completed request for: #{response.effective_url}"
          #@crawl_log << "ARACHNID effective domain: #{Arachnid.parse_domain(response.effective_url)}"
          # Note that this will match subdomains as well.
          next unless Arachnid.parse_domain(response.effective_url).include? @domain

          #yield response

          # Parse the page and pull out internal links
          #@crawl_log << "ARACHNID page body: #{response.body}"
          @crawl_log << "ARACHNID Processing page links from #{response.effective_url}"
          elements = Nokogiri::HTML.parse(response.body).css('a')
          links = elements.map {|link| link.attribute('href').to_s}.uniq.sort.delete_if {|href| href.empty? }
          #@crawl_log << "ARACHNID links: #{links}"
          links.each do |link|
            next if link.match(/^\(|^javascript:|^mailto:|^#|^\s*$|^about:/)
            begin

              absolute_link = make_absolute(split_url_at_hash(link), response.effective_url)

              #@crawl_log << "ARACHNID got link: #{link}"
              #@crawl_log << "ARACHNID absolute link: #{absolute_link}"
              #@crawl_log << "ARACHNID internal link? #{internal_link?(link, response.effective_url)}"
              #@crawl_log << "ARACHNID no hash? #{no_hash_in_url?(absolute_link)}"
              #@crawl_log << "ARACHNID extension not ignored? #{extension_not_ignored?(absolute_link)}"
              #@crawl_log << "ARACHNID visited? #{@global_visited.include?(absolute_link)}"

              if internal_link?(link, response.effective_url) &&
                !@global_visited.include?(absolute_link) && no_hash_in_url?(absolute_link) && extension_not_ignored?(link)
                #@crawl_log << "ARACHNID Got one! -> #{absolute_link}"
                unless @global_queue.include?(absolute_link)
                  #@crawl_log << "ARACHNID Adding to global_queue: #{absolute_link}"
                  @global_queue << absolute_link
                end
              end

            rescue Addressable::URI::InvalidURIError => e
              #@crawl_log << "ARACHNID #{e.class}: Ignored link #{link} (#{e.message}) on page #{q}"
            end
          end
          #@crawl_log << "ARACHNID @global_queue: #{@global_queue}"
        end
        @crawl_log << "ARACHNID Global queue size: #{@global_queue.size}"
        @crawl_log << "ARACHNID Global visited queue size: #{@global_visited.size}"
        @hydra.queue request
      end

      @crawl_log << "ARACHNID Running the hydra"
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
    parsed_url.include? @domain
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


#x = Arachnid.new("http://yahoo.com",{:debug => true})
#x.crawl
#puts x.crawl_log.join("\n")
