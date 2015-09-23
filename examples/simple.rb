Arachnid.new("https://www.whitehouse.gov", {
  :debug => true }).crawl(
    { :threads => 5,
      :max_urls => 1000}
    ) do |response|

    #"response" is just a Typhoeus response object.
    puts response.effective_url

    #You can retrieve the body of the page with response.body
    parsed_body = Nokogiri::HTML.parse(response.body)
end
