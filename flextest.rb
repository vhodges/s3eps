require 'aws/s3'
require 'pp'

AWS::S3::Base.establish_connection!(
                                    :access_key_id => "<Your S3 key>",
                                    :secret_access_key => "<Your s3 secret> ",
                                    :server => "<Server s3 eps is running on>",
                                    :port => "8080"
                                    )

# File sizes (boundries)
files = [
#         0,
         1,
         15,
         16,
         17,
         32,
         48,
         64,
         80,
         2389
        ]

files.each do |file_size|
  file = Array.new(file_size) {|i| i % 10}.join("")

  puts "Uploading #{file_size}.txt ..."
  AWS::S3::S3Object.store("#{file_size}.txt", StringIO.new(file), "contractually-vhodges-userphotos")

  puts "Downloading #{file_size}.txt ..."
  dl_file = AWS::S3::S3Object.value "#{file_size}.txt", "contractually-vhodges-userphotos"

  puts "Compare: #{ (file.eql?(dl_file) ) ? "SUCCESS" : "FAIL" }"

  sleep(0.5)
end
