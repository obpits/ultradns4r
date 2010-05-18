#!/usr/bin/ruby -W0
#
# ultradns4r - Ruby library and command line client for Neustar UltraDNS SOAP API
#
# Author: Michael Conigliaro <mike [at] conigliaro [dot] org>
#

require 'logger'
require 'optparse'
require 'pp'
require 'socket'
require 'rubygems'
require 'savon'

module UltraDns

  class Client

    attr_reader :soap_error

    # constructor
    def initialize(username, password)
      wsdl = 'https://ultra-api.ultradns.com/UltraDNS_WS?wsdl'
      @soap_client = soap_client = Savon::Client.new(wsdl)
      @soap_namespaces = {
        'xmlns:wsdl' => 'http://webservice.api.ultra.neustar.com/',
        'xmlns:sch'  => 'http://schema.ultraservice.neustar.com/'
      }
      @wsse_header = {
        'wsse:Security' => {
          'wsse:UsernameToken' => {
            'wsse:Username' => username,
            'wsse:Password' => password,
            'wsse:Nonce' => Digest::SHA1.hexdigest(String.random + Time.now.to_i.to_s),
            'wsu:Created' => Time.now.strftime(Savon::SOAP::DateTimeFormat),
            :attributes! => {
              'wsse:Password' => {
                'Type' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText'
              }
            },
            :order! => [
              'wsse:Username',
              'wsse:Password',
              'wsse:Nonce',
              'wsu:Created'
            ]
          },
          :attributes! => {
            'wsse:UsernameToken' => {
              'wsu:Id' => 'UsernameToken-1',
              'xmlns:wsu' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'
            }
          }
        },
        :attributes! => {
          'wsse:Security' => {
            'xmlns:wsse' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
          }
        }
      }.to_soap_xml
    end

    # do soap call
    def soap_call(method, args = {})
      @soap_error = nil

      response = @soap_client.send(method.to_sym) do |soap|
        soap.namespaces.merge!(@soap_namespaces)
        soap.header = @wsse_header

        # map method name to soap call name when necessary
        case method
          when /get_resource_records_of_dname_by_type!?/
            soap.action = 'getResourceRecordsOfDNameByType'
            soap.input = 'getResourceRecordsOfDNameByType'
        end

        soap.body = args
      end

      # save errors
      if !Savon::Response.raise_errors?
        if response.soap_fault?
          if response.to_hash[:fault][:detail]
            @soap_error = '%s (Fault code: %d)' % [response.to_hash[:fault][:detail][:ultra_ws_exception][:error_description],
                                     response.to_hash[:fault][:detail][:ultra_ws_exception][:error_code]]
          else
            @soap_error = '%s' % response.to_hash[:fault][:faultstring]
          end
        elsif response.http_error?
          @soap_error = response.http_error
        end
      end

      return response
    end

    # return the id of the specified record type
    def self.get_rr_type_id(rr_type)
      return {
        'A'        => 1,
        'AAAA'     => 28,
        'AFSDB'    => 18,
        'ALL3'     => 0,
        'ANY'      => 255,
        'AXFR'     => 252,
        'CNAME'    => 5,
        'EID'      => 31,
        'GID'      => 102,
        'GPOS'     => 27,
        'HINFO'    => 13,
        'ISDN'     => 20,
        'KEY'      => 25,
        'LOC'      => 29,
        'MAILA'    => 253,
        'MAILB'    => 254,
        'MB'       => 7,
        'MD'       => 3,
        'MF'       => 4,
        'MG'       => 8,
        'MINFO'    => 14,
        'MX'       => 15,
        'NAPTR'    => 35,
        'NIMLOC'   => 32,
        'NULL'     => 10,
        'NS'       => 2,
        'NSAP'     => 22,
        'NSAP-PTR' => 23,
        'NXT'      => 30,
        'PTR'      => 12,
        'PX'       => 26,
        'RP'       => 17,
        'RT'       => 21,
        'SIG'      => 24,
        'SOA'      => 6,
        'SRV'      => 33,
        'SSHFP'    => 44,
        'TXT'      => 16,
        'UID'      => 101,
        'UINFO'    => 100,
        'WKS'      => 11,
        'X25'      => 19
      }[rr_type.upcase]
    end

  end

end

# command line client
if __FILE__ == $0

  # set default command line options
  options = {
    :cred_file => File.expand_path('~/ultradns4r.secret'),
    :username  => nil,
    :password  => nil,
    :zone      => nil,
    :rrname    => Socket.gethostbyname(Socket.gethostname).first + '.',
    :rrttl     => 86400,
    :rrtype    => 'A',
    :rrdata    => nil,
    :log_level => 'warn'
  }

  # parse command line options
  OptionParser.new do |opts|
    opts.banner = "Usage: #{$0} [OPTIONS] RR-DATA[, ...]\nExample: #{$0} -n srv.example.org. -t SRV 0 10 20 target.example.org."

    opts.on('-c', '--credentials-file VALUE', 'Path to file containing API username/password (default: %s)' % options[:cred_file]) do |c|
      options[:cred_file] = c
    end

    opts.on('-z', '--zone VALUE', 'DNS Zone (default: Auto-detect)') do |z|
      options[:zone] = z
    end

    opts.on('-n', '--rr-name VALUE', 'DNS record name (default: %s)' % options[:rrname]) do |n|
      options[:rrname] = n
    end

    opts.on('-s', '--rr-ttl VALUE', 'DNS record TTL (default: %s)' % options[:rrttl]) do |s|
      options[:rrttl] = s
    end

    opts.on('-t', '--rr-type VALUE', 'DNS record type (default: %s)' % options[:rrtype]) do |t|
      options[:rrtype] = t
    end

    opts.on('-v', '--verbosity VALUE', 'Log verbosity (default: %s)' % options[:log_level]) do |v|
      options[:log_level] = v
    end

    opts.on('--dry-run', "Perform a trial run without making changes") do |d|
      options[:dry_run] = d
    end
  end.parse!

  # instantiate logger
  log = Logger.new(STDOUT)
  Savon::Request.logger = log
  log.level = eval('Logger::' + options[:log_level].upcase)

  # disable savon exceptions so we can access the error descriptions
  Savon::Response.raise_errors = false

  # validate command line options
  begin
    (options[:username], options[:password]) = File.open(options[:cred_file]).readline().strip().split()
  rescue Errno::ENOENT
    log.error('Credentials file does not exist: %s' % options[:cred_file])
    Process.exit(1)
  end
  if !UltraDns::Client.get_rr_type_id(options[:rrtype])
    log.error('"%s" is not a supported record type' % options[:rrtype])
    Process.exit(1)
  end
  if !options[:zone]
    options[:zone] = options[:rrname][(options[:rrname].index('.') + 1)..-1]
  end
  if ARGV.size > 0
    options[:rrdata] = ARGV.join(' ').split(',')
  else
    log.error('No rr-data specified')
    Process.exit(1)
  end

  # instantiate ultradns client
  c = UltraDns::Client.new(options[:username], options[:password])

  # check if zone exists
  response = c.soap_call('get_zone_info!', {'zoneName' => options[:zone]})
  if c.soap_error
    log.error('Unable to obtain info for zone "%s" - %s' % [options[:zone], c.soap_error])
    Process.exit(1)
  end

  # get transaction id
  if not options[:dry_run]
    response = c.soap_call('start_transaction!')
    if c.soap_error
      log.error('Unable to get transaction ID - %s' % c.soap_error)
      Process.exit(1)
    else
      transaction_id = response.to_hash[:start_transaction_response][:transaction_id]
      log.info('Got transaction ID "%s"' % transaction_id)
    end
  end

  # query for existing records
  response = c.soap_call('get_resource_records_of_dname_by_type!',
    {'zoneName' => options[:zone], 'hostName' => options[:rrname], 'rrType' => UltraDns::Client.get_rr_type_id(options[:rrtype])})
  if c.soap_error
    log.error('Query for existing records failed - %s' % c.soap_error)
  else

    # make sure we're always dealing with an array of resource records
    resource_records = []
    if response.to_hash[:get_resource_records_of_d_name_by_type_response][:resource_record_list][:resource_record]
      if response.to_hash[:get_resource_records_of_d_name_by_type_response][:resource_record_list][:resource_record].type == Hash
        resource_records[0] = response.to_hash[:get_resource_records_of_d_name_by_type_response][:resource_record_list][:resource_record]
      elsif response.to_hash[:get_resource_records_of_d_name_by_type_response][:resource_record_list][:resource_record].type == Array
        resource_records = response.to_hash[:get_resource_records_of_d_name_by_type_response][:resource_record_list][:resource_record]
      end
    end

    # delete existing records
    resource_records.each do |rr|
      if options[:dry_run]
        log.warn('Will delete record (Name="%s" Type="%s" Target="%s", GUID="%s")' %
          [rr[:d_name], options[:rrtype], rr[:info_values][:info1_value], rr[:guid]])
      else
        c.soap_call('delete_resource_record!', {'transactionID' => transaction_id, 'guid' => rr[:guid]})
        if c.soap_error
          log.warn('Failed to delete record (Name="%s" Type="%s" Target="%s", GUID="%s") - %s' %
            [rr[:d_name], options[:rrtype], rr[:info_values][:info1_value], rr[:guid], c.soap_error])
        else
          log.warn('Deleted record (Name="%s" Type="%s" Target="%s", GUID="%s")' %
            [rr[:d_name], options[:rrtype], rr[:info_values][:info1_value], rr[:guid]])
        end
      end
    end

    # loop through each rr datum
    options[:rrdata].each do |rrdata|

      # build InfoValues array for new record
      InfoValues = {}
      rrdata.split(' ').each do |value|
        InfoValues['Info' + (InfoValues.length + 1).to_s + 'Value'] = value
      end

      # build new record request
      rr_hash = {
        'transactionID' => transaction_id,
        'resourceRecord' => {
          'sch:InfoValues' => '',
          :attributes! => {
            'sch:InfoValues' => InfoValues
          }
        },
        :attributes! => {
          'resourceRecord' => {
            'ZoneName' => options[:zone],
            'DName'    => options[:rrname],
            'TTL'      => options[:rrttl],
            'Type'     => UltraDns::Client.get_rr_type_id(options[:rrtype])
          }
        }
      }

      # add new record
      if options[:dry_run]
        log.warn('Will create record (Zone="%s", Name="%s" TTL="%s", Type="%s", Data="%s")' %
          [options[:zone], options[:rrname], options[:rrttl], options[:rrtype], rrdata])
      else
        c.soap_call('create_resource_record!', rr_hash)
        if c.soap_error
          log.error('Failed to create record (Zone="%s", Name="%s" TTL="%s", Type="%s", Data="%s") - %s' %
            [options[:zone], options[:rrname], options[:rrttl], options[:rrtype], rrdata, c.soap_error])
        else
          log.warn('Created record (Zone="%s", Name="%s" TTL="%s", Type="%s", Data="%s")' %
            [options[:zone], options[:rrname], options[:rrttl], options[:rrtype], rrdata])
        end
      end

    end

  end

  # commit/rollback transaction
  if not options[:dry_run]
    c.soap_call('commit_transaction!', {'transactionID' => transaction_id})
    if c.soap_error
      log.error('Failed to commit transaction with ID "%s" - %s' % [transaction_id, c.soap_error])
      c.soap_call('rollback_transaction!', {'transactionID' => transaction_id})
      if c.soap_error
        log.fatal('Failed to roll back transaction with ID "%s" - %s' % [transaction_id, c.soap_error])
      end
    else
      log.info('Committed transaction with ID "%s"' % transaction_id)
    end
  end

end
