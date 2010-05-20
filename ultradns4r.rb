#!/usr/bin/ruby -W0
################################################################################
# ultradns4r - Ruby library and command line client for Neustar UltraDNS SOAP API
# Copyright (c) 2010 Michael Conigliaro <mike [at] conigliaro [dot] org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
################################################################################

require 'logger'
require 'optparse'
require 'pp'
require 'socket'
require 'rubygems'
require 'savon'

module UltraDns

  class Client

    attr_reader :error

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
      tries = 0
      begin
        if tries > 0
          sleep(3)
        end

        # do soap call
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

        tries += 1

        # save errors
        @error = nil
        if !Savon::Response.raise_errors?
          if response.soap_fault?
            if response.to_hash[:fault][:detail]
              @error = '%s (Fault code: %d)' % [response.to_hash[:fault][:detail][:ultra_ws_exception][:error_description],
                                       response.to_hash[:fault][:detail][:ultra_ws_exception][:error_code]]
            else
              @error = '%s' % response.to_hash[:fault][:faultstring]
            end
          elsif response.http_error?
            @error = response.http_error
          end
        end

      # Cannot open: file:/opt/apps/ultradns/ultra_api/server/node2/data/wsdl/UltraDNS.ear/UltraDNS_WS.jar/UltraWebServiceService41762.wsdl
      end while @error =~ /^Cannot open: file:/ and tries < 20

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
    :cred_file => './ultradns4r.secret',
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
    opts.banner = "Usage: #{$0} [options] [rr-data][, ...]\n" \
      + "Example: #{$0} -n srv.example.org. -t SRV 0 10 20 target.example.org."

    opts.on('-c', '--credentials-file VALUE', 'Path to file containing API username/password (default: %s)' % options[:cred_file]) do |opt|
      options[:cred_file] = opt
    end

    opts.on('-z', '--zone VALUE', 'DNS Zone (default: Auto-detect)') do |opt|
      options[:zone] = opt
    end

    opts.on('-n', '--rr-name VALUE', 'Resource record name (default: %s)' % options[:rrname]) do |opt|
      options[:rrname] = opt
    end

    opts.on('-s', '--rr-ttl VALUE', 'Resource record TTL (default: %s)' % options[:rrttl]) do |opt|
      options[:rrttl] = opt
    end

    opts.on('-t', '--rr-type VALUE', 'Resource record type (default: %s)' % options[:rrtype]) do |opt|
      options[:rrtype] = opt
    end

    opts.on('-v', '--verbosity VALUE', 'Log verbosity (default: %s)' % options[:log_level]) do |opt|
      options[:log_level] = opt
    end

    opts.on('--dry-run', "Perform a trial run without making changes") do |opt|
      options[:dry_run] = opt
    end

    opts.on('--use-transaction', "All operations are performed within a single transaction") do |opt|
      options[:use_transaction] = opt
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
  end

  # instantiate ultradns client
  c = UltraDns::Client.new(options[:username], options[:password])

  # check if zone exists
  response = c.soap_call('get_zone_info!', {'zoneName' => options[:zone]})
  if c.error
    log.error('Unable to obtain info for zone "%s" - %s' % [options[:zone], c.error])
    Process.exit(1)
  end

  # get transaction id
  if options[:use_transaction] and not options[:dry_run]
    response = c.soap_call('start_transaction!')
    if c.error
      log.error('Unable to get transaction ID - %s' % c.error)
      Process.exit(1)
    else
      transaction_id = response.to_hash[:start_transaction_response][:transaction_id]
      log.info('Got transaction ID "%s"' % transaction_id)
    end
  else
    transaction_id = nil
  end

  # enable automatic serial updating
  if options[:use_transaction] and not options[:dry_run]
    response = c.soap_call('auto_serial_update!', {
      'transactionID'         => transaction_id,
      'autoSerialUpdateValue' => 'enable'})
    if c.error
      log.error('Unable to enable automatic serial updating - %s' % c.error)
    else
      log.info('Enabled automatic serial updating')
    end
  end

  # query for existing records
  response = c.soap_call('get_resource_records_of_dname_by_type!', {
    'zoneName' => options[:zone],
    'hostName' => options[:rrname],
    'rrType'   => UltraDns::Client.get_rr_type_id(options[:rrtype])})
  if c.error
    log.error('Query for existing records failed - %s' % c.error)
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

    # loop through existing records
    resource_records.each do |rr|

      # delete existing records
      if options[:dry_run]
        log.warn('Will delete record (Name="%s" Type="%s" Target="%s", GUID="%s")' %
          [rr[:d_name], options[:rrtype], rr[:info_values][:info1_value], rr[:guid]])
      else
        c.soap_call('delete_resource_record!', {
          'transactionID' => transaction_id,
          'guid' => rr[:guid]})
        if c.error
          log.warn('Failed to delete record (Name="%s" Type="%s" Target="%s", GUID="%s") - %s' %
            [rr[:d_name], options[:rrtype], rr[:info_values][:info1_value], rr[:guid], c.error])
        else
          log.warn('Deleted record (Name="%s" Type="%s" Target="%s", GUID="%s")' %
            [rr[:d_name], options[:rrtype], rr[:info_values][:info1_value], rr[:guid]])
        end
      end
    end

    # loop through each rr datum
    if options[:rrdata]
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
          if c.error
            log.error('Failed to create record (Zone="%s", Name="%s" TTL="%s", Type="%s", Data="%s") - %s' %
              [options[:zone], options[:rrname], options[:rrttl], options[:rrtype], rrdata, c.error])
          else
            log.warn('Created record (Zone="%s", Name="%s" TTL="%s", Type="%s", Data="%s")' %
              [options[:zone], options[:rrname], options[:rrttl], options[:rrtype], rrdata])
          end
        end

      end
    end

  end

  # commit/rollback transaction
  if options[:use_transaction] and not options[:dry_run]
    c.soap_call('commit_transaction!', {'transactionID' => transaction_id})
    if c.error
      log.error('Failed to commit transaction with ID "%s" - %s' % [transaction_id, c.error])
      c.soap_call('rollback_transaction!', {'transactionID' => transaction_id})
      if c.error
        log.fatal('Failed to roll back transaction with ID "%s" - %s' % [transaction_id, c.error])
      end
    else
      log.info('Committed transaction with ID "%s"' % transaction_id)
    end
  end

end
