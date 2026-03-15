##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
# Optimized by ra1nyxin for Issue #21096
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/ftp'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def proto
    'ftp'
  end

  def initialize
    super(
      'Name'        => 'FTP Authentication Scanner (Enhanced)',
      'Description' => %q{
        This module tests FTP logins across a range of hosts. It has been 
        enhanced to consistently handle anonymous logins and resolve 
        credential validation errors.
      },
      'Author'      => ['todb', 'ra1nyxin'],
      'References'  => [
        ['CVE', '1999-0502'] # Weak password
      ],
      'License'     => MSF_LICENSE,
      'DefaultOptions' => {
        'ConnectTimeout' => 30,
        'ANONYMOUS_LOGIN' => false # Default to false, but handled correctly when true
      }
    )

    register_options(
      [
        Opt::Proxies,
        Opt::RPORT(21),
        OptBool.new('ANONYMOUS_LOGIN', [ false, 'Attempt to login with anonymous/guest account', false]),
        OptBool.new('RECORD_GUEST', [ false, "Record anonymous/guest logins to the database", false])
      ]
    )

    register_advanced_options(
      [
        OptBool.new('SINGLE_SESSION', [ false, 'Disconnect after every login attempt', false]),
      ]
    )

    deregister_options('FTPUSER', 'FTPPASS') 
    @accepts_all_logins = {}
  end

  def run_host(ip)
    print_status("#{ip}:#{rport} - Starting FTP login sweep")
    cred_collection = build_credential_collection(
      username: datastore['USERNAME'],
      password: datastore['PASSWORD'],
      prepended_creds: anonymous_creds
    )

    scanner = Metasploit::Framework::LoginScanner::FTP.new(
      configure_login_scanner(
        host: ip,
        port: rport,
        proxies: datastore['PROXIES'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        max_send_size: datastore['TCP::max_send_size'],
        send_delay: datastore['TCP::send_delay'],
        connection_timeout: datastore['ConnectTimeout'],
        ftp_timeout: datastore['FTPTimeout'],
        framework: framework,
        framework_module: self,
        ssl: datastore['SSL'],
        ssl_version: datastore['SSLVersion'],
        ssl_verify_mode: datastore['SSLVerifyMode'],
        ssl_cipher: datastore['SSLCipher'],
        local_port: datastore['CPORT'],
        local_host: datastore['CHOST']
      )
    )

    scanner.check_protocol_options

    begin
      scanner.scan! do |result|
        credential_data = result.to_h
        credential_data.merge!(
          module_fullname: self.fullname,
          workspace_id: myworkspace_id
        )

        if result.success?
          is_anon = (result.credential.public.to_s.downcase == 'anonymous')
          if !is_anon || (is_anon && datastore['RECORD_GUEST'])
            credential_data[:private_type] = :password
            credential_core = create_credential(credential_data)
            credential_data[:core] = credential_core
            create_credential_login(credential_data)
          end
          print_good "#{ip}:#{rport} - Login Successful: #{result.credential}"
        else
          invalidate_login(credential_data)
          vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
        end
      end
    rescue Metasploit::Framework::LoginScanner::Invalid => e
      print_error("#{ip}:#{rport} - Scanner Configuration Error: #{e.message}")
    rescue Rex::ConnectionError, Rex::ConnectionTimeout
      print_error("#{ip}:#{rport} - Connection failed.")
    end
  end

  def anonymous_creds
    anon_list = []
    if datastore['ANONYMOUS_LOGIN'] || datastore['RECORD_GUEST']
      passwords = ['mozilla@example.com']
      passwords << 'IEUser@' if datastore['RECORD_GUEST']
      passwords.each do |p|
        anon_list << Metasploit::Framework::Credential.new(
          public: 'anonymous', 
          private: p, 
          realm: nil, 
          private_type: :password
        )
      end
    end
    
    anon_list
  end

  def test_ftp_access(user, scanner)
    dir = Rex::Text.rand_text_alpha(8)
    begin
      write_check = scanner.send_cmd(['MKD', dir], true)
      if write_check && write_check =~ /^2/
        scanner.send_cmd(['RMD', dir], true)
        print_status("#{rhost}:#{rport} - User '#{user}' has READ/WRITE access")
        return 'Read/Write'
      else
        print_status("#{rhost}:#{rport} - User '#{user}' has READ access")
        return 'Read-only'
      end
    rescue
      return 'Unknown'
    end
  end
end
