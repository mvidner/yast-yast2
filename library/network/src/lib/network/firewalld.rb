# encoding: utf-8
#
# ***************************************************************************
#
# Copyright (c) 2016 SUSE LLC.
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 or 3 of the GNU General
# Public License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.   See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, contact SUSE LLC.
#
# To contact SUSE about this file by physical or electronic mail,
# you may find current contact information at www.suse.com
#
# ***************************************************************************
#
# File: lib/network/firewalld.rb
# Summary:  FirewallD configuration API
# Authors:  Karol Mroz <kmroz@suse.de>, Markos Chandras <mchandras@suse.de>
#

require 'yast'

module Firewalld

  # exception when firewall-cmd fails
  class FirewallCMDError < StandardError
  end

  class FWCmd

    include Yast::Logger

    BASH_SCR_PATH = Yast::Path.new(".target.bash_output")
    # Base firewall-cmd command
    COMMAND = "LANG=Python firewall-cmd"

    attr_reader :option_str

    def initialize(option_str)
      @option_str = option_str
    end

    def command
      "#{COMMAND} #{option_str}".strip.squeeze(" ")
    end

    # Output resulting of executing the command
    def output(need_output = true)
      cmd_result = Yast::SCR.Execute(BASH_SCR_PATH, command)

      # See firewall-cmd manpage for exit codes. Not all of them justify an
      # exception. 0 and 1 can be used as true and false respectively.
      case cmd_result["exit"]
      when 0, 1
        if need_output
          cmd_result["stdout"]
        else
          log.debug "#{command} returned: #{cmd_result['stdout']}"
          cmd_result["exit"].zero? ? true : false
        end
      else
        raise FirewallCMDError, "Calling firewall-cmd (cmd: #{command}) failed: #{cmd_result["stderr"]}"
      end
    end
  end

  class FirewalldAPI
    def self.create(type = :bash)
      case type
      when :bash
        FirewalldBashAPI.new
      when :dbus
        nil
      else
        raise "Unsupported Firewalld API type: #{type}"
      end
    end
  end

  class FirewalldBashAPI

    # Simple wrapper for commands. Returns true on success
    def do_cmd(*args)
      fwcmd = FWCmd.new(args.join(''))
      fwcmd.output(false)
    end

    ### State ###

    # True if firewalld is running
    def is_running?
      do_cmd("--state")
    end

    # True if firewalld was reloaded
    def reload
      do_cmd("--reload")
    end

    # True if firewalld was fully reloaded
    def complete_reload
      do_cmd("--complete-reload")
    end

    # True if runtime config has been made permanent
    def make_permanent
      do_cmd("--runtime-to-permanent")
    end

    ### Zones ####

    # Return list of zones.
    def get_zones
      fwcmd = FWCmd.new("--permanent --get-zones")
      fwcmd.output.split(" ")
    end

    # Return zone, or nil.
    def get_zone_of_interface(iface)
      do_cmd("--permanent --get-zone-of-interface=#{iface}")
    end

    # Return list of interfaces found in zone. Empty list if none found.
    def get_interfaces_in_zone(zone)
      fwcmd = FWCmd.new("--permanent --zone=#{zone} --list-interfaces")
      fwcmd.output.split(" ")
    end

    # Return list of services that have been added to zone, or [].
    def get_services_in_zone(zone)
      fwcmd = FWCmd.new("--permanent --zone=#{zone} --list-services")
      fwcmd.output.split(" ")
    end

    # Return list of ports that have been added to zone, or [].
    def get_ports_in_zone(zone)
      fwcmd = FWCmd.new("--permanent --zone=#{zone} --list-ports")
      fwcmd.output.split(" ")
    end

    # Return list of protocols that have been added to zone, or [].
    def get_protocols_in_zone(zone)
      fwcmd = FWCmd.new("--permanent --zone=#{zone} --list-protocols")
      fwcmd.output.split(" ")
    end

    # Return zone information
    def list_all_zone(zone)
      fwcmd = FWCmd.new("--permanent --zone=#{zone} --list-all")
      fwcmd.output.split("\n")
    end

    # Return zone information
    def list_all_zones
      fwcmd = FWCmd.new("--permanent --list-all-zones")
      fwcmd.output.split("\n")
    end

    ### Interfaces ###

    # True if interface is enabled in zone
    def is_interface_enabled?(zone, interface)
      do_cmd("--permanent --zone=#{zone} --query-interface=#{interface}")
    end

    # True if interface added in zone
    def add_interface_to_zone(zone, interface)
      do_cmd("--permanent --zone=#{zone} --add-interface=#{interface}")
    end

    # True if interface removed from zone
    def remove_interface_from_zone(zone, interface)
      do_cmd("--permanent --zone=#{zone} --remove-interface=#{interface}")
    end

    ### Services ###

    # Return list of firewalld supported services.
    def get_supported_services
      fwcmd = FWCmd.new("--permanent --get-services")
      fwcmd.output.split(" ")
    end

    # Return service information
    def get_service_info(service)
      fwcmd = FWCmd.new("--permanent --info-service #{service}")
      fwcmd.output.split("\n")
    end

    # --get-short and --get-description are not present in any firewalld
    # release at the moment so we expect exceptions and we treat them properly.
    # See: https://github.com/t-woerner/firewalld/pull/91
    #
    # Return service short description
    def get_service_short(service)
      # these may not exist on early firewalld releases
      begin
        fwcmd = FWCmd.new("--permanent --service=#{service} --get-short")
        fwcmd.output
      rescue FirewallCMDError
        "Unknown description for #{service}"
      end
    end

    # Return service long description
    def get_service_description(service)
      begin
        fwcmd = FWCmd.new("--permanent --service=#{service} --get-description")
        fwcmd.output
      rescue FirewallCMDError
        "Unknown description for #{service}"
      end
    end

    # True if FirewallD supports the service. Returns true/false.
    def is_service_supported?(service)
      supported_services = get_supported_services
      supported_services.include?(service)
    end

    # True if service is enabled in zone. Returns true/false
    def is_service_enabled?(zone, service)
      do_cmd("--permanent --zone=#{zone} --query-service=#{service}")
    end

    # Return port/protocol pair as defined in the service file
    def get_service_ports(service)
      fwcmd = FWCmd.new("--permanent --service=#{service} --get-ports")
      fwcmd.output.strip
    end

    # Return port/protocol pair as defined in the service file
    def get_service_protocol(service)
      fwcmd = FWCmd.new("--permanent --service=#{service} --get-protocol")
      fwcmd.output.strip
    end

    # True if port is enabled in zone.
    def is_port_enabled?(zone, port)
      do_cmd("--permanent --zone=#{zone} --query-port=#{port}")
    end

    # True if protocol is enabled in zone.
    def is_protocol_enabled?(zone, protocol)
     do_cmd("--permanent --zone=#{zone} --query-protocol=#{protocol}")
    end

    # True to add service to zone.
    def add_service_to_zone(zone, service)
      do_cmd("--permanent --zone=#{zone} --add-service=#{service}")
    end

    # True to add port to zone.
    def add_port_to_zone(zone, port)
      do_cmd("--permanent --zone=#{zone} --add-port=#{port}")
    end

    # True to add port to zone.
    def add_protocol_to_zone(zone, protocol)
      do_cmd("--permanent --zone=#{zone} --add-protocol=#{protocol}")
    end

    # True to remove service from zone.
    def remove_service_from_zone(zone, service)
      do_cmd("--permanent --zone=#{zone} --remove-service=#{service}")
    end

    # True to remove service from zone.
    def remove_port_from_zone(zone, port)
      do_cmd("--permanent --zone=#{zone} --remove-port=#{port}")
    end

    # True to remove service from zone.
    def remove_protocol_from_zone(zone, protocol)
      do_cmd("--permanent --zone=#{zone} --remove-protocol=#{protocol}")
    end

    # True if masquerade is enabled in zone
    def is_masquerade_enabled?(zone)
      do_cmd("--permanent --zone=#{zone} --query-masquerade")
    end

    # True to enable masquerade to zone.
    def add_masquerade(zone)
      return true if is_masquerade_enabled?(zone)
      do_cmd("--permanent --zone=#{zone} --add-masquerade")
    end

    # True to remove masquerade from zone.
    def remove_masquerade(zone)
      return true if not is_masquerade_enabled?(zone)
      do_cmd("--permanent --zone=#{zone} --remove-masquerade")
    end

    ### Logging ##

    # True if $value logging is enabled
    def is_log_denied?(value)
      fwcmd = FWCmd.new("--get-log-denied")
      fwcmd.output.strip == value ? true : false
    end

    # True to enable $value logging
    def set_log_denied(value)
      do_cmd("--set-log-denied=#{value}")
    end

    # Return log-denied value
    def get_log_denied
      fwcmd = FWCmd.new("--get-log-denied")
      fwcmd.output.strip
    end

  end
end
