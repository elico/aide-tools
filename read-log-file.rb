#!/usr/bin/env ruby

require "json"

lines = File.open(ARGV[0]).readlines

$debug = 0

report = {}

summary = {}

added_enteries_details = {}
changed_enteries = {}
detailed_change_info = {}
detailed_change_info_current_filename = ""

line_num = 0
sections = ["command", "start-timestamp", "summary", "added-enteries", "changed-enteries", "detailed-change-info", "database-info"]
section = false
section_header = ""
current_section_name = ""

while line_num < lines.size
  if line_num == 0
    current_section_name = "command"
    report["comand"] = lines[line_num].chomp
    line_num = line_num + 1
    next
  end

  if lines[line_num] =~ /^[\-]+$/
    line_num = line_num + 1
    next
  end

  if lines[line_num].chomp.empty?
    line_num = line_num + 1
    next
  end

  # checking for section mark
  case lines[line_num]
  when /^Start\ timestamp\:\ ([0-9\-]+)\ ([\:0-9]+) ([\-\+0-9]+)\ \(AIDE ([0-9\.]+)\)/
    current_section_name = "start-timestamp"
    report["start-timestamp"] = {}
    report["start-timestamp"]["date"] = Regexp.last_match(1)
    report["start-timestamp"]["time"] = Regexp.last_match(2)
    report["start-timestamp"]["timezone"] = Regexp.last_match(3)
    report["start-timestamp"]["version"] = Regexp.last_match(4)
  when /^Summary\:/
    current_section_name = "summary"
    line_num = line_num + 1
    next
  when /^Detailed\ information\ about\ changes\:/
    current_section_name = "detailed-change-info"
    line_num = line_num + 1
    next
  when /^Changed\ entries\:/
    current_section_name = "changed-enteries"
    line_num = line_num + 1
    next
  when /^Added\ entries\:/
    current_section_name = "added-enteries"
    line_num = line_num + 1
    next
  when /^The\ attributes\ of\ the\ \(uncompressed\)\ database\(s\)/
    current_section_name = "database-info"
    report["database-info"] = {}
    line_num = line_num + 1
    next
  when /^End\ timestamp\:\ ([0-9\-]+)\ ([\:0-9]+) ([\-\+0-9]+)\ \(run\ time\:\ ([msh0-9\s]+)\)/
    current_section_name = "start-timestamp"
    report["end-timestamp"] = {}
    report["end-timestamp"]["date"] = Regexp.last_match(1)
    report["end-timestamp"]["time"] = Regexp.last_match(2)
    report["end-timestamp"]["timezone"] = Regexp.last_match(3)
    report["end-timestamp"]["runtime"] = Regexp.last_match(4)
    line_num = line_num + 1
    next
  else
  end

  case current_section_name
  when "database-info"
    if lines[line_num] =~ /^[a-zA-Z0-9\/]+/
      report["database-info"]["database-filename"] = lines[line_num].chomp.strip
      # Probably a filename line
      line_num = line_num + 1
      next
    end
    if lines[line_num] =~ /[\s\t]+(MD5|RMD160|SHA1|TIGER)[\s\t]+\:[\s\t]+([a-zA-Z0-9\/\=\+]+)/
      report["database-info"][Regexp.last_match(1)] = Regexp.last_match(2)
      line_num = line_num + 1
      next
    end
    if lines[line_num] =~ /[\s\t]+(SHA256)[\s\t]+\:[\s\t]+([a-zA-Z0-9\/\=\+]+)/
      report["database-info"][Regexp.last_match(1)] = []
      report["database-info"][Regexp.last_match(1)] << Regexp.last_match(2)
      line_num = line_num + 1
      report["database-info"][Regexp.last_match(1)] << lines[line_num].chomp.strip
      report["database-info"][Regexp.last_match(1)] = report["database-info"][Regexp.last_match(1)].join
      line_num = line_num + 1
      next
    end
    if lines[line_num] =~ /[\s\t]+(SHA512)[\s\t]+\:[\s\t]+([a-zA-Z0-9\/\=\+]+)/
      report["database-info"][Regexp.last_match(1)] = []
      report["database-info"][Regexp.last_match(1)] << Regexp.last_match(2)
      line_num = line_num + 1
      report["database-info"][Regexp.last_match(1)] << lines[line_num].chomp.strip
      line_num = line_num + 1
      report["database-info"][Regexp.last_match(1)] << lines[line_num].chomp.strip
      report["database-info"][Regexp.last_match(1)] = report["database-info"][Regexp.last_match(1)].join
      line_num = line_num + 1
      next
    end
  when "summary"
    if lines[line_num] =~ /^[\s]+([a-zA-Z\s]+)\:[\t\s]+([0-9]+)/
      summary[Regexp.last_match(1)] = Regexp.last_match(2).to_i
    else
    end
  when "added-enteries"
    space_index = lines[line_num].index(" ")

    details = lines[line_num][0..space_index]
    file_name = lines[line_num][(space_index + 1)..-1].chomp
    added_enteries_details[file_name] = {}
    added_enteries_details[file_name]["value"] = details.gsub(":", "")
  when "changed-enteries"
    space_index = lines[line_num].index(": ")
    # puts lines[line_num]

    file_name = lines[line_num][(space_index + 1)..-1].chomp
    details = lines[line_num][0..space_index]
    changed_enteries[file_name] = {}
    changed_enteries[file_name]["value"] = details.strip.gsub(":", "")
  when "detailed-change-info"
    if lines[line_num] =~ /^File\:\s(.*)/
      # Filename line
      file_name = Regexp.last_match(1)
      line_num = line_num + 1
      detailed_change_info[file_name] = {}
      changes_info = {}
      current_change_details = ""

      while lines[line_num].include?("|")
        if lines[line_num].chomp.empty?
          line_num = line_num + 1
          next
        end
        if lines[line_num] =~ /^[\s]+(Size|Perm|SHA512|SHA1|SHA256)/
          current_change_details = Regexp.last_match(1)
          #   puts current_change_details

          if current_change_details == "SHA512"
            first_value_mark_pos = lines[line_num].index(":")
            detailed_change_info[file_name]["SHA512"] = {}
            detailed_change_info[file_name]["SHA512"]["old"] = []
            detailed_change_info[file_name]["SHA512"]["new"] = []
            value_first_line = lines[line_num][first_value_mark_pos..-1].chomp.split("|")
            if value_first_line.size > 0
              detailed_change_info[file_name]["SHA512"]["old"] << value_first_line[0].gsub(/\:/, "").gsub(/[\s]+/, "")
              detailed_change_info[file_name]["SHA512"]["new"] << value_first_line[1].gsub(/\:/, "").gsub(/[\s]+/, "")
            end
            line_num = line_num + 1
            value_second_line = lines[line_num].chomp.split("|")
            if value_second_line.size > 0
              detailed_change_info[file_name]["SHA512"]["old"] << value_second_line[0].gsub(/\:/, "").gsub(/[\s]+/, "")
              detailed_change_info[file_name]["SHA512"]["new"] << value_second_line[1].gsub(/\:/, "").gsub(/[\s]+/, "")
            end
            line_num = line_num + 1
            value_third_line = lines[line_num].chomp.split("|")
            if value_third_line.size > 0
              detailed_change_info[file_name]["SHA512"]["old"] << value_third_line[0].gsub(/\:/, "").gsub(/[\s]+/, "")
              detailed_change_info[file_name]["SHA512"]["new"] << value_third_line[1].gsub(/\:/, "").gsub(/[\s]+/, "")
            end
            detailed_change_info[file_name]["SHA512"]["old"] = detailed_change_info[file_name]["SHA512"]["old"].join
            detailed_change_info[file_name]["SHA512"]["new"] = detailed_change_info[file_name]["SHA512"]["new"].join
            line_num = line_num + 1
            next
          end

          if current_change_details == "Size"
            value_mark_pos = lines[line_num].index(":")
            value = lines[line_num][value_mark_pos..-1].chomp.split("|")
            if value.size > 0
              detailed_change_info[file_name]["Size"] = {}
              detailed_change_info[file_name]["Size"]["old"] = value[0].gsub(/\:/, "").gsub(/[\s]+/, "").to_i
              detailed_change_info[file_name]["Size"]["new"] = value[1].gsub(/\:/, "").gsub(/[\s]+/, "").to_i
            end
          end

          if current_change_details == "Perm"
            value_mark_pos = lines[line_num].index(":")
            value = lines[line_num][value_mark_pos..-1].split("|")
            if value.size > 0
              detailed_change_info[file_name]["Perm"] = {}
              detailed_change_info[file_name]["Perm"]["old"] = value[0].gsub(/\:/, "").gsub(/[\s]+/, "")
              detailed_change_info[file_name]["Perm"]["new"] = value[1].gsub(/\:/, "").gsub(/[\s]+/, "")
            end
          end
        end
        line_num = line_num + 1
        next
      end
    end
    line_num = line_num + 1
    next
  else
  end
  line_num = line_num + 1
end

report["summary"] = summary
report["added-enteries"] = added_enteries_details
report["changed-enteries"] = changed_enteries
report["detailed-change-info"] = detailed_change_info
puts JSON.pretty_generate(report)
