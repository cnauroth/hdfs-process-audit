# Accepts as input audit log entries from an hdfs-audit.log file.  Prints
# aggregate reports of operation counts within each second, grouped by
# UserGroupInformation and grouped by command.
#
# This script consumes O(n) memory, where n=# input audit log entries.  We need
# to sort by timestamp, which might be out of order in the input due to
# asynchronous audit logging.  We also need to identify the full set of columns
# so that we can print consistent output with the same columns in each row.  The
# easiest way to do this is to slurp all of the audit log entries into
# associative arrays, and then sort and iterate at the end.  This could be
# optimized if needed, but that might take us beyond awk.
#
# This script requires GNU awk (gawk) for multi-dimensional array support.
#
# Example:
#     cat hdfs-audit.log | gawk -f ./process_audit5.awk > /tmp/process_audit.out
#
# UPDATE: This version of the script contains changes to the multi-dimensional
# array handling for backwards-compatibility with older gawk versions.  I tested
# this successfully with gawk 3.1.8.  It probably works fine with plain non-GNU
# awk too.  This version of the script was also modified to parse a Hadoop 1
# audit log.  As a next step improvement, the script should guess whether it's
# the Hadoop 1 or Hadoop 2 format while parsing the first line.

# Print the top header, which is a tab-delimited list of column names.
function print_columns_header(columns, n_columns) {
  header = "Timestamp"
  for (i = 1; i <= n_columns; i++) {
    column = columns[i]
    header = header "\t" column
  }
  printf "%s\n", header
}

# Print stats, sorted by timestamp.  Each row consists of timestamp, followed by
# the count for each column within that timestamp.
function print_stats(stats, columns, n_columns) {
  n_sorted_stat_keys = asorti(stats, sorted_stat_keys)
  timestamp = ""
  split("", timestamp_stats, ""); # initialize empty timestamp_stats array

  for (i = 1; i <= n_sorted_stat_keys; i++) {
    stat_key = sorted_stat_keys[i]
    split(stat_key, stat_key_fields, SUBSEP)
    if (timestamp != "" && timestamp != stat_key_fields[1]) {
      # We crossed into a different timestamp.  Print the prior timestamp_stats.
      row = timestamp
      for (j = 1; j <= n_columns; j++) {
        column = columns[j]
        count = column in timestamp_stats ? timestamp_stats[column] : 0
        row = row "\t" count
      }
      printf "%s\n", row
      split("", timestamp_stats, ""); # initialize empty timestamp_stats array
    }
    timestamp = stat_key_fields[1]
    sub_key = stat_key_fields[2]
    timestamp_stats[sub_key] = stats[stat_key]
  }
  if (timestamp != "") {
    # Print timestamp_stats for the last timestamp still in progress.
    row = timestamp
    for (j = 1; j <= n_columns; j++) {
      column = columns[j]
      count = column in timestamp_stats ? timestamp_stats[column] : 0
      row = row "\t" count
    }
    printf "%s\n", row
  }
}

BEGIN {
  SUBSEP = "_"
  # Set field separator to tab.  The first field in a record will contain the
  # Log4J space-delimited date, timestamp, log level, classname and also the
  # first real field of our audit log format, the UserGroupInformation.  All
  # subsequent fields of the audit log format are tab-delimited.
  FS = "\t"
}

{
  # Get timestamp from field 1 and drop milliseconds.
  timestamp = $1
  gsub("^[0-9]*-[0-9]*-[0-9]* ", "", timestamp)
  gsub(",.*$", "", timestamp)

  # Get UserGroupInformation from field 1 and drop field name.
  ugi = $1
  gsub("^.*ugi=", "", ugi)

  # Get command from field 3 and drop field name.
  cmd = $3
  gsub("cmd=", "", cmd)

  stats_by_ugi[timestamp,ugi]++
  stats_by_cmd[timestamp,cmd]++

  # Track set of every encountered UserGroupInformation and command, so that we
  # know every column to output for each timestamp.  We're using an associative
  # array as a set, so the value of each array element doesn't matter.  We're
  # only going to use the keys later.
  ugi_columns[ugi] = 1
  cmd_columns[cmd] = 1
}

END {
  # Sort UserGroupInformation and command columns.
  n_ugi_columns = asorti(ugi_columns)
  n_cmd_columns = asorti(cmd_columns)

  # Print header and stats for UserGroupInformation.
  print_columns_header(ugi_columns, n_ugi_columns)
  print_stats(stats_by_ugi, ugi_columns, n_ugi_columns)

  # Print a newline before the next report.
  printf "\n"

  # Print header and stats for command.
  print_columns_header(cmd_columns, n_cmd_columns)
  print_stats(stats_by_cmd, cmd_columns, n_cmd_columns)
}
