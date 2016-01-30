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
#     cat hdfs-audit.log | gawk -f ./process_audit3.awk > /tmp/process_audit.out

# Print the top header, which is a tab-delimited list of column names.
function print_columns_header(columns) {
  header = "Timestamp"
  for (i in columns) {
    if (header != "") {
      header = header "\t"
    }
    column = columns[i]
    header = header column
  }
  printf "%s\n", header
}

# Print stats, sorted by timestamp.  Each row consists of timestamp, followed by
# the count for each column within that timestamp.
function print_stats(stats, columns) {
  asorti(stats, sorted_timestamps)
  for (i in sorted_timestamps) {
    timestamp = sorted_timestamps[i]
    row = timestamp
    for (j in columns) {
      if (row != "") {
        row = row "\t"
      }
      column = columns[j]
      count = column in stats[timestamp] ? stats[timestamp][column] : 0
      row = row count
    }
    printf "%s\n", row
  }
}

{
  # Get timestamp from field 2 and drop milli seconds.
  gsub(",.*$", "", $2)  

  # Get UserGroupInformation from field 6 and drop field name.
  gsub("ugi=", "", $6)

  # Get command from field 9 and drop field name.
  gsub("cmd=", "", $9)

  # Increment counter of UserGroupInformation and command within timestamp.
  stats_by_ugi[$2][$6]++
  stats_by_cmd[$2][$9]++

  # Track set of every encountered UserGroupInformation and command, so that we
  # know every column to output for each timestamp.  We're using an associative
  # array as a set, so the value of each array element doesn't matter.  We're
  # only going to use the keys later.
  ugi_columns[$6] = 1
  cmd_columns[$9] = 1
}

END {
  # Sort UserGroupInformation and command columns.
  asorti(ugi_columns)
  asorti(cmd_columns)

  # Print header and stats for UserGroupInformation.
  print_columns_header(ugi_columns)
  print_stats(stats_by_ugi, ugi_columns)

  # Print a newline before the next report.
  printf "\n"

  # Print header and stats for command.
  print_columns_header(cmd_columns)
  print_stats(stats_by_cmd, cmd_columns)
}
