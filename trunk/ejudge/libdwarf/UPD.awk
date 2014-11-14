BEGIN {
if (ARGC <=  2)  {
    print "Bogus use of awk file, requires arg"
    exit 1   
} else  {
    v=ARGV[1]
    ARGV[1]=""
}
}
$0 ~  /#define DWARFDUMP_VERSION/ { print $1, $2, "\"",v,"\"" }
$0 !~ /^#define DWARFDUMP_VERSION/ { print $0 }
