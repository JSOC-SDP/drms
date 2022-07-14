#!/usr/bin/perl -w

## TODO:: See that counter might need to be incremented after all
###
#####
use lib qw(/home/slony/Scripts);

use Net::FTP;
use Data::Dumper;
use Net::SCP;
use Net::SSH qw(ssh ssh_cmd issh sshopen2 sshopen3);
use Fcntl ':flock';

use strict;

## only one version of this program running
unless (flock(DATA, LOCK_EX|LOCK_NB)) {
    print "$0 is already running. Exiting.\n";
    exit(1);
}

#### CONFIGURATION variables
$Net::SCP::scp="/usr/bin/scp";                  ## path to fast scp instance.
my $rmt_hostname="j0.stanford.edu";             ## remote machine name
my $rmt_port="55000";                           ## port to fast scp server in remote machine
my $user="igor";                                ## user login in remote machine
my $rmt_dir="/scr21/jennifer/slony_logs/igor";  ## directory in remote machine
my $workdir="/home/slony/logs";              ## local working directory
my $slony_log_path="/home/slony/logs";       ## directory where logs files are writen to in local machine
my $PSQL="/usr/bin/psql -Uslony nso_drms";   ## psql path
my $email_list='igor@noao.edu';                 ## list of people to email in case some problem occurs.
my $counter_file="/home/slony/logs/slony_counter.txt";  ## path to file keeping the slony counter.
#### END of CONFIGURATION variables

sub get_log_list {
  my $file_name_regex=shift;
  my $ls_string="$rmt_dir/$file_name_regex";
  print "$ls_string\n";
  sshopen3("$user\@$rmt_hostname", *WRITER, *READER, *ERROR, "ls -1 $ls_string");

  my $output=undef;
  while(<READER>) {
    $output .= $_;
  }
  my @list = split("\n",$output);
  my $error=0;
  while (<ERROR>) {
    next if $_ =~ /No match/;
    if ($_ !~ /^\s*$/) {
      print "ERROR: $_";
      $error=1;
    }
  }

  close(READER);
  close(WRITER);
  close(ERROR);

  if ($error ==1) {
    print "get_log_list failed ... exiting\n";
  }

  return @list;
}
sub save_current_counter {
  my ($counter_file, $log_file) = @_;
  my ($counter)= ($log_file=~/slony1_log_2_0+(\d+).sql/);
  open my $fhW, ">$counter_file" or die "Can't Open $counter_file:$!";
  print $fhW $counter;
  close $fhW;
}

sub ingest_log {
  my ($log, $scp) = @_;

  my ($log_name) = ($log=~/(slony1_log_2_.*sql)$/);
  print "file name = $log_name\n";

  $scp->get($log_name) or die "Cannot get file $log_name ", $scp->{errstr} if defined $scp;


#  print "$PSQL -f $slony_log_path/$log_name\n";

  
  #open SQLOUT, "/usr/local/pgsql/bin/psql -Uslony drmsdb -f /home/slony/Scripts/$log_name |";
  open SQLOUT, "$PSQL -f $slony_log_path/$log_name |";

  while (<SQLOUT>) {
    #print "SQL out [$_]\n";

    if ($_ =~ /slony1_log_2_0+(\d+)\.sql:\d+:\s+ERROR:(.*)/) {
      print "SQL out [$_]\n";
      send_error($1, $2);
      exit;
    }
  }
  close SQLOUT;

  #clean up
  `rm $log_name`;

}

sub send_error {
  my ($log_file, $error_msg) = @_;

#  my $email_list='igor@noao.edu';

  # print "echo \"$error_msg\" | mail -s \"ERROR:: Slony log [$log_file]\" $email_list\n";
  `echo "$error_msg" | mail -s "ERROR:: Slony log [$log_file]" $email_list`;
}

chdir $workdir;

my $scp = Net::SCP->new($rmt_hostname) or die "Cannot connect to $rmt_hostname: $!";
$scp->login($user);
$scp->cwd($rmt_dir);

## read current counter
#my $counter_file="/home/slony/Scripts/slony_counter.test.txt";
local $/;
open my $fhR, "<$counter_file" or die "Can't Open $counter_file:$!";
my $cur_counter=<$fhR>;
close $fhR;

print "Start Counter is $cur_counter\n";

## move counter to point to the next log
$cur_counter++;

my ($next_batch)=($cur_counter=~/^(\d+)\d\d\d$/?$1:0);

###################################
## START with stand alone sql log files

my $ls_sql_file=sprintf ("slony1_log_2_%017d[0-9][0-9]*.sql",$next_batch);
my @list = get_log_list($ls_sql_file);


#print Dumper [@list];

for my $log (@list) {
  my ($counter)= ($log=~/slony1_log_2_0+(\d+).sql/);
  if ($counter >= $cur_counter) {
    ingest_log($log, $scp);
    save_current_counter($counter_file, $log);
  }
}

## NOW check tar files ##

my $ls_tar_name="slony*.tar*";
my @tar_list = get_log_list($ls_tar_name);

for my $tar (@tar_list) {
  next unless ($tar=~/(slony_logs_(\d+)-(\d+).tar(\.gz)?)/); 
  #print $tar, "\n";
  #my ($tar_file, $counter1,$counter2)= ($tar=~/(slony_logs_(\d+)-(\d+).tar(\.gz)?)/);
  my ($tar_file, $counter1,$counter2)= ($1,$2,$3);
  if ($counter2 >= $cur_counter && $counter1 <= $cur_counter) {
    print "Counter1 [$counter1] and Counter2 [$counter2]\n";
    print "Tar file is $tar_file\n";
    # ftp get tar file
    $scp->get($tar, "./$tar_file") or die "error [$!] ", $scp->{errstr};;
    # get list from tar file
    my $tar_test=$tar_file=~/\.gz$/? "tar tfz $tar_file" : "tar tf $tar_file";
    my $list = `$tar_test`;
    if ($? != 0) {
      print "Error executing [$tar_test]\n";
      exit
    }


    my @list=split ("\n", $list);

    # expand tar;
    my $tar_exp=$tar_file=~/\.gz$/? "tar xfz $tar_file": "tar xf $tar_file";
    system($tar_exp);
    if ($? !=0) {
      print "failed to execute tar command [$tar_exp]: $!\n";
      exit;
    }
    for my $log (@list) {
      my ($counter)= ($log=~/slony1_log_2_0+(\d+).sql/);
      if ($counter >= $cur_counter) {
        ingest_log($log);
        save_current_counter($counter_file, $log);
      }
    }
  }
}
__DATA__
