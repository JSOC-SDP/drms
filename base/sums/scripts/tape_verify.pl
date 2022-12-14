#!/usr/bin/perl -w

#-------------------------------------------------------------------------------------
#
# tape_verify.pl
#
# This script scans the T50 IMPORT/EXPORT slots (26-30) for tapes.
# Each tape is transferred to the TAPE DRIVE where each file is read and a md5 check sum is calculated.
# The check sums are saved into a file (ex: 000822L4.md5_offsite)
# After all tapes have been scanned, the check sums generated offsite will be compaired with 
# check sums generated onsite at Stanford to verify that the tapes are not dammaged after being transported.
# A summary report for each tape is written to a file to be sent back to Stanford for acknowlegements.
#
# For example:
#
# 000822L4.md5                     (input:  generated by SUMS) 
# 000822L4.md5_offsite             (output: generated offsite by this script)
# HMI_2008.05.12_14:00:00:00.ver   (output: verify summary report, generated by this scritpt)
#                        
#-------------------------------------------------------------------------------------


use strict;
use warnings;


my $OFF_SITE_TAPE_VERIFICATION_DEBUG_MESSAGES = 1;

# let user choose working_dir at runtime 
# For example: we "run_remote_tape_verify.pl" from our data center using ~tapetest/tape_verify/ as default working directory
# ssh tapetest@wonton 'cd tape_verify/; ./scripts/tape_verify.pl'

my $working_dir = "./"; 

    
my $log_filename = $working_dir . "tape_verify.log";
open (LOG_OUTFILE, ">$log_filename") || die "Can't Open : $log_filename $!\n";
print LOG_OUTFILE "# " . $log_filename . " generated by tape_verify.pl\n";

TapeVerify(); # main()

close LOG_OUTFILE;

exit; 


#-------------------------------------------------------------------------------------
# TapeVerify()
#
# This is the main() function.
# 
# Since there is only TAPE DRIVE (slot 0). 
# Only one tape is on transit at a time. It is transferred to drive and process and returned to the same slot.
# The original_tape_positions are kept here for convinient lookup.


sub TapeVerify
{
    my ($tapes_in_slots, $tape_label, $filename, $number_of_files, %tapes, @tape_list);
    my ($slot, %original_tape_positions);

    DebugMessage("Begin at ". GetTimeString(). "\n");

    %original_tape_positions = ();


    $tapes_in_slots = InitCheck();

    GetCurrentTapePositions(\%original_tape_positions);
    DisplayTapePositions(\%original_tape_positions);


    # Create a hash containing tape_labels and number_of_files
    # Look for correspondent md5 files previously generated onsite for a particular tape. 

    DebugMessage("Search for correspondent .md5 files previously generated onsite.\n");
    %tapes=();

    foreach $tape_label (@$tapes_in_slots)
    {
	$filename = $working_dir . $tape_label . ".md5";
	$number_of_files = 0;

	if (-e $filename) # if file exist
	{
	    open(FILE, "<$filename") or die "can't open $filename: $!";
	    $number_of_files++ while <FILE>;
	    close(FILE);

	    if($number_of_files)
	    {
		$tapes{$tape_label} = $number_of_files-1; # not counting the first comment line
	    }
	}
	else # missing md5
	{
	    $tapes{$tape_label} = -1; # This will be reported as missing md5 file.
	}
    }

    @tape_list = sort keys (%tapes);




    # Show the list of tapes to be verified, skip those with ( )
    DebugMessage("Tapes to be verified : ");
    foreach $tape_label (@tape_list)
    {
	if ($tapes{$tape_label} > 0)
	{
	    DebugMessage(" $tape_label");
	}
	else
	{
	    DebugMessage(" ($tape_label)");
	}
    }
    DebugMessage("\n");




    # Scan each tape, generate "tape_label.md5_offsite" file
    foreach $tape_label (@tape_list)
    {

	# Tapes with missing md5 (-1) or empty md5 (0) will not be loaded (to save time)

	if ($tapes{$tape_label} > 0)
	{
	    LoadTape($tape_label, \%original_tape_positions);
	
	    CheckTape($tape_label, $tapes{$tape_label});

	    UnloadTape(\%original_tape_positions);
	}
    }

    DebugMessage("Finish at ". GetTimeString(). "\n");

    # Compare "tape_label.md5" to "tape_label.md5_offsite" and write "verify summary report"
    CompareFilesAndReport(\@tape_list);


    #DebugMessage("tape_verify.pl done!\n");

}

#-------------------------------------------------------------------------------------
# InitCheck()
#
# There should be no tape in SLOT 0.
# If there is tape in SLOT 0, unload it to an open slot in (1-25)
#
# Return a list of tapes available in IMPORT/EXPORT slots (26-30)

sub InitCheck
{
    my ($current_tape, @process_list, $slot, %current_tape_positions, $result);


    # Note: We might get "Illegal Element Type Code 83 reported" from t50, the first time trying to talk to it
    # Just do this once to clear the error message...then begin
    $result = `mtx -f /dev/t50 status`;
  

    GetCurrentTapePositions(\%current_tape_positions);

    $current_tape = GetCurrentTapeLabel();
    if($current_tape) 
    {
	UnloadTape(\%current_tape_positions);
    }
    
    for($slot=26;$slot <31;$slot++)
    {
	if($current_tape_positions{$slot}) 
	{
	    push(@process_list, $current_tape_positions{$slot});     
	}
    }


    return (\@process_list);
}

#-------------------------------------------------------------------------------------
# CheckTape (tape_label, number_of_files = 10)
#
# Rewind Tape
# Scan Tape for files, get MD5s and save them into file "$tape_label.md5_offsite" (ie: 000828L4.md5_offsite)
# Rewind Tape
#

sub CheckTape
{
    my $tape_label = $_[0];
    my $number_of_files = defined($_[1]) ? $_[1] : 10;

    my ($filename, $command, $check_sum, $i);


    #DebugMessage("RetensionTape\n");
    #$command = "mt -f /dev/nst0 retension";
    #system($command)==0 || die "CheckTape() fails. ";  


    DebugMessage("RewindTape\n");
    $command = "mt -f /dev/nst0 rewind";
    system($command)==0 || die "CheckTape() fails. ";  


    # Skip first file (contains only the Tape Label - no data)
    $command = "mt -f /dev/nst0 fsf 1";
    system($command)==0 || die "CheckTape() fails. ";  

    $filename = $working_dir ."$tape_label.md5_offsite";
    open(OUTFILE,">$filename") || die "CheckTape() fails: $!";
    print OUTFILE "# $tape_label.md5_offsite generated by tape_verify.pl at " . GetTimeString() ."\n";

    
    for($i=1;$i<=$number_of_files;$i++)
    {

	$check_sum = GetCheckSum();

	if($check_sum)
	{
	    print OUTFILE "$i $check_sum\n";
	    DebugMessage("GetCheckSum($tape_label:$i) => [$check_sum]\n");
	}
	else { last;} # something wrong
    } 

    close (OUTFILE);


    $i--;
    if($i == $number_of_files)
    {
	DebugMessage("CheckTape($tape_label:1-$i) complete.\n");
    }
    else
    {
	DebugMessage("CheckTape($tape_label:1-$i) ====> NOT COMPLETE!\n");
    }

    DebugMessage("RewindTape\n");
    $command = "mt -f /dev/nst0 rewind";
    system($command)==0 || die "CheckTape() fails. ";  


}

#-------------------------------------------------------------------------------------
# LoadTape ($tape_label, \%original_tape_positions)
#
# Look up the tape positions from global $original_tape_positions to see where the tape_label is
# (rather than GetCurrentTapePositions()) 
# load it into SLOT 0
#

sub LoadTape
{
    my ($tape_label, $original_tape_positions) = @_;
    my($slot, $found_slot, $command);
    

    foreach $slot (keys %$original_tape_positions) 
    {  
	if($original_tape_positions->{$slot} eq $tape_label)
	{
	    $found_slot = $slot;
	    last;
	}
    }


    # Move tape
    DebugMessage("LoadTape($tape_label) from slot $found_slot.\n");

    if($found_slot)
    {
	$command = "mtx -f /dev/t50 load $found_slot 0";
	system($command)==0 || die "LoadTape($tape_label) fails =>";  
    }
    else
    {
	DebugMessage("LoadTape($tape_label) tape not found\n");
	DebugMessage("Here is the list of currently available tapes:\n");
        DisplayTapePositions($original_tape_positions);
    }
    
}

#-------------------------------------------------------------------------------------
# UnloadTape (\%original_tape_positions) 
#
# Use global $original_tape_position to determine which slot.
# if tape is originally from one of IMPORT/EXPORT slots, place it back to the original slot.
# else tape is originally from one of internal slots, place it in an open slot (1-25).

sub UnloadTape
{

    my $original_tape_positions = shift;    
    my ($tape_label, $slot, $found_slot, $command);

    $found_slot = undef;


    $tape_label = GetCurrentTapeLabel();
    if(!$tape_label) # no tape in SLOT #0
    {
	return;
    }
    

    foreach $slot (keys %$original_tape_positions) 
    {  
	if($original_tape_positions->{$slot} eq $tape_label)
	{
	    $found_slot = $slot;
	    last;
	}
    }


    if(! $found_slot)
    {
	for($slot=1;$slot <26;$slot++)
	{
	    if(!$original_tape_positions->{$slot}) 
	    {
		$found_slot = $slot;
		last;
	    }
	}
    }
    

    if(! $found_slot) 
    {
	die ("UnloadTape() could not find open slot to unload.\n");
    }

    # Move tape
    DebugMessage("UnloadTape($tape_label) to slot $found_slot.\n");

    $command = "mtx -f /dev/t50 unload $found_slot 0";
    system($command)==0 || die "UnLoadTape() fails =>";

    # Will get following response, if wanna check
    # "Unloading Data Transfer Element into Storage Element $found_slot...done".

}


#-------------------------------------------------------------------------------------
# DisplayTapePositions (\%tape_positions)
#
# Tape Positions: (3)
# slot[0] => tape[000829L4]
# slot[1] => tape[000822L4]
# slot[29] => tape[000828L4]


sub DisplayTapePositions
{
    my $hash = $_[0];
    my (@order_keylist, $key, $message);


    @order_keylist = sort{$a <=> $b} (keys(%{$hash}));

    DebugMessage("Tape Positions: (" . @order_keylist . " tapes)\n");  

    foreach $key (@order_keylist) 
    {
	DebugMessage("slot[". $key ."] => tape[" . $hash->{$key} ."]\n");
    }
}


#-------------------------------------------------------------------------------------
# GetCurrentTapeLable in TAPE DRIVE (SLOT 0)
#
# return a tape label (ex: 000828L4) or undef if SLOT 0 is empty.
#


sub GetCurrentTapeLabel
{
    my ($line, $name, $value);

    $value = undef;
    open(COM,"mtx -f /dev/t50 status |") || die "GetCurrentTapeLabel() fails : $!";
    while (defined ($line = <COM>)) {
	chomp($line);
	if ($line =~ /Data Transfer Element 0/) 
	{
	    ($name, $value) = split( /=/,$line);
	    if($value) 
	    {
		$value =~ s/^\s+//;
		$value =~ s/\s+$//;
	    }
	    last;
	}
    }
    close(COM) || die "GetCurrentTapeLabel() fails : $!";

    return $value;
}

#-------------------------------------------------------------------------------------
# GetCurrentFileNumber()
#
# GetCurrentFileNumber asks TAPE DRIVE where we are on tape (ex: => 9)

sub GetCurrentFileNumber
{
    my ($line, $name, $value);

    $value = undef;
    open(COM,"mt -f /dev/nst0 status |") || die "GetCurrentFileNumber() fails : $!";
    while (defined ($line = <COM>)) {
	chomp($line);
	if ($line =~ /file number/)  # Where we are on the current TAPE
	{
	    ($name, $value) = split( /=/,$line);
	    $value =~s/^\s+//;
	    last;
	}
    }
    close(COM) || die "GetCurrentFileNumber() fails : $!";

    return $value;
}

#-------------------------------------------------------------------------------------
# GetCheckSum()
#
# GetCheckSum of the current file on TAPE DRIVE (Slot 0)
# Note: current file number will advanced to the next one.
#
# Note: Caller use this function to check END OF DATA as well
# This system command always return 0, even at the EOD (end of data) on TAPE. 
# Experiment => A blank block of tape return $check_sum = "d41d8cd98f00b204e9800998ecf8427e"
# For now, we use that as END OF DATA indicator, which return $checksum=undef


sub GetCheckSum
{
    my ($result, $checksum, $command);

    $checksum = undef;


    $command = "dd if=/dev/nst0 bs=256b 2>/dev/null | /usr/local/bin/md5filter 256 './current_md5' > /dev/null 2> './err.log'";
    $result = system($command);#==0 || die "GetCheckSum() fails : $!";

    if($result == 0)
    {    
	open(MD5_FILE,"<current_md5") || die "GetCheckSum()  fails: $!";

	if(defined ($checksum = <MD5_FILE>)) 
	{
	    chomp($checksum);

	    if($checksum eq "d41d8cd98f00b204e9800998ecf8427e")
	    {
		$checksum = undef;
	    }
	}

	close(MD5_FILE) || die "GetCheckSum() fails : $!";
    }

    #DebugMessage("GetCheckSum() => [$result] [$checksum]\n");

   return $checksum;
}

#-------------------------------------------------------------------------------------
# GetCurrentTapePositions()  return tapes as a hash 
#
# where %tape_positions{"slot_number"} = "label" if there is a tape in slot number
#       %tape_positions("slot_number"} =  undef  if there is no tape in slot number
#
# ------------------------------------------------------------------------------------
# A sample output of Tape Robot "status" command
#
#  Storage Changer /dev/t50:1 Drives, 30 Slots ( 5 Import/Export )
#Data Transfer Element 0:Full (Storage Element 6 Loaded):VolumeTag = 000828L4
#      Storage Element 1:Full :VolumeTag=000829L4
#      Storage Element 2:Empty
#      ...
#      Storage Element 29 IMPORT/EXPORT:Empty
#      Storage Element 30 IMPORT/EXPORT:Full :VolumeTag=000822L4
#
#-------------------------------------------------------------------------------------

# Note: we use the \%tape_positions defined in caller function (rather than local %tape_positions)
#

sub GetCurrentTapePositions
{
    
    #my %tape_positions=();
    my ($line, $slot_number, $label);  

    
    open(COM,"mtx -f /dev/t50 status |") || die "GetTapePositions() fails : $!";
    while (defined ($line = <COM>)) 
    {
	chomp($line);

	if ($line =~ /VolumeTag/) # look for slot with tape (line has "VolumeTag") 
	{

	    if($line =~ /Data Transfer Element 0/) 
	    {
		$slot_number = "0";
			
		$label = (split(/ = /,$line))[1];
		#$label =~ s/^\s+//;
		$label =~ s/\s+$//;
	    }
	    else
	    {
		$slot_number = (split/[ :]/,(split(/Storage Element /,$line))[1])[0];
		$label = (split(/=/,$line))[1];
		$label =~ s/\s+$//;

	    }
	    
	    #print "line=[$line]slot=[$slotno]label=[$label]\n";

	    #$tape_positions{$slot_number} = $label;	    
	    $_[0]{$slot_number} = $label;
	}
    }
    close(COM) || die "can't close $!";


    #foreach $key (sort keys(%tapes)) 
    #{
    #	print "GetTapeLabels ". $key . " => " . $tapes{$key} . "\n";
    #}

    #return %tape_positions;

}


#-------------------------------------------------------------------------------------
# GetTimeString() return (ie: 2008.06.10_14:30:00)
#
# usage: $string = getTimeString( [$time_t] ); Omit parameter for current time/date

sub GetTimeString
{
    
    @_ = localtime(shift || time);
    return(sprintf("%04d.%02d.%02d_%02d:%02d:%02d",$_[5]+1900,$_[4]+1,$_[3],$_[2],$_[1],$_[0]));
    #($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
}

#-------------------------------------------------------------------------------------
# DebugMessage($message)

sub DebugMessage 
{
    if ($OFF_SITE_TAPE_VERIFICATION_DEBUG_MESSAGES)
    {
	# print to stdout
	print $_[0];

	# log to file
	unless($_[0] =~ /^GetCheckSum/) # skip line with GetCheckSum 	
	{
	    print LOG_OUTFILE $_[0];
	}
    }
}

#-------------------------------------------------------------------------------------
# CompareFilesAndReport(\@tapelist)
#
# For each tape in the list, read check_sums generated onsite and offsite into strings.
# Compare each lines (checksums) on a tape. 
# If they all matched, report success(0) else false (1)
#
# For example:
#
# 000822L4.md5         (generated onsite) 
# 000822L4.md5_offsite (generated offsite)
# HMI_2008.05.12_14:00:00:00.ver (compared results)
#
#
# Content of 000822L4.md5
# # /dds/socdc/000822L4.md5 from datacapture
# 1 307ab4d598e042e9dfa845fd5486d29a
# 2 af5fdd97d69fde10daf8122c6eda435f
#....
# Content of 000822L4.md5_offsite
# # 000607L4.md5_offsite generated by tape_verify.pl at 2008.06.12_22:27:15
# 1 307ab4d598e042e9dfa845fd5486d29a
# 2 af5fdd97d69fde10daf8122c6eda435f
#....
# Content of HMI_2008.05.12_14:00:00:00.ver
# # Offsite verify offhost:dds/off2ds/HMI_2008.06.12_22:40:29.ver
# # Tape   0=success
# 000822L4 0
# 000823L4 0
# #END
#....
#
# After generating all .md5_offsite for the current set of tapes,
# Here, it checks:
# 1. The existence of both .md5 and .md5_offsite for each tape
# 2. The length of both files (should be the same)
# 3. The correctness of all the md5s.
#
# %summary_report is a hash, containing detail report (tape_label => @error_list)
# If all above test passes 
#    @error_list would have one line (ie: Tape(000822L4:1-1500) => CHECKED.)
# Else
#    @report_list has the first line with the error status and details in the following lines
#


sub CompareFilesAndReport
{
    my $tapelist = $_[0];

    my ($ver_filename, $tape_label , $success, $number_of_tapes, $i);
    my (@lines_1, @lines_2, $filename_1, $filename_2, $len_1, $len_2);
    my (%summary_report, $error_list, $status);

   

    $success = 0;
    $number_of_tapes = scalar(@{$tapelist});

    foreach $tape_label (@$tapelist)
    {

	$error_list = []; # return a new reference to empty list


	# Check for missing files
	$filename_1 = $working_dir.$tape_label . ".md5";
	$filename_2 = $working_dir.$tape_label . ".md5_offsite";

        if ((-e $filename_1) and (-e $filename_2)) # if both files exist
        {
	    # Open, Read and Close at once
	    open (FILE_IN_1,"<$filename_1")  or die "can't open $filename_1: $!";
	    open (FILE_IN_2,"<$filename_2")  or die "can't open $filename_2: $!";
	    @lines_1 = <FILE_IN_1>;
	    @lines_2 = <FILE_IN_2>;
	    close FILE_IN_1;
	    close FILE_IN_2;


	    # Check for dimensions
	    $len_1 = scalar(@lines_1);
	    $len_2 = scalar(@lines_2);
	    
	    if($len_1 == $len_2)
	    {

		# Check each lines (except the first comment lines)
		for ($i = 1; $i < $len_1; $i++) 
		{
		    if($lines_1[$i] ne $lines_2[$i]) # wong md5
		    {
			$status = "Tape ($tape_label) => Wrong checksums.\n";
			push @{$error_list},  $status;
			last;
		    }	
		}
		
		if($i == $len_1) # all successfully checked!
		{
		    $i--;	   
                    $status  = "Tape ($tape_label:1-$i) => CHECKED.\n";
		    push @{$error_list} , $status;
		    $success++;
		}
		else # No, there are miss-match md5, append them to the @error_list
		{
		    chomp(@lines_1);
		    chomp(@lines_2);
		    for ($i = 1; $i < $len_1; $i++) 
		    {
			if($lines_1[$i] ne $lines_2[$i])
			{
			    $status = "[" . $lines_1[$i]. "] [". $lines_2[$i]. "]\n";
			    push @{$error_list}, $status; 
			}	
		    }

		} # append...
	    
	    }
	    else # wrong file size
	    {
		$status = "Tape ($tape_label) => Wrong file sizes.\n";
		push @{$error_list}, $status; 		
		$status = "$filename_1 ($len_1 files) $filename_2 ($len_2 files) \n";
		push @{$error_list}, $status;
	    }
	    
	
	}
	else # missing file
	{
	    $status = "Tape ($tape_label) => Missing (or empty) files.\n";
	    push @{$error_list}, $status; 

	    unless (-e $filename_1)
	    {
		$status = "$filename_1 is missing.\n";
		push @{$error_list}, $status;
	    }

	    unless (-e $filename_2)
	    {
		$status = "$filename_2 is missing.\n";
		push @{$error_list}, $status;
	    }

	}


	# Store reference of @error_list into %summary_report
	$summary_report{$tape_label} = $error_list;


    }# foreach $tape_label





    # Display SUMMARY REPORT 
    DebugMessage("\n----------------------------------------------------------------------------\n");
    DebugMessage("SUMMARY REPORT:\n\n");
    
    foreach $tape_label (@$tapelist)
    {
	DebugMessage(${$summary_report{$tape_label}}[0] , "\n");
    }

    DebugMessage("\ntape_verify.pl successfully checks $success tapes out of $number_of_tapes.\n");
    DebugMessage("----------------------------------------------------------------------------\n");




    # Writing SUMMARY REPORT to .ver

    $ver_filename = $working_dir . "HMI_" . GetTimeString() . ".ver";    
    open (VER_FILE, ">>$ver_filename") || die "CompareAndReport() Can't Open : $ver_filename $!\n";
	
    print VER_FILE "# Offsite verify offhost:dds/off2ds/" . $ver_filename . "\n";
    print VER_FILE "# Tape   0=success\n";
    
    foreach $tape_label (@$tapelist)
    {
	if(${$summary_report{$tape_label}}[0] =~ /CHECKED.$/) 	
	{
	    print VER_FILE "$tape_label 0\n";
	}
	else
	{
	    print VER_FILE "$tape_label 1\n";
	}
    }
    print VER_FILE "#END\n\n";


    print VER_FILE "----------------------------------------------------------------------------\n";
    
    # If error detected, append error_list found to .ver
    if($success < $number_of_tapes)
    {

	foreach $tape_label (@$tapelist)
	{
	    
	    #unless(${$summary_report{$tape_label}}[0] =~ /CHECKED.$/) 	
	    foreach $status (@{$summary_report{$tape_label}})
	    {
		print VER_FILE $status;
	    }
	    
	    print VER_FILE "----------------------------------------------------------------------------\n";
	}   

    }
    
    close VER_FILE;

    # If error detected, append "tape_verify.log" to .ver
    #if($success < $number_of_tapes)
    {    
	#system("cat tape_verify.log >> $ver_filename" )==0 || die "Could not dump tape_verify.log to .ver";
	system("cat $log_filename >> $ver_filename" )==0 || die "Could not dump $log_filename to .ver";
    }


}

#-------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------
# CompareHashesAndReport(\@tapelist)
#
# This is another way to compare 2 files if the line formats (spacings) are different between md5 and md5_offsite
#
# For each tape in the list (IMPORT/EXPORT slots), read check_sums generated onsite and offsite into hashes.
# Compare every check_sum (one for each file on tape)
# If they all matched, report success(0) else false (1)
#
# For example:
#
# 000822.md5         (generated onsite) 
# 000822.md5_offsite (generated offsite)
# HMI_2008.05.12_14:00:00:00.ver (compared results)
#

sub CompareHashesAndReport
{
    my $tapelist = $_[0];

    my ($ver_filename, $tape_label , $key, $value, $verified);
    my ($hash_1, $hash_2, $filename_1, $filename_2);


    
    $ver_filename = "HMI_" . GetTimeString() . ".ver";    
    open (FILE_OUT, ">>$ver_filename") || die "CompareAndReport() Can't Open : $ver_filename $!\n";
	
    print FILE_OUT "# Offsite verify offhost:dds/off2ds/" . $ver_filename . "\n";
    print FILE_OUT "# Tape   0=success\n";
    

    
    foreach $tape_label (@$tapelist)
    {
	$filename_1 = $tape_label . ".md5";
	$hash_1 = ReadMd5ToHash($filename_1);
	$filename_2 = $tape_label . ".md5_offsite";
	$hash_2 = ReadMd5ToHash($filename_2);

	
	# compare values 
	$verified = "0";


	foreach $key (keys %$hash_2) 
	{  
	    if($hash_1->{$key} ne $hash_2->{$key})
	    {
		$verified = "1";
		last;
	    }

	    DebugMessage("[$hash_1->{$key}] and [" . $hash_2->{$key} ."] => $verified\n");

	}

	print FILE_OUT $tape_label ." ". $verified . "\n";
	
    }

    close FILE_OUT;
    
}

#-------------------------------------------------------------------------------------
# ReadMD5ToHash(filename) return a hash.
#
# The onsite and offsite md5 should be identical (except for the first line), 
# The first comment line can be used as validity check (or skip it)
#

sub ReadMd5ToHash
{
    
    my ($filename) = $_[0];
    my ($expected_first_line, $line, @items);
    my %check_sums=();



    open (FILE_IN, $filename) || die "Can't Open : $filename $!\n";
    
    $line = <FILE_IN>; chomp($line); # Read first line  


    #------------------------------------------------------------------------
    # Validity check by comparing the first line with what is expected

    if(0)
    {

	if (/.md5_offsite$/, $filename) {
	    $expected_first_line = $filename . " from offsite tape verification";
	}
	else {
	    $expected_first_line = "# /dds/socdc/" . $filename  . " from datacapture";	
	}
    
	if ($line ne $expected_first_line) 
	{
	    DebugMessage("Invalid $filename (first line differs from $expected_first_line)\n");
	    close FILE_IN;
	    return undef;
	}
    }

    #----------------------------------------------------------------



    # Read each line into a hash

    while (<FILE_IN>) 
    {

	#print $_;

	s/#.*//;            # ignore comments by erasing them
	next if /^(\s)*$/;  # skip blank lines
	chomp;              # remove trailing newline characters
	       
 	@items = split(/ /,$_);
        $check_sums { $items[0] } = $items[1];

    }
    
    close FILE_IN;

    #print "Number of items: " . keys(%check_sums) . "\n";
    #PrintHash(\%check_sums);
    
    return \%check_sums;             

}

#-------------------------------------------------------------------------------------
