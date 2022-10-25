#!/usr/bin/env python3
# encoding=UTF-8

import subprocess
import sys
import os
from datetime import datetime


#####################################################################################################
####                                                                                             ####
#### init_test_tshark                                                                            ####
####                                                                                             ####

def init_test_tshark():
    # Add Wireshark program folder to PATH
    if sys.platform == 'win32':
        # In order to make sure tshark is in the windows PATH
        os.environ['PATH'] += ';C:\Program Files\Wireshark'

    # Print tshark version or else error out
    try:
        version_message = subprocess.Popen(
            ['tshark', '-v'], stdout=subprocess.PIPE).communicate()[0]
        # version message includes license, so let's take first line
        print(version_message.splitlines()[0].decode("UTF-8"))

    # If the tshark executable doesn't exist or isn't on path
    except FileNotFoundError:
        print("ERROR: Tshark is not installed"
              "\nOn some OSes, it comes bundled with Wireshark.")
    
    return

####                                                                                             ####
#####################################################################################################


#####################################################################################################
####                                                                                             ####
#### get_pcap_aantal_packets                                                                            ####
####                                                                                             ####

def get_pcap_aantal_packets( pcap_in ):

    a = subprocess.check_output(
        ['capinfos', '-c', pcap_in],
        shell=True)
            
    b = a.decode()
    c = b.split('\r\n')
    cap_aantal_packets = ( c[1].split(':',1) )[1].lstrip()

    return cap_aantal_packets

####                                                                                             ####
#####################################################################################################


#####################################################################################################
####                                                                                             ####
#### check_pcap_time_stamps                                                                      ####
####                                                                                             ####

def check_pcap_time_stamps( pcap_in, start_time, end_time ):

    a = subprocess.check_output(
        ['capinfos', '-a', '-e', pcap_in],
        shell=True)
            
    b = a.decode()
    c = b.split('\r\n')
    cap_start_time = ( c[1].split(':',1) )[1].lstrip()
    cap_end_time = ( c[2].split(':',1) )[1].lstrip()

    cap_start_time = cap_start_time.rsplit(',')[0]
    cap_end_time = cap_end_time.rsplit(',')[0]
    print( "\t\t" + cap_start_time )
    print( "\t\t" + cap_end_time )
    #print( "\t\t" + cap_start_time, "\t-\t" + cap_end_time )
    #print()
            
    cap_start_time = datetime.strptime( cap_start_time, "%Y-%m-%d %H:%M:%S" )
    cap_end_time = datetime.strptime( cap_end_time, "%Y-%m-%d %H:%M:%S" )
    #difference = cap_end_time - cap_start_time
    #print( difference )
    #print( difference.days )
    #print( difference.seconds )

    return ( cap_start_time >= start_time and cap_start_time <= end_time ) or ( cap_end_time >= start_time and cap_end_time <= end_time )

####                                                                                             ####
#####################################################################################################


#####################################################################################################
####                                                                                             ####
#### check_number                                                                                ####
####                                                                                             ####

def check_number( number ):
    if number.lower().endswith(' k') : 
        index_nr = number.find(' k')      
        number = 1000*int( number[:index_nr] )
    elif number.lower().endswith(' m') : 
        index_nr = number.find(' m')      
        number = 1000*1000*int( number[:index_nr] )
    return number
    

####                                                                                             ####
#####################################################################################################

#####################################################################################################
####                                                                                             ####
#### shark_filter_dir                                                                            ####
####                                                                                             ####

def shark_filter_dir( dir_in, file_ext, start_time, end_time, pcap_filters, results_dir, tmp_filter_file_suffix ):
    
    totaal_aantal_pakketten = 0
    for file in os.listdir( dir_in ):
        if file.endswith( file_ext ):
            pcap_in = os.path.join( dir_in, file )
            print( "\tInput file: ", pcap_in )
            
            filter_bool = check_pcap_time_stamps( pcap_in, start_time, end_time )
            #print("result: " + str(filter_bool) )

            if filter_bool :
                filtered_pcap = shark_filter_file( pcap_in, pcap_filters, results_dir, tmp_filter_file_suffix )
                aantal_packets = get_pcap_aantal_packets( filtered_pcap )
                print( "\t\tOutput file: ", filtered_pcap, " ( aantal pakketten: ", aantal_packets, ")")
                totaal_aantal_pakketten += int( check_number( aantal_packets ) )
            else:
                print( "\t\tFile not filtered due to non-matching time stamps" )
    
    return totaal_aantal_pakketten

####                                                                                             ####
#####################################################################################################


#####################################################################################################
####                                                                                             ####
#### shark_filter_file                                                                           ####
####                                                                                             ####

def shark_filter_file( pcap_in, pcap_filters, results_dir, file_out_suffix ):
    """
    :arg: Pcap file, pcap filters, output directory and file suffix
    :return: Output pcap file
    """
    pcap_out, ext = os.path.basename(pcap_in).split('.')
    pcap_out += file_out_suffix + '.' + ext
    #pcap_out = results_dir + '/' + pcap_out
    pcap_out = os.path.join( results_dir, pcap_out )
    
    subprocess.call(
        ['tshark', '-n', '-r', pcap_in, '-Y', pcap_filters, '-w', pcap_out],
        shell=True)

    return pcap_out

####                                                                                             ####
#####################################################################################################
    
    
#####################################################################################################
####                                                                                             ####
#### merge pcap bestanden                                                                        ####
####                                                                                             ####

def merge_pcap( files_in_dir, files_in_suffix, file_out_pcap ):
    """
    :arg: files_in_dir, file_in_suffix, file_out_pcap
    :return: Output pcap file
    """

    merged_pcap = files_in_dir + '/' + file_out_pcap
    files_in = files_in_dir + '/' + '*' + files_in_suffix + '.pcap'

    subprocess.call(
        ['mergecap', '-w', merged_pcap, files_in],
        shell=True)
    
    #print( "\tMerged file: ", merged_pcap )

    return merged_pcap

####                                                                                             ####
#####################################################################################################

   
#####################################################################################################
####                                                                                             ####
#### remove temp bestanden in directory                                                          ####
####                                                                                             ####

def remove_pcap_dir( files_in_dir, suffix_ext ):
    """
    :arg: files_in_dir, suffix_ext
    :return: 
    """

    for file in os.listdir( files_in_dir ):
        if file.endswith( suffix_ext ):
            #remove file       
            remove_file( os.path.join( files_in_dir , file ) )            
    return

####                                                                                             ####
#####################################################################################################


#####################################################################################################
####                                                                                             ####
#### remove temp bestand                                                                         ####
####                                                                                             ####

def remove_file( file_del ):
    """
    :arg: files_del
    :return: 
    """

    #remove file         
    subprocess.call( 
        ['del', file_del],
        shell=True)
    print( "\tRemoved file: ", file_del )    

    return

####                                                                                             ####
#####################################################################################################

#####################################################################################################
####                                                                                             ####
#### get number                                                                                  ####
####                                                                                             ####
   
def get_next_number( results_dir, file_start ):

    number = 1
    for file in os.listdir( results_dir ):
        if file.startswith( file_start ):
            number += 1
    
    if number < 10: number = "0" + str(number)
    return number
    
####                                                                                             ####
#####################################################################################################

####
#### init variables
####

# relative input and output directories 
input_dir = 'tapbestanden_2022_10_06'
results_dir = 'results'

# file names and suffixes
file_results_base = 'filter_results_'
file_ext = ".pcap"
tmp_filter_file_suffix = '_out'
merged_suffix = "_MERGED" 
final_suffix = "_FINAL"

# indicate whether temp files need to be removed
remove_temp_filtered_files = True
remove_temp_merged_files = True

# define time period
# pcap files with 1 or more records in this period will be filtered
start_time = '2022-10-06 09:00:00'
end_time = '2022-10-06 14:00:00'

#define wireshark filter (other than time)
pcap_filters = ''
pcap_filters += '( ip.src == 192.168.3.52 )'
pcap_filters += ' or '
pcap_filters += '( ip.dst == 192.168.3.52 )'
pcap_filters += ' or '
pcap_filters += '( wlan.addr == 70:CD:0D:0D:A9:71  )'


####   
#### programma
####

# compose datetime variables from start and end time
start_time = datetime.strptime( start_time, "%Y-%m-%d %H:%M:%S" )
end_time = datetime.strptime( end_time, "%Y-%m-%d %H:%M:%S" )

# compose wireshark time filter
time_filter = ''
time_filter += '(frame.time >= \"{}\" )'.format(start_time)
time_filter += ' and '
time_filter += '(frame.time <= \"{}\" )'.format(end_time)

print()
init_test_tshark()

print()
print("Time period: ", start_time, "  -  ", end_time)

print()
print("Start filtering files")  
print("\tFilter: ", pcap_filters)
total_packets = shark_filter_dir( input_dir, file_ext, start_time, end_time, pcap_filters, results_dir, tmp_filter_file_suffix )

print()
print("Start merging filtered files") 
number = get_next_number( results_dir, file_results_base )
print("\tNumber: ", number )
file_results_base += str(number) + merged_suffix
merged_pcap = merge_pcap( results_dir, tmp_filter_file_suffix, file_results_base + file_ext ) 
aantal_packets = get_pcap_aantal_packets( merged_pcap )
print( "\tMerged file: ", merged_pcap , " ( aantal pakketten: ", aantal_packets, ")")
if ( int( check_number( aantal_packets )) != int( total_packets ) ):
    print("\tERROR: aantal pakketten in merged file (", aantal_packets ,") klopt niet met aantal pakketten uit gefilterde files (", total_packets ,") !")

print()
print("Start filtering merged file using time filter")
print("\tTime_filter: ", time_filter)
file_results = os.path.join( results_dir, file_results_base + file_ext )
final_pcap = shark_filter_file( file_results, time_filter, results_dir, final_suffix )
aantal_packets = get_pcap_aantal_packets( final_pcap )
print( "\tTime filtered merged file: ", final_pcap , " ( aantal pakketten: ", aantal_packets, ")")


# clean up temporary files
if remove_temp_filtered_files or remove_temp_merged_files:
    print()
    print("Start removing temporary files")

if remove_temp_filtered_files:
    suffix_ext = tmp_filter_file_suffix + file_ext
    remove_pcap_dir( results_dir, suffix_ext )  

if remove_temp_merged_files:
    suffix_ext = merged_suffix + file_ext
    remove_pcap_dir( results_dir, suffix_ext ) 

print()
print("FINISHED")
        
####                                                                                             ####
#####################################################################################################
    