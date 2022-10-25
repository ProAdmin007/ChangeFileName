# Python 3 code to rename multiple
# files in a directory or folder
 
# importing os module
import datetime
import os
import re
 
# Function to rename multiple files
def main():
    count = 0  
    folder = "C:/DATA/tapbestanden_2022_10_06"
    for count, filename in enumerate(os.listdir(folder)):
        # get file packet number
        packetnummer = re.findall('\d+', filename)
        # file modification timestamp of a file
        data1 = "C:/DATA/tapbestanden_2022_10_06/",filename
        data = ''.join(data1)
        m_time = os.path.getmtime(data)
        # convert timestamp into DateTime object
        dt_m = (datetime.datetime.fromtimestamp(m_time).strftime('%Y-%m-%d %H;%M'))
        dst = f"capture_{str(packetnummer[0])}_{str(dt_m)}.pcap"
        src =f"{folder}/{filename}"  # foldername/filename, if .py file is outside folder
        dst =f"{folder}/{dst}"
         
        # rename() function will
        # rename all the files
        os.rename(src, dst)
        count +=1
    print(count, " Bestanden zijn aangepast!")
 
# Driver Code
if __name__ == '__main__':
     
    # Calling main() function
    main()