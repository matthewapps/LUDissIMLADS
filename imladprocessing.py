import csv

import numpy as np
import pandas as pd
import gc as gc
import time
from datetime import datetime
from datetime import datetime, timedelta
from numba import jit
from probables import (CountMinSketch)
import matplotlib.pyplot as plt
pd.set_option('display.max_columns', None)

#Folder for extracts from wiresharks
tld_in = "/Users/mattmini/1. Dissertation/D.pcapExtracts/trimmed_"
#Folder for output files
tld_out = "/Users/mattmini/1. Dissertation/C.pcapAnalysis/"
#Output extension
lblFN = ".csv"

#Print start time
starttime =time.time()
print(datetime.utcfromtimestamp(starttime).strftime('%Y-%m-%d %H:%M:%S'))
#Input column headers
hdrblk = "ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents   label   detailed-label"
columnnames = hdrblk.split("	")

hdr ="ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents   label   detailed-label"



#Filename index
sld=["CTU-IoT-Malware-Capture-34-1", #0
         "CTU-IoT-Malware-Capture-43-1", #1
         "CTU-IoT-Malware-Capture-44-1", #2
         "CTU-IoT-Malware-Capture-49-1", #3
         "CTU-IoT-Malware-Capture-52-1", #4
         "CTU-IoT-Malware-Capture-20-1", #5
         "CTU-IoT-Malware-Capture-21-1", #6
         "CTU-IoT-Malware-Capture-42-1", #7
         "CTU-IoT-Malware-Capture-60-1", #8
         "CTU-IoT-Malware-Capture-17-1", #9
         "CTU-IoT-Malware-Capture-36-1", #10
         "CTU-IoT-Malware-Capture-33-1", #11
         "CTU-IoT-Malware-Capture-8-1",  #12
         "CTU-IoT-Malware-Capture-35-1", #13
         "CTU-IoT-Malware-Capture-48-1", #14
         "CTU-IoT-Malware-Capture-39-1", #15
         "CTU-IoT-Malware-Capture-7-1",  #16
         "CTU-IoT-Malware-Capture-9-1",  #17
         "CTU-IoT-Malware-Capture-3-1",  #18
         "CTU-IoT-Malware-Capture-1-1",  #19
         "CTU-IoT-Honeypot-Capture-4-1",  #20
         "CTU-IoT-Honeypot-Capture-5-1",  #21
         "CTU-IoT-Honeypot-Capture-7-1", ] #22

# index of target ip addresses for each file
addresses=["192.168.1.195", "192.168.1.198", "192.168.1.199", "192.168.1.193","192.168.1.197", "192.168.100.103","192.168.100.113","192.168.1.197","192.168.1.195","192.168.100.111",
"192.168.1.198","192.168.1.197" , "192.168.100.113" ,"192.168.1.195","192.168.1.200","192.168.1.194","192.168.100.108","192.168.100.111","192.168.2.5","192.168.100.103",'192.168.1.132','192.168.2.3']

#specify files to process in this run
files_to_process=[0,2,5,6,7,12,16,17,18,19,20,21]
#files_to_process=[7]
#files_to_process=[17]
#files_to_process=[20]

timewindow =60 #  window in seconds
EWMA = 5
EWMAadjust=False
if EWMAadjust:
    fileext="Adjust"
else:
    fileext = ""

#Write output files
def write_to_csv(df, filename, hdr):
    with open(filename, 'w', newline='') as csvfile:
        f = csv.writer(csvfile, delimiter=' ', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        #f.writerow(hdr)
        df.to_csv(filename, mode='a', index=False,header=True)
        #f.close()
        print (sld[sld_tsv]+" - Step 6 completed  FILE SAVED TO DISK")

def timegroup(dt, timestamp, timewindow):
     return round((dt - datetime(timestamp.year, timestamp.month, timestamp.day,timestamp.hour,timestamp.minute,timestamp.second)).total_seconds()/timewindow)

#Calculate UCL & LCL
@jit
def ucllclcalc( ewma_previous, errormean):
    lcl = ewma_previous - 1.96 * abs(errormean)
    ucl= ewma_previous + 1.96 * abs(errormean)
    ucl=max(ucl,0)
    lcl = max(lcl, 0)
    return lcl,ucl

#Calculate UCL & LCL
def ucllcl(df):
    errormean=0
    ewma_previous=0
    for index, row in df.iterrows():
        lcl , ucl  = ucllclcalc(ewma_previous, errormean)
        df.at[index,'LCL']=lcl
        df.at[index, 'UCL']=ucl
        actual_previous=row[3]
        ewma_previous=row[6]
        error=abs(actual_previous-ewma_previous)
        errormean=(error+(errormean*index))/(index+1)
        df.at[index, 'errormean'] = errormean

#Create Charts
def plotresults(dfresultsforDevice,EWMA,timewindow,file):
    dfresultsforDevice[['Count','EWMA','UCL']].plot()
    plottitle=file+":  EWMA span = "+str(EWMA)+", time window = "+str(timewindow)+" adjust="+ str(EWMAadjust) +" "+ str(datetime.now().isoformat(timespec='minutes'))
    plt.suptitle(plottitle, fontsize=8)
    plt.show()
    dfresultsforDevice[['COUNTEXCEEDSUCL']].plot()
    plottitle = file + ":  EWMA span = " + str(EWMA) + ", time window = " + str(timewindow) + " adjust=" + str(
        EWMAadjust) + " " + str(datetime.now().isoformat(timespec='minutes'))
    plt.suptitle(plottitle, fontsize=8)
    plt.show()

# main
for sld_tsv in files_to_process:
    print(sld[sld_tsv] + " -Process Started")
    df1 = pd.DataFrame({'No': pd.Series([], dtype='int'),
                        'Time': pd.Series([], dtype='float32'),
                        'Source': pd.Series([], dtype='str'),
                        'Destination': pd.Series([], dtype='str'),
                        'Protocol': pd.Series([], dtype='str'),
                        'Length': pd.Series([], dtype='int'),
                        'DateTime': pd.Series([], dtype='datetime64[ns]')})

    df1 =pd.read_csv(tld_in + sld[sld_tsv] + lblFN, parse_dates=True)

    print(tld_in + sld[sld_tsv] + lblFN)
    print(df1.head())
    print(df1.info())
    df1 = df1[df1['Destination'].eq(addresses[sld_tsv])].copy()

    # Step 1 Create a datetime column and tag the entries with minutes since the start -
    # minutes since the start will determine the time group
    df1['DateTime'] = pd.to_datetime(df1['DateTime'])
    df1.set_index(pd.DatetimeIndex(df1['DateTime']))
    first_timestamp = df1.iloc[0, 6]
    print(first_timestamp)
    df1['timegroup'] = df1.apply (lambda row: timegroup(row["DateTime"],first_timestamp,timewindow), axis=1)
    df1.sort_values(by=['timegroup','DateTime'], inplace=True)

    # Initialise the countsketch
    cms = CountMinSketch(width=100000, depth=20)

    # Initialise dataframe
    dfresults = pd.DataFrame({'DateTime': pd.Series([], dtype='datetime64[ns]'),
                              'Dest-IP': pd.Series([], dtype='str'),
                              'Timegroup': pd.Series([], dtype='int'),
                              'Count': pd.Series([], dtype='int'),
                              'ActualCount': pd.Series([], dtype='int'),
                              'ts': pd.Series([], dtype='float64')})

    #Initialise the variables
    currenttimegroup = 0
    tg = 0
    actualcount=1
    cmscount=0

    #Group the timegroup
    for index, row in df1.iterrows():
        memberoftimegroup = row[7]
        print ("No", row[0], "Time", row[1],'Source', row[2], 'Destination',row[3], 'Protocol',row[4],'Length', row[5],'DateTime', row[6], 'Timegroup',row[7],"/",tg)
        print("actualcount:", actualcount,' csmscount:',cmscount)
        mDateTime = row[6]
        mDestIP = row[3]
        ts = datetime.timestamp(row[6])
        if memberoftimegroup != currenttimegroup:
            cmscount = cms.check(row[3])
            dfresults=dfresults.append({'DateTime': mDateTime,'Dest-IP': mDestIP, 'Timegroup': currenttimegroup, 'Count': cmscount,'ActualCount':actualcount,'ts':ts}, ignore_index=True)
            print("=============================================================>" )
            cms = CountMinSketch(width=100000, depth=20)
            currenttimegroup=memberoftimegroup
            tg=tg+1
            actualcount = 0

        cms.add(row[3])
        actualcount=actualcount+1

    # Initialise final dataframe dataframe
    dfresultsforDevice = pd.DataFrame({'DateTime': pd.Series([], dtype='float64'),
                                       'Dest-IP': pd.Series([], dtype='str'),
                                       'Timegroup': pd.Series([], dtype='int'),
                                       'Count': pd.Series([], dtype='int'),
                                       'EWMA': pd.Series([], dtype='float32'),
                                       'Error': pd.Series([], dtype='float32'),
                                       'LCL': pd.Series([], dtype='float32'),
                                       'UCL': pd.Series([], dtype='float32'),
                                       'COUNTEXCEEDSUCL': pd.Series([], dtype='float32'),
                                       'ActualCount': pd.Series([], dtype='int'),
                                       'ts': pd.Series([], dtype='float64'),
                                      })

    dfresultsforDevice = dfresults[dfresults['Dest-IP'].eq(addresses[sld_tsv])].copy()

    #prep the final df
    dfresultsforDevice.set_index('Timegroup')
    dfresultsforDevice.sort_values(by=['Timegroup', 'DateTime'], inplace=True)

    #Calculate the EWMA
    dfresultsforDevice['EWMA']=dfresults['Count'].ewm(span=EWMA,adjust=EWMAadjust).mean()

    #Calculate the difference between the EWMA and the count (count=number of packets = to the number of rows in the timegroup)
    dfresultsforDevice['Error'] = dfresultsforDevice["Count"] - dfresultsforDevice["EWMA"]

    dfresultsforDevice.loc[dfresultsforDevice['Error'] < 0, 'Error'] = dfresultsforDevice['Error'] * -1

    #calculate the UCL and LCL
    ucllcl(dfresultsforDevice)

    #Calculate the difference
    dfresultsforDevice['COUNTEXCEEDSUCL'] = dfresultsforDevice["Count"] - dfresultsforDevice["UCL"]
    #dfresultsforDevice.loc[dfresultsforDevice['COUNTEXCEEDSUCL'] < 0, 'COUNTEXCEEDSUCL'] = dfresultsforDevice['COUNTEXCEEDSUCL'] *-1

    dfresultsforDevice.loc[dfresultsforDevice['COUNTEXCEEDSUCL'] <= 0, 'ANOMALY'] = 0
    dfresultsforDevice.loc[dfresultsforDevice['COUNTEXCEEDSUCL'] > 0, 'ANOMALY'] = 1

    plotresults(dfresultsforDevice,EWMA,timewindow,sld[sld_tsv])
    filecat="TG_"+str(timewindow)+"_EWMA_"+str(EWMA)+"_pcapAnalysis_"
    filename = tld_out + filecat + sld[sld_tsv].split('/')[0] + ".csv"
    write_to_csv(dfresults, filename, hdr)
    filename = tld_out + filecat + "pcapAnalysis_device"+sld[sld_tsv].split('/')[0] + "_V2"+fileext+".csv"
    write_to_csv(dfresultsforDevice, filename, hdr)


print(dfresults.info())
print(dfresults.head())
print(dfresults.tail())
print(dfresultsforDevice.info())
print(dfresultsforDevice.head())
print(dfresultsforDevice.tail())
endtime=time.time()
duration=endtime-starttime
print("\nStarted: ")
print(datetime.utcfromtimestamp(starttime).strftime('%Y-%m-%d %H:%M:%S'))

print("\nEnded : ")
print(datetime.utcfromtimestamp(endtime).strftime('%Y-%m-%d %H:%M:%S'))

print("\nThe whole process took : ",duration/60,"mins")
