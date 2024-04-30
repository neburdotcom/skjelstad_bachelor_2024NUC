There are three scripts on this directory, one for durumeric definition of a scan, one for the case studies and one for geographical plotting of countries.
If you want to tweak the scripts behaviour you need to tweak on the below variables, a explonation is below.
You need to have a API key for Greynoise.io for case_studies.py work as intended.


----------------------------------------------------------------------------------------------------------------------------------------------------------


FOR THE DURUMERIC METHOD SCRIPT:

MIN_DESTINATIONS = minimum destination a source IP has probed to be counted as a scan
RATE_THRESHOLD = the minimuim packet rate to be deemed as a scan, in seconds. RATE_THRESHOLD of 10 would mean 10 packets per second
Output of the script is a CSV file with the headers= Date,Source IP,Network,Port,Distinct Destinations,Total Packets,Rate

----------------------------------------------------------------------------------------------------------------------------------------------------------

FOR THE CASE STUDY SCRIPT:

In the below variables shapefile_path you need to add the full path to the shapefile to corretly plot geographical identicly to the bachelor thesis.
Terminal will ask for input when needed at the start, after all is set up the script will run by itself, and report on when pcap files are done analysing. 

MIN_DESTINATIONS = minimum destination a source IP has probed to be counted as a scan
RATE_THRESHOLD = the minimuim packet rate to be deemed as a scan, in seconds. RATE_THRESHOLD of 10 would mean 10 packets per second
MIN_DURATION = minimum overall duration of a scan minutes. 
MAX_RATE_THRESHOLD = the maximum packet rate in seconds. MAX_RATE_THRESHOLD of 10 would mean a MAXIMUM 10 packets per second

Output of the script is a CSV file, and two geographical heatmaps, one for benign activity and one for malicious
The csv has the headers= Date,Source IP,Network,Port,Distinct Destinations,Total Packets,Rate

----------------------------------------------------------------------------------------------------------------------------------------------------------

HEATMAP SCRIPT

This script produces a geographical heatmap of the countries and counts you provide in the csv in the folder pasted in 'data_df'
You need to download the shapefile in the comment below for the script to work as intended
On line 37 you can change where the picture is saved along with the picture name. RIght now it just shows the plot, as plt.savefig is commented out.

The CSV needs to have the headers 'Country,Count', and the countries need to be in full name. If you want the countries in a 2 letter code, change the 'left_on' on line 24 to 'ISO_A2'
