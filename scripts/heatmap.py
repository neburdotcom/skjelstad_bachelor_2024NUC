#RUBEN SKJELSTAD 30.04.2024
#!#/usr/bin/python3

#This script produces a geographical heatmap of the countries and counts you provide in the csv in the folder pasted in 'data_df'
#You need to download the shapefile in the comment below for the script to work as intended
#On line 37 you can change where the picture is saved along with the picture name. RIght now it just shows the plot, as plt.savefig is commented out.

#--------------------------------------------------------------------------------------------------------------------------------------------------

#The CSV needs to have the headers 'Country,Count', and the countries need to be in full name. If you want the countries in a 2 letter code, change the 'left_on' on line 24 to 'ISO_A2'

import pandas as pd
import geopandas as gpd
import matplotlib.pyplot as plt
from matplotlib.colors import Normalize

# Load csv
data_df = pd.read_csv(r'path\to\the\country\file\scans_malicious_countries.csv')

# Shapefile https://www.naturalearthdata.com/downloads/10m-cultural-vectors/
world = gpd.read_file(r'path\to\the\shapefile\ne_10m_admin_0_countries.shp')

# ISO_A2 for 2 letter codes, ADMIN for whole name
world = world.merge(data_df, how="left", left_on="ADMIN", right_on="Country")

# Exclude Antarctica from the DataFrame
world = world[world['ISO_A3'] != 'ATA']

MAX_VALUE = 250
fig, ax = plt.subplots(1, 1, figsize=(18, 10))
world.plot(column='Count', ax=ax, legend=True, cmap='gnuplot',
           norm=Normalize(vmin=0, vmax=MAX_VALUE),
           legend_kwds={'orientation': "horizontal",
                        'shrink': 0.5,
                        'aspect': 20,
                        'pad': 0.05},
           missing_kwds={'color': 'lightgrey'}, edgecolor='black', linewidth=0.1)
ax.set_ylim(-59, 90)
plt.subplots_adjust(left=0.045, bottom=0.0, right=0.964, top=1, wspace=0.2, hspace=0.2)

#plt.savefig(r'path/to/your/picture/output/main_definition_all_scans.png', dpi=300, format='png')
plt.show()