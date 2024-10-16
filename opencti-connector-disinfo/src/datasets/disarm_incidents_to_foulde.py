# This program takes the incidents form the DISARM_DATA_MASTER_additions.xlsx file and transforms them into a CSV file with the format of the Foulde Hardy dataset.
import pandas as pd
import csv

# Read the Excel file
excel_file = "DISARM_DATA_MASTER_additions.xlsx"
incident_df = pd.read_excel(excel_file, sheet_name='incidents')
incident_techniques_df = pd.read_excel(excel_file, sheet_name='incidenttechniques')

# Foulde header:
header = "Year,Target Country,Event,Region,Sub-region,Country of Origin,Threat Actor,Event description, T0002_Facilitate State Propaganda,T0072_Segment Audiences,T0072.001_Geographic Segmentation,T0072.002_Demographic Segmentation,T0072.005_Political Segmentation,T0081.007_Identify Target Audience Adversaries,T0003_Leverage Existing Narratives,T0004_ Develop Competing Narratives,T0022_Leverage Conspiracy Theory Narratives,T0022.001_ Amplify Existing Conspiracy Theory  Narratives,T0068_Respond to Breaking News Event or Active Crisis,T0082_Develop New Narratives,T0083_Integrate Target Audience Vulnerabilities into Narrative,T0023_Distort Facts,T0023.001_Reframe Context,T0084.001_Use Copy Pasta,T0084.002_Plagiarise Content,T0084.003_Deceptively Labelled or Translated,T0084.004_Appropriate Content,T0085_Develop Text-Based Content,T0085.001_Develop AI-Generated Text,T0085.004_Develop Documents,T0085.003_Develop Inauthentic News Article,T0085.005_Develop Book,T0085.006_Develop Opinion Article,T0086_Develop Image-Based Content,T0086.001_Develop Memes,T0086.002_Develop AI-Generated Images (Deepfakes),T0086.004_Aggregate Information Into Evidence Collages,T0087_Develop Video-Based Content,T0087.001_Develop AI-Generated Videos (Deepfakes),T0087.002_Deceptively Edit Videos (Cheapfakes),T0088_Develop Audio-Based Content,T0088.002_Deceptively Edit Audio (Cheapfakes),T0089_Obtain Private Documents,T0089.001_Obtain Authentic Documents,T0089.003_Alter Authentic Documents,T0007_Create Inauthentic Social Media Pages and Groups,T0013_Create Inauthentic Websites,T0090_Create Inauthentic Accounts,T0090.004_Create Sockpuppet Accounts,T0091.001_Recruit Contractors,T0091.002_Recruit Partisans,T0094_Infiltrate Existing Networks,T0093_Acquire/Recruit Network,T0093.001_Fund Proxies,T0092_Build Network,T0092.001_Create Organisations,T0092.002_Use Follow Trains,T0092.003_Create Community or Sup-Group,T0095_Develop Owned Media Assets,T0096_Leverage Content Farms,T0096.001_Create Content Farms,T0096.002_Outsource Content Creation to External Organizations,T0141.001_Acquire Compromised Account,T0097_Create Personas,T0098.001_Create Inauthentic News Sites,T0098.002_Leverage Existing Inauthentic News Sites,T0099_Impersonate Existing Entities,T0142_Fabricate Grassroots Movement,T0016_Create Clickbait,T0018_Purchase Targeted Advertisements,T0101_Create Localised Content,T0029_Online Polls,T0043_Chat Apps,T0103.001_Video Livestream,T0104.001_Mainstream Social Networks,T0104.003_Private/Closed Social Networks,T0104.004_Interest-Based Networks,T0105.002_Video Sharing,T0105.003_Audio Sharing,T0106_Discussion Forums,T0106.001_Anonymous Message Boards,T0107_Bookmarking and Content Curation,T0108_Blogging and Publishing Networks,T0110_Formal Diplomatic Channels,T0111.001_TV,T0111.002_Newspaper,T0111.003_Radio,T0112_Email,T0046_Use Search Engine Optimization,T0113_Employ Commercial Analytic Firms,T0114_Deliver Ads,T0115_Post Content,T0115.001_Share Memes,T0116_Comment or Reply on Content,T0116.001_Post Inauthentic Social Media Comments,T0117_Attract Traditional Media,T0049_Flood Information Space,T0049.003_Bots Amplify via Automated Forwarding and Reposting,T0049.002_Flood Existing Hashtag,T0049.001_Trolls Amplify and Manipulate,T0039_Bait Influencers,T0119.001_Post across Groups,T0119.002_Post across Platforms,T0122_Direct Users to Alternative Platforms,T0048_Harass,T0048.002_Harass People Based on Identities,T0123_Control Information Environment through Offensive Cyberspace Operations,T0124_Suppress Opposition,T0124.003_Exploit Platform TOS/Content Moderation,T0057_Organise Events,T0057.001_Pay for Physical Action,T0057.002_Conduct Symbolic Action,T0126_Encourage Attendance at Events,T0126.002_Facilitate Logistics or Support for Attendance,T0061_Sell Merchandise,Facebook,Instagram,X,Youtube,TikTok,Telegram,Gab,Parler,Gettr,Truth Social,Vkontakte,Odnoklassniki,Reddit,4chan,Discord,Tumblr,Pinterest,Paypal,LiveJournal,Pastebin,Vimeo,WhatsApp,WeChat,Line,Fiverr,OpenAI,Cyber Attacks,Attribution Source: Government,Attribution Source: Platform,Attribution Source: Company,Attribution Source: Researchers/Journalists,Source 1,Source 2,Source 3,Source 4,Source 5,Source 6,Source 7,Source 8,,,,,,,,,,,,,"

with open('disarm_to_foulde.csv', 'w') as f:
    header = header.split(',')
    f.write(','.join(header) + '\n')

# Iterate over the merged dataframe
for index, row in incident_df.iterrows():
    
    print("Processing incident: {}.\tTechniques: ".format(row['name']), end=' ')

    incident_id = row['disarm_id']
    
    # Get the techniques for the incident
    technique_ids = incident_techniques_df[incident_techniques_df['incident_id'] == incident_id]['technique_ids']
    
    # The old columns are: disarm_id	name	objecttype	summary	year_started	attributions_seen	found_in_country	urls	notes	when_added	found_via	longname
    # And we have the techniques ids.
    # Now we want to transform that into a CSV wth the following columns: Year,Target Country,Event,Region,Sub-region,Country of Origin,Threat Actor,Event description, T0002_Facilitate State Propaganda,T0072_Segment Audiences,T0072.001_Geographic Segmentation,T0072.002_Demographic Segmentation,T0072.005_Political Segmentation,T0081.007_Identify Target Audience Adversaries,T0003_Leverage Existing Narratives,T0004_ Develop Competing Narratives,T0022_Leverage Conspiracy Theory Narratives,T0022.001_ Amplify Existing Conspiracy Theory  Narratives,T0068_Respond to Breaking News Event or Active Crisis,T0082_Develop New Narratives,T0083_Integrate Target Audience Vulnerabilities into Narrative,T0023_Distort Facts,T0023.001_Reframe Context,T0084.001_Use Copy Pasta,T0084.002_Plagiarise Content,T0084.003_Deceptively Labelled or Translated,T0084.004_Appropriate Content,T0085_Develop Text-Based Content,T0085.001_Develop AI-Generated Text,T0085.004_Develop Documents,T0085.003_Develop Inauthentic News Article,T0085.005_Develop Book,T0085.006_Develop Opinion Article,T0086_Develop Image-Based Content,T0086.001_Develop Memes,T0086.002_Develop AI-Generated Images (Deepfakes),T0086.004_Aggregate Information Into Evidence Collages,T0087_Develop Video-Based Content,T0087.001_Develop AI-Generated Videos (Deepfakes),T0087.002_Deceptively Edit Videos (Cheapfakes),T0088_Develop Audio-Based Content,T0088.002_Deceptively Edit Audio (Cheapfakes),T0089_Obtain Private Documents,T0089.001_Obtain Authentic Documents,T0089.003_Alter Authentic Documents,T0007_Create Inauthentic Social Media Pages and Groups,T0013_Create Inauthentic Websites,T0090_Create Inauthentic Accounts,T0090.004_Create Sockpuppet Accounts,T0091.001_Recruit Contractors,T0091.002_Recruit Partisans,T0094_Infiltrate Existing Networks,T0093_Acquire/Recruit Network,T0093.001_Fund Proxies,T0092_Build Network,T0092.001_Create Organisations,T0092.002_Use Follow Trains,T0092.003_Create Community or Sup-Group,T0095_Develop Owned Media Assets,T0096_Leverage Content Farms,T0096.001_Create Content Farms,T0096.002_Outsource Content Creation to External Organizations,T0141.001_Acquire Compromised Account,T0097_Create Personas,T0098.001_Create Inauthentic News Sites,T0098.002_Leverage Existing Inauthentic News Sites,T0099_Impersonate Existing Entities,T0142_Fabricate Grassroots Movement,T0016_Create Clickbait,T0018_Purchase Targeted Advertisements,T0101_Create Localised Content,T0029_Online Polls,T0043_Chat Apps,T0103.001_Video Livestream,T0104.001_Mainstream Social Networks,T0104.003_Private/Closed Social Networks,T0104.004_Interest-Based Networks,T0105.002_Video Sharing,T0105.003_Audio Sharing,T0106_Discussion Forums,T0106.001_Anonymous Message Boards,T0107_Bookmarking and Content Curation,T0108_Blogging and Publishing Networks,T0110_Formal Diplomatic Channels,T0111.001_TV,T0111.002_Newspaper,T0111.003_Radio,T0112_Email,T0046_Use Search Engine Optimization,T0113_Employ Commercial Analytic Firms,T0114_Deliver Ads,T0115_Post Content,T0115.001_Share Memes,T0116_Comment or Reply on Content,T0116.001_Post Inauthentic Social Media Comments,T0117_Attract Traditional Media,T0049_Flood Information Space,T0049.003_Bots Amplify via Automated Forwarding and Reposting,T0049.002_Flood Existing Hashtag,T0049.001_Trolls Amplify and Manipulate,T0039_Bait Influencers,T0119.001_Post across Groups,T0119.002_Post across Platforms,T0122_Direct Users to Alternative Platforms,T0048_Harass,T0048.002_Harass People Based on Identities,T0123_Control Information Environment through Offensive Cyberspace Operations,T0124_Suppress Opposition,T0124.003_Exploit Platform TOS/Content Moderation,T0057_Organise Events,T0057.001_Pay for Physical Action,T0057.002_Conduct Symbolic Action,T0126_Encourage Attendance at Events,T0126.002_Facilitate Logistics or Support for Attendance,T0061_Sell Merchandise,Facebook,Instagram,X,Youtube,TikTok,Telegram,Gab,Parler,Gettr,Truth Social,Vkontakte,Odnoklassniki,Reddit,4chan,Discord,Tumblr,Pinterest,Paypal,LiveJournal,Pastebin,Vimeo,WhatsApp,WeChat,Line,Fiverr,OpenAI,Cyber Attacks,Attribution Source: Government,Attribution Source: Platform,Attribution Source: Company,Attribution Source: Researchers/Journalists,Source 1,Source 2,Source 3,Source 4,Source 5,Source 6,Source 7,Source 8,,,,,,,,,,,,,
    # The binding will be for each row: Year-year_started, Target Country-found_in_country, Event-name, Region-found_in_country, Sub-region-NA, Country of Origin-NA, Threat Actor-attributions_seen, Event description-summary, (put a 1 in the column of the technique if it is in the technique_ids)..., (we put the channels manually), (fill the sources separating the urls field by spaces).
    # We will write the CSV to a file called disarm_to_foulde.csv

    with open('disarm_to_foulde.csv', 'a', encoding="utf-8", newline='') as f:
        newincidentrow = [row['year_started'], row['found_in_country'], row['name'], row['found_in_country'], '', '', 
                          row['attributions_seen'] if pd.notna(row['attributions_seen']) else 'Unknown', 
                          row['summary'] if pd.notna(row['summary']) else 'No description']

        # Marking the techniques used (this is brute force :D)
        for technique in header[header.index('Event description')+1:header.index('Facebook')]:
            # Check what technique_id appears in the list of techniques of the dataframe
            found = '0'
            for technique_id in technique_ids:
                if technique.startswith(technique_id):
                    found = '1'
                    #print("Does {} start with {}?".format(technique_id, technique), end=' ')
                    #print (found)
                    print(technique, end=', ')
                    break
            newincidentrow.append(found)


        # Channels (empty for now)
        newincidentrow.extend(['0' for i in range (header.index("OpenAI") - header.index("Facebook")+1)])

        # Cyber Attacks (not for now)
        newincidentrow.append('0')

        # Attribution Source  (not for now)
        newincidentrow.extend(['0' for i in range(4)])

        # Sources (we have it in DISARM incidents separated by ,)
        sources = str(row['urls']).split()
        for i in range(8):
            if i < len(sources):
                newincidentrow.append(sources[i])
            else:
                newincidentrow.append('')
        # Last commas
        newincidentrow.extend(['' for i in range(13)])

        # Lets add the row to the CSV 
        csvwriter = csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        csvwriter.writerow(newincidentrow)
        print("")


print("CSV file created successfully!")