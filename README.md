# VolUtility
Web Interface for Volatility Memory Analysis framework


## Overview
Runs plugins and stores the output in a mongo database. 
Extracts files from plugins (that support dump-dir) and stores them in the database
Search across all plugins and file content with string search and yara rules.
Allows you to work on multiple images in one database

Video Demo showing some of the features.
https://www.youtube.com

## Installation
Tested on Ubuntu 14.04 LTS

### Volatility
You need to install volatility. Minimum version is 2.5.
2.5 is needed as this is when unified output was introduced.

```
git clone https://github.com/volatilityfoundation/volatility
cd volatility
sudo python setup.py install
```

VolUtility will list what version you have installed under the Help page (At least it will soon)

### Mongo & PyMongo
Install mongodb version 3 or higher first. 
https://docs.mongodb.org/v3.0/tutorial/install-mongodb-on-ubuntu/

Then install pymongo
```sudo pip install pymongo```

### Django
```sudo pip install django```

### Other
```sudo pip install virustotal-api```

### Get the code

```git clone https://github.com/kevthehermit/VolUtility```

### VirusTotal
If you would like to add a virus total key

create a file in the web directory named vt_key.py
In the file add a single line
```API_KEY = 'YourKeyHere'```


### Run The Code
cd VolUtility
```./manage.py runserver 0.0.0.0:8000```

browse to http://your.ip:8000

File paths are on the box thats running the interface. This does not Upload mem dumps. Just points to them

## Using VolUtility

#### Basic usage
Create a new session then click the run button next to each plugin name. Plugins run in the background and you will be notified when a plugin completes. 
Click the view button next to each plugin to view the output, that can be searched and filtered. 

#### Plugins
You can add extra plugin directories for example the Volatility Community plugin pack. 
This must be done before creating a new session. Any sessions created after this will include the extra plugins. 

#### Vol Command Line.
In the session page, on the toolbar there is an option to run vol commands. This takes a full vol.py command string without the ```vol.py```. 
e.g.

```--plugin-dir=/path/to/dir --profile=Win7SP1x86 -f /path/to/image.vmem procdump --dump-dir=/path/to/dump```

## Clean the DB
The following commands will erase all data in the Volutility Database
```
mongo
use voldb
db.dropDatabase()
use voldbfs
db.dropDatabase()
exit
```

## ToDo:

  - Select plugins to run when importing image. 
  - Update the following plugins to support unified output (On Volatility, Not here)
  - pstree
    - bitlocker
    - chromedownloadchains 
    - pstree
    - wndscan 
    - dumpregistry 
    - userhandles 
    - sessions
  - More support for other plugins  
  - Better Error handling for vol plugins
  - Memory Threat Score. Use signature based analysis on plugins as they run to generate a threat score for the image. 
  - Add extra features to file sections, like PE info etc.
  - Global Search across all sessions.
  
  
## Help

## Thanks
Volatility Foundation for writing Volatility - http://www.volatilityfoundation.org/
Alissa Torres for teaching me memory via SANS FOR526 - https://twitter.com/sibertor
Using volatility as a library - http://dsocon.blogspot.co.uk/2012/08/using-volatility-framework-as-library.html
James Habben's origional eVolve concept - https://github.com/JamesHabben/evolve