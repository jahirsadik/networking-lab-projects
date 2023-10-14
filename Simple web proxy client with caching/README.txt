- Open a terminal in this folder and run using the command,

		python SimpleClientWithCache.py <url>

- Running it will create a ./cache folder with cached .html files
        and open the html file in default browser

-- Code Assumptions --
1. Filenames are hash output of their domain & path info (unique)
2. First test if the server is alive using HEAD method
3. Cache the file only if last-modified date is specified
4. Tested using several links, workes perfectly with the books 
        authors test link at: http://gaia.cs.umass.edu/ethereal-labs/lab2-2.html