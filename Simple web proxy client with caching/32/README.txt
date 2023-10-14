-- How to Run --
	- Open a terminal in this folder and run using the command,

			Python SimpleClientWithCache.py <url>

	- Running it will create a ./cache folder with cached .html files
	        and open the html file in default browser

-- Tracefile Explanation --
	1. Filter tracefile using 'http'
	2. Last http response has status code 304 as it was not modified
	3. No request was sent after getting status code 304, as the file was 
	        fetched from the cache
	4. Due to assumption that we have to check if server is alive by using the
	        HEAD method, there were multiple HEAD method HTTP requests sent

-- Code Assumptions --
	1. Filenames are hash output of their domain & path info (unique)
	2. First test if the server is alive using HEAD method
	3. Cache the file only if last-modified date is specified
	4. Tested using several links, workes perfectly with the books 
        	     authors test link at: http://gaia.cs.umass.edu/ethereal-labs/lab2-2.html