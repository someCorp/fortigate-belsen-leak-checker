Parse and gather some info for the leak https://github.com/arsolutioner/fortigate-belsen-leak 

clone this repo
download affected_ips.txt and GeoLite2-City.mmdb in the repo's folder
-- run
python3 fortigate-belsen-leak-checker/someChecker.py --tld cl
-- should see something similar to
200.126.107.xx 1411x   200.126.107.x/24        No disponible
200.73.92.xxx  1874x   200.73.64.x/19          host242.200.73.xx.static.ifxnw.cl
216.241.2.xxx    1874x   216.241.2.x/24        hostxx.216.241.2.ifxnw.cl
200.73.69.xx   1874x   200.73.64.x/19          hostxx.200.73.69.static.ifxnw.cl
