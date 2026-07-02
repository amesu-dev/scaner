# Simple Passive Scaner
## Description
This tool created for passive scaning servers by domain name.
<br>**Warning**: It send sigle http request to get information about certeficate!

Usage: `./dist/scaner <domain> <port>`

## Code
This code was wroten by few days. The author finds the code messy. After all, this was a learning project, not a real tool for remote system reconnaissance. I apologize for the confusing functions in places. Perhaps I'll tidy up the code later.

(Yeah, there is my auth key from FOFA. So what? Replace it or use directly. I dont care)

## Instalation and build
First of all you should install dependencies:
```bash
apt install libssl-dev libcurl4-openssl-dev nlohmann-json3-dev
```
You can build with `build.bash` or command:
```bash
cd dist
cmake .. -DCMAKE_BUILD_TYPE=Release -DTEST_BUILD=0
```
Param `TEST_BUILD=1` compiles only entry of `src/test`.
<br>`TEST_BUILD=0` compiles `src/` exluding `src/test`.