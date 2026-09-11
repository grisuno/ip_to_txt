# Subsystem: root

## app.py
- Layer: utility
- Language: py
- Symbols:
  - `is_private_ip` (function, line 3) `def is_private_ip(ip_int)`
  - `ip_to_int` (function, line 16) `def ip_to_int(ip)`
  - `generate_ips` (function, line 20) `def generate_ips(start_ip, end_ip)`
  - `int_to_ip` (function, line 33) `def int_to_ip(ip_int)`
  - `main` (function, line 36) `def main()`

## ip_to_db.py
- Layer: utility
- Language: py
- Symbols:
  - `is_private_ip` (function, line 8) `def is_private_ip(ip_int)`
  - `ip_to_domain` (function, line 20) `def ip_to_domain(ip_address)`
  - `process_page` (function, line 28) `def process_page(domain)`
  - `ip_to_int` (function, line 43) `def ip_to_int(ip)`
  - `generate_ips` (function, line 48) `def generate_ips(start_ip, end_ip)`
  - `int_to_ip` (function, line 66) `def int_to_ip(ip_int)`
  - `save_to_db` (function, line 70) `def save_to_db(domain, title)`
  - `main` (function, line 79) `def main()`

## main.go
- Layer: utility
- Language: go
- Symbols:
  - `initDB` (function, line 35) `func initDB(`
  - `getLastCheckpoint` (function, line 65) `func getLastCheckpoint(`
  - `setCheckpoint` (function, line 75) `func setCheckpoint(`
  - `wasIPProcessed` (function, line 85) `func wasIPProcessed(`
  - `ipToInt` (function, line 92) `func ipToInt(`
  - `intToIP` (function, line 104) `func intToIP(`
  - `isPrivateIP` (function, line 114) `func isPrivateIP(`
  - `reverseDNS` (function, line 123) `func reverseDNS(`
  - `extractTitle` (function, line 132) `func extractTitle(`
  - `fetchTitle` (function, line 151) `func fetchTitle(`
  - `resolveDomainToIP` (function, line 178) `func resolveDomainToIP(`
  - `getRootDomain` (function, line 195) `func getRootDomain(`
  - `runCrtSh` (function, line 222) `func runCrtSh(`
  - `contains` (function, line 252) `func contains(`
  - `union` (function, line 262) `func union(`
  - `saveToDB` (function, line 281) `func saveToDB(`
  - `processPTRIP` (function, line 294) `func processPTRIP(`
  - `scanIPsWithPTR` (function, line 361) `func scanIPsWithPTR(`
  - `main` (function, line 422) `func main(`
