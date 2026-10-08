# API

## app.py
- `is_private_ip` (function) `app.py:3` `def is_private_ip(ip_int)`
- `ip_to_int` (function) `app.py:16` `def ip_to_int(ip)`
- `generate_ips` (function) `app.py:20` `def generate_ips(start_ip, end_ip)`
- `int_to_ip` (function) `app.py:33` `def int_to_ip(ip_int)`
- `main` (function) `app.py:36` `def main()`

## ip_to_db.py
- `is_private_ip` (function) `ip_to_db.py:8` `def is_private_ip(ip_int)`
- `ip_to_domain` (function) `ip_to_db.py:20` `def ip_to_domain(ip_address)`
- `process_page` (function) `ip_to_db.py:28` `def process_page(domain)`
- `ip_to_int` (function) `ip_to_db.py:43` `def ip_to_int(ip)`
- `generate_ips` (function) `ip_to_db.py:48` `def generate_ips(start_ip, end_ip)`
- `int_to_ip` (function) `ip_to_db.py:66` `def int_to_ip(ip_int)`
- `save_to_db` (function) `ip_to_db.py:70` `def save_to_db(domain, title)`
- `main` (function) `ip_to_db.py:79` `def main()`

## main.go
- `initDB` (function) `main.go:35` `func initDB(` -- initDB inicializa la base de datos
- `getLastCheckpoint` (function) `main.go:65` `func getLastCheckpoint(` -- getLastCheckpoint devuelve la última IP escaneada por el algoritmo
- `setCheckpoint` (function) `main.go:75` `func setCheckpoint(` -- setCheckpoint guarda la última IP procesada
- `wasIPProcessed` (function) `main.go:85` `func wasIPProcessed(` -- wasIPProcessed verifica si una IP ya fue procesada como PTR
- `ipToInt` (function) `main.go:92` `func ipToInt(` -- ipToInt convierte IP string a uint32
- `intToIP` (function) `main.go:104` `func intToIP(` -- intToIP convierte uint32 a string IP
- `isPrivateIP` (function) `main.go:114` `func isPrivateIP(` -- isPrivateIP verifica si una IP es privada
- `reverseDNS` (function) `main.go:123` `func reverseDNS(` -- reverseDNS realiza lookup inverso
- `extractTitle` (function) `main.go:132` `func extractTitle(` -- extractTitle extrae el <title> de HTML
- `fetchTitle` (function) `main.go:151` `func fetchTitle(` -- fetchTitle intenta HTTP y luego HTTPS
- `resolveDomainToIP` (function) `main.go:178` `func resolveDomainToIP(` -- resolveDomainToIP resuelve un dominio a IP pública
- `getRootDomain` (function) `main.go:195` `func getRootDomain(` -- getRootDomain extrae el dominio raíz (ej: google.com de mail.google.com)
- `runCrtSh` (function) `main.go:222` `func runCrtSh(` -- runCrtSh busca subdominios usando crt.sh
- `contains` (function) `main.go:252` `func contains(` -- contains verifica si un slice tiene un string
- `union` (function) `main.go:262` `func union(` -- union combina dos slices sin duplicados
- `saveToDB` (function) `main.go:281` `func saveToDB(` -- saveToDB guarda un registro con source
- `processPTRIP` (function) `main.go:294` `func processPTRIP(` -- processPTRIP procesa una IP: PTR → dominio → web → crt.sh → subdominios
- `scanIPsWithPTR` (function) `main.go:361` `func scanIPsWithPTR(` -- scanIPsWithPTR escanea desde la última IP guardada + 1
- `main` (function) `main.go:422` `func main(`
