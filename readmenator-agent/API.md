# API

## app.py

### is_private_ip (function) `def is_private_ip(ip_int)`
- Defined: `app.py:3`

### ip_to_int (function) `def ip_to_int(ip)`
- Defined: `app.py:16`

### generate_ips (function) `def generate_ips(start_ip, end_ip)`
- Defined: `app.py:20`

### int_to_ip (function) `def int_to_ip(ip_int)`
- Defined: `app.py:33`

### main (function) `def main()`
- Defined: `app.py:36`

## ip_to_db.py

### is_private_ip (function) `def is_private_ip(ip_int)`
- Defined: `ip_to_db.py:8`

### ip_to_domain (function) `def ip_to_domain(ip_address)`
- Defined: `ip_to_db.py:20`

### process_page (function) `def process_page(domain)`
- Defined: `ip_to_db.py:28`

### ip_to_int (function) `def ip_to_int(ip)`
- Defined: `ip_to_db.py:43`

### generate_ips (function) `def generate_ips(start_ip, end_ip)`
- Defined: `ip_to_db.py:48`

### int_to_ip (function) `def int_to_ip(ip_int)`
- Defined: `ip_to_db.py:66`

### save_to_db (function) `def save_to_db(domain, title)`
- Defined: `ip_to_db.py:70`

### main (function) `def main()`
- Defined: `ip_to_db.py:79`

## main.go

### initDB (function) `func initDB(`
- Defined: `main.go:35`
- Doc: initDB inicializa la base de datos

### getLastCheckpoint (function) `func getLastCheckpoint(`
- Defined: `main.go:65`
- Doc: getLastCheckpoint devuelve la última IP escaneada por el algoritmo

### setCheckpoint (function) `func setCheckpoint(`
- Defined: `main.go:75`
- Doc: setCheckpoint guarda la última IP procesada

### wasIPProcessed (function) `func wasIPProcessed(`
- Defined: `main.go:85`
- Doc: wasIPProcessed verifica si una IP ya fue procesada como PTR

### ipToInt (function) `func ipToInt(`
- Defined: `main.go:92`
- Doc: ipToInt convierte IP string a uint32

### intToIP (function) `func intToIP(`
- Defined: `main.go:104`
- Doc: intToIP convierte uint32 a string IP

### isPrivateIP (function) `func isPrivateIP(`
- Defined: `main.go:114`
- Doc: isPrivateIP verifica si una IP es privada

### reverseDNS (function) `func reverseDNS(`
- Defined: `main.go:123`
- Doc: reverseDNS realiza lookup inverso

### extractTitle (function) `func extractTitle(`
- Defined: `main.go:132`
- Doc: extractTitle extrae el <title> de HTML

### fetchTitle (function) `func fetchTitle(`
- Defined: `main.go:151`
- Doc: fetchTitle intenta HTTP y luego HTTPS

### resolveDomainToIP (function) `func resolveDomainToIP(`
- Defined: `main.go:178`
- Doc: resolveDomainToIP resuelve un dominio a IP pública

### getRootDomain (function) `func getRootDomain(`
- Defined: `main.go:195`
- Doc: getRootDomain extrae el dominio raíz (ej: google.com de mail.google.com)

### runCrtSh (function) `func runCrtSh(`
- Defined: `main.go:222`
- Doc: runCrtSh busca subdominios usando crt.sh

### contains (function) `func contains(`
- Defined: `main.go:252`
- Doc: contains verifica si un slice tiene un string

### union (function) `func union(`
- Defined: `main.go:262`
- Doc: union combina dos slices sin duplicados

### saveToDB (function) `func saveToDB(`
- Defined: `main.go:281`
- Doc: saveToDB guarda un registro con source

### processPTRIP (function) `func processPTRIP(`
- Defined: `main.go:294`
- Doc: processPTRIP procesa una IP: PTR → dominio → web → crt.sh → subdominios

### scanIPsWithPTR (function) `func scanIPsWithPTR(`
- Defined: `main.go:361`
- Doc: scanIPsWithPTR escanea desde la última IP guardada + 1

### main (function) `func main(`
- Defined: `main.go:422`
