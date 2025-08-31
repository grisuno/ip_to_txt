package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/net/html"
)

const (
	DefaultWorkers = 500
	Timeout        = 10 * time.Second
	DBName         = "sites.db"
	UserAgent      = "Mozilla/5.0 LazyOwn RedTeam Scanner v1.0"
)

var (
	db        *sql.DB
	httpClient *http.Client
	mu         sync.Mutex
	wg         sync.WaitGroup
)

// initDB inicializa la base de datos
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", DBName)
	if err != nil {
		log.Fatal("Error abriendo DB:", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS sites (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT,
		domain TEXT,
		title TEXT,
		protocol TEXT,
		source TEXT DEFAULT 'ptr',
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS checkpoint (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		last_ip TEXT NOT NULL
	);
	`
	_, err = db.Exec(schema)
	if err != nil {
		log.Fatal("Error creando tablas:", err)
	}
}

// getLastCheckpoint devuelve la última IP escaneada por el algoritmo
func getLastCheckpoint() string {
	var ip string
	err := db.QueryRow("SELECT last_ip FROM checkpoint WHERE id = 1").Scan(&ip)
	if err != nil {
		return "1.1.1.1" // inicio por defecto
	}
	return ip
}

// setCheckpoint guarda la última IP procesada
func setCheckpoint(ipStr string) {
	mu.Lock()
	defer mu.Unlock()
	_, err := db.Exec(`INSERT OR REPLACE INTO checkpoint (id, last_ip) VALUES (1, ?)`, ipStr)
	if err != nil {
		log.Printf("Error guardando checkpoint %s: %v", ipStr, err)
	}
}

// wasIPProcessed verifica si una IP ya fue procesada como PTR
func wasIPProcessed(ipStr string) bool {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM sites WHERE ip = ? AND source = 'ptr'", ipStr).Scan(&count)
	return err == nil && count > 0
}

// ipToInt convierte IP string a uint32
func ipToInt(ipStr string) uint32 {
	parts := strings.Split(ipStr, ".")
	var ip uint32
	for _, part := range parts {
		var b uint32
		fmt.Sscanf(part, "%d", &b)
		ip = (ip << 8) + b
	}
	return ip
}

// intToIP convierte uint32 a string IP
func intToIP(ipInt uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		ipInt>>24&0xFF,
		ipInt>>16&0xFF,
		ipInt>>8&0xFF,
		ipInt&0xFF,
	)
}

// isPrivateIP verifica si una IP es privada
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate()
}

// reverseDNS realiza lookup inverso
func reverseDNS(ipStr string) (string, error) {
	names, err := net.LookupAddr(ipStr)
	if err != nil || len(names) == 0 {
		return "", err
	}
	return strings.TrimSuffix(names[0], "."), nil
}

// extractTitle extrae el <title> de HTML
func extractTitle(body []byte) string {
	reader := strings.NewReader(string(body))
	tokenizer := html.NewTokenizer(reader)
	for {
		tokenType := tokenizer.Next()
		switch tokenType {
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			if token.Data == "title" {
				tokenizer.Next()
				return strings.TrimSpace(tokenizer.Token().Data)
			}
		case html.ErrorToken:
			return "Sin título"
		}
	}
}

// fetchTitle intenta HTTP y luego HTTPS
func fetchTitle(domain, ipStr string) (string, string) {
	client := &http.Client{Timeout: Timeout}

	for _, scheme := range []string{"http", "https"} {
		url := fmt.Sprintf("%s://%s", scheme, domain)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", UserAgent)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			body := make([]byte, 10240)
			n, _ := resp.Body.Read(body)
			resp.Body.Close()

			title := extractTitle(body[:n])
			return title, scheme
		}
		resp.Body.Close()
	}
	return "", ""
}

// resolveDomainToIP resuelve un dominio a IP pública
func resolveDomainToIP(domain string) string {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return ""
	}
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			ipStr := ipv4.String()
			if !isPrivateIP(ipStr) {
				return ipStr
			}
		}
	}
	return ""
}

// getRootDomain extrae el dominio raíz (ej: google.com de mail.google.com)
func getRootDomain(domain string) string {
	// Dominios especiales de segundo nivel
	secondLevel := map[string]bool{
		"co.uk": true, "com.au": true, "com.mx": true, "com.ar": true,
		"com.br": true, "com.co": true, "com.pe": true, "com.ve": true,
		"net.uk": true, "org.uk": true,
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}

	if len(parts) >= 3 {
		last2 := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if secondLevel[last2] {
			if len(parts) >= 4 {
				return parts[len(parts)-4] + "." + parts[len(parts)-3] + "." + last2
			}
			return parts[len(parts)-3] + "." + last2
		}
	}

	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// runCrtSh busca subdominios usando crt.sh
func runCrtSh(domain string) []string {
	cmd := exec.Command("sh", "-c",
		fmt.Sprintf(`curl -s "https://crt.sh/?q=%%.%s&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\\*\\.//g' | sort -u`, domain))

	output, err := cmd.Output()
	if err != nil {
		log.Printf("Error en crt.sh para %s: %v", domain, err)
		return nil
	}

	var domains []string
	re := regexp.MustCompile(`[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}`)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		found := re.FindAllString(line, -1)
		for _, d := range found {
			d = strings.ToLower(d)
			if !contains(domains, d) {
				domains = append(domains, d)
			}
		}
	}
	return domains
}

// contains verifica si un slice tiene un string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// union combina dos slices sin duplicados
func union(a, b []string) []string {
	set := make(map[string]bool)
	var result []string
	for _, s := range a {
		if !set[s] {
			set[s] = true
			result = append(result, s)
		}
	}
	for _, s := range b {
		if !set[s] {
			set[s] = true
			result = append(result, s)
		}
	}
	return result
}

// saveToDB guarda un registro con source
func saveToDB(ipStr, domain, title, protocol, source string) {
	mu.Lock()
	defer mu.Unlock()
	_, err := db.Exec(`INSERT INTO sites (ip, domain, title, protocol, source) VALUES (?, ?, ?, ?, ?)`,
		ipStr, domain, title, protocol, source)
	if err != nil {
		log.Printf("Error guardando en DB: %v", err)
	} else {
		fmt.Printf("✅ [%s] %s [%s] → %s\n", source, domain, ipStr, title)
	}
}

// processPTRIP procesa una IP: PTR → dominio → web → crt.sh → subdominios
func processPTRIP(ipStr string) {
	// Evitar reprocesar IPs ya guardadas como ptr
	if wasIPProcessed(ipStr) {
		return
	}

	fmt.Printf("[→] Probando PTR: %s\n", ipStr)

	if isPrivateIP(ipStr) {
		fmt.Printf("[✗] IP privada, saltando: %s\n", ipStr)
		return
	}

	domain, err := reverseDNS(ipStr)
	if err != nil {
		return
	}

	domain = strings.ToLower(domain)
	fmt.Printf("[✓] PTR encontrado: %s → %s\n", ipStr, domain)

	title, protocol := fetchTitle(domain, ipStr)
	if title == "" {
		title = "Sin título"
	}

	// Guardar dominio PTR
	saveToDB(ipStr, domain, title, protocol, "ptr")

	// === 1. Buscar subdominios del dominio encontrado (ej: %.mail.google.com) ===
	subdomains := runCrtSh(domain)
	fmt.Printf("[🔍] Encontrados %d subdominios para: %s\n", len(subdomains), domain)

	// === 2. Esperar 1 segundo para ser respetuoso ===
	time.Sleep(1 * time.Second)

	// === 3. Extraer dominio raíz y buscar todos sus subdominios (ej: %.google.com) ===
	rootDomain := getRootDomain(domain)
	if rootDomain == domain {
		subdomains = union(subdomains, []string{domain})
	} else {
		fmt.Printf("[🔍] Buscando subdominios globales para dominio raíz: %s\n", rootDomain)
		time.Sleep(1 * time.Second)
		subdomains2 := runCrtSh(rootDomain)
		fmt.Printf("[🔍] Encontrados %d subdominios para dominio raíz: %s\n", len(subdomains2), rootDomain)
		subdomains = union(subdomains, subdomains2)
	}

	if len(subdomains) == 0 {
		return
	}

	// Resolver cada subdominio y guardar
	for _, sub := range subdomains {
		subIP := resolveDomainToIP(sub)
		if subIP == "" {
			continue
		}
		subTitle, subProto := fetchTitle(sub, subIP)
		if subTitle == "" {
			subTitle = "Sin título"
		}
		saveToDB(subIP, sub, subTitle, subProto, "crt")
	}
}

// scanIPsWithPTR escanea desde la última IP guardada + 1
func scanIPsWithPTR(endIP string, limit int) {
	endInt := ipToInt(endIP)
	scanCount := uint32(limit)

	if limit == 0 {
		scanCount = 0xFFFFFFFF // sin límite
	}

	// Obtener última IP procesada
	lastIPStr := getLastCheckpoint()
	lastInt := ipToInt(lastIPStr)

	// Empezar desde la siguiente IP
	startInt := lastInt + 1
	if startInt == 0 { // Overflow
		fmt.Println("✅ Alcanzado límite de IPv4 (255.255.255.255)")
		return
	}

	if startInt > endInt {
		fmt.Println("✅ Rango completado.")
		return
	}

	fmt.Printf("Iniciando desde IP: %s (última fue: %s)\n", intToIP(startInt), lastIPStr)
	fmt.Printf("Rango final: %s → %s\n", intToIP(startInt), endIP)

	sem := make(chan struct{}, DefaultWorkers)
	var scanned uint32
	var muScan sync.Mutex

	for ipInt := startInt; ipInt <= endInt; ipInt++ {
		muScan.Lock()
		if scanCount > 0 && scanned >= scanCount {
			muScan.Unlock()
			break
		}
		muScan.Unlock()

		ipStr := intToIP(ipInt)

		wg.Add(1)
		go func(ip string) {
			defer wg.Done() // ✅ Solo aquí
			sem <- struct{}{}
			processPTRIP(ip)
			<-sem
			setCheckpoint(ip)
		}(ipStr)

		muScan.Lock()
		scanned++
		muScan.Unlock()
	}

	wg.Wait()
	finalIP := intToIP(startInt + scanned - 1)
	setCheckpoint(finalIP)
	fmt.Printf("✅ Escaneo completado. Última IP procesada: %s\n", finalIP)
}

func main() {
	var limit int
	flag.IntVar(&limit, "limit", 100, "Número máximo de IPs a escanear. Usa 0 para sin límite.")
	flag.Parse()

	if limit == 0 {
		fmt.Println("\033[31m[!] Advertencia: Escaneo masivo de IPv4.\033[0m")
		fmt.Print("¿Continuar? (yes): ")
		var confirm string
		fmt.Scanln(&confirm)
		if confirm != "yes" {
			fmt.Println("Cancelado.")
			return
		}
	} else {
		fmt.Printf("[*] Límite: %d IPs\n", limit)
	}

	initDB()
	defer db.Close()

	httpClient = &http.Client{Timeout: Timeout}

	fmt.Println("[*] Iniciando escaneo con checkpoint...")
	scanIPsWithPTR("255.255.255.255", limit)
}
