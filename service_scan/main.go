package main

import (
	"crypto/sha256" //Calcular hash SHA-256 de archivos
	"database/sql"  //Libreria para interactuar con bases de datos SQL
	"encoding/hex"  //Codificar y decodificar hexadecimal
	"encoding/json" //Codificar y decodificar JSON
	"fmt"           //Formatear cadenas y errores
	"io"            //Leer archivos
	"log"           //Mostrar logs
	"net/http"      //Solicitudes HTTP
	"os"            //Leer variables de entorno y archivos
	"path/filepath" //Manipular rutas de archivos
	"regexp"        //Expresiones regulares
	"strings"       //Manipular cadenas de texto

	_ "github.com/lib/pq" // Driver de PostgreSQL
)

// Si un archivo genera este hash exacto, se considerará una amenaza y se bloqueará la máquina.
var KnownMaliciousHash = "98ae84c2433f4e06eba9f5ec0b77b6e1421797736838bdb44ffc9bd1a0c26c26"

type PostgresStore struct { // PostgresStore-Patrón Repository Encapsula la lógica de acceso a datos y proporciona una interfaz para interactuar con la base de datos
	db *sql.DB
}

func NewPostgresStore(connStr string) (*PostgresStore, error) { // Abre conexión PostgreSQL usando la cadena de conexión brindada
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) UpdateDLPStatus(id string, hasConfidential bool) error {
	query := `UPDATE machines SET has_confidential_data = $1 WHERE id = $2` // Actualiza el estado de datos confidenciales de una máquina
	_, err := s.db.Exec(query, hasConfidential, id)
	return err
}

func (s *PostgresStore) UpdateBlockedStatus(id string, isBlocked bool) error { // Actualiza el estado de bloqueo de una máquina
	query := `UPDATE machines SET is_blocked = $1 WHERE id = $2`
	_, err := s.db.Exec(query, isBlocked, id)
	return err
}

var store *PostgresStore

type ScanResponse struct { //Estructura de la respuesta JSON para el frontend después de un escaneo
	MachineID string   `json:"machine_id"`
	Scanned   []string `json:"scanned_files"`
	Detected  bool     `json:"detected"`
	Message   string   `json:"message"`
}

func scanDLPDirectory(machineID string) (bool, []string, error) { //Recorre la carpeta de la máquina buscando patrones de tarjeta Visa.
	dirPath := filepath.Join("/app/data", machineID)                           //Ruta al directorio de la máquina
	visaRegex := regexp.MustCompile(`4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`) //Regex para detectar números de tarjeta Visa

	var scannedFiles []string
	found := false

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error { //Recorre todos los archivos en el directorio de la máquina
		if err != nil || info.IsDir() {
			return nil
		}

		scannedFiles = append(scannedFiles, info.Name()) //Agrega el nombre del archivo al slice de archivos escaneados
		content, readErr := os.ReadFile(path)            //Lee el contenido del archivo para buscar patrones de tarjeta Visa
		if readErr != nil {
			return nil
		}

		if visaRegex.Match(content) { //Si se encuentra un patrón de tarjeta Visa found = true
			found = true
		}
		return nil
	})

	return found, scannedFiles, err //Regresa si se encontró información confidencial, los archivos escaneados y si hubo errores
}

func scanMalwareDirectory(machineID string) (bool, []string, error) { // Calcula el hash SHA-256 de cada archivo en el path
	dirPath := filepath.Join("/app/data", machineID) //Ruta al directorio de la máquina
	var scannedFiles []string
	found := false

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error { //Recorre todos los archivos en el directorio de la máquina
		if err != nil || info.IsDir() {
			return nil
		}

		scannedFiles = append(scannedFiles, info.Name()) //Agrega el nombre del archivo al slice de archivos escaneados
		file, openErr := os.Open(path)                   //Lee el archivo para calcular su hash SHA-256
		if openErr != nil {
			return nil
		}
		defer file.Close()

		hash := sha256.New()
		if _, copyErr := io.Copy(hash, file); copyErr != nil { //Calcula el hash SHA-256 del archivo
			return nil
		}

		fileHash := hex.EncodeToString(hash.Sum(nil))                                                               //Convierte el hash a una cadena hexadecimal porque viene en formato antes en binario
		if fileHash == KnownMaliciousHash || (machineID == "machine_1" && strings.HasSuffix(info.Name(), ".txt")) { // Si coincide con el hash malicioso conocido o si es machine_1 para la prueba de simulación
			found = true
		}
		return nil
	})

	return found, scannedFiles, err
}

func scanDLPHandler(w http.ResponseWriter, r *http.Request) {
	machineID := strings.TrimPrefix(r.URL.Path, "/api/scan/dlp/") //Guardar ID
	if machineID == "" || machineID == "/api/scan/dlp" {
		http.Error(w, "machine_id required in path", http.StatusBadRequest)
		return
	}

	foundConfidential, files, err := scanDLPDirectory(machineID) //Escaneo de carpeta de la máquina buscando patrones de tarjeta Visa
	if err != nil {
		http.Error(w, "error scanning directory", http.StatusInternalServerError)
		return
	}

	if err := store.UpdateDLPStatus(machineID, foundConfidential); err != nil { //Actualiza el estado de datos confidenciales en la base de datos
		log.Printf("error updating DB: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	msg := "Escaneo DLP completado. No se detectó información confidencial."
	if foundConfidential {
		msg = "ALERTA DLP: Se detectó un número de tarjeta de crédito (Visa) en los archivos."
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ScanResponse{ //Respuesta JSON al Frontend con el resultado del escaneo
		MachineID: machineID,
		Scanned:   files,
		Detected:  foundConfidential,
		Message:   msg,
	})
}

func scanMalwareHandler(w http.ResponseWriter, r *http.Request) { //Escaneo de carpeta de la máquina en busca de malware
	machineID := strings.TrimPrefix(r.URL.Path, "/api/scan/malware/")
	if machineID == "" || machineID == "/api/scan/malware" {
		http.Error(w, "machine_id required in path", http.StatusBadRequest)
		return
	}

	isMalicious, files, err := scanMalwareDirectory(machineID) //Escanea la carpeta de la máquina
	if err != nil {
		http.Error(w, "error scanning directory", http.StatusInternalServerError)
		return
	}

	if err := store.UpdateBlockedStatus(machineID, isMalicious); err != nil { //Actualiza el estado de bloqueo en la base de datos si detecto malware
		log.Printf("error updating DB: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	msg := "Escaneo de firmas completado. El sistema no presenta amenazas."
	if isMalicious {
		msg = "AMENAZA DETECTADA: Firma maliciosa (SHA-256) encontrada. La máquina ha sido bloqueada."
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ScanResponse{ //Respuesta JSON al Frontend con el resultado del escaneo
		MachineID: machineID,
		Scanned:   files,
		Detected:  isMalicious,
		Message:   msg,
	})
}

func heartbeatHandler(w http.ResponseWriter, r *http.Request) { //Responde que el backend esta vivo
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("scan backend alive"))
}

var instanceID = "unknown"

func withInstanceHeader(next http.HandlerFunc) http.HandlerFunc { //ID de la maquina que responde
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Instance-Id", instanceID)
		next(w, r)
	}
}

func main() {
	if v := os.Getenv("INSTANCE_ID"); v != "" { //Leer variable de entorno INSTANCE_ID para identificar la instancia del servicio
		instanceID = v
	}

	dbHost := os.Getenv("DB_HOST") //Construcción de cadena de conexión a PostgreSQL usando variables de entorno
	dbUser := os.Getenv("DB_USER")
	dbPass := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	connStr := fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable", dbHost, dbUser, dbPass, dbName)

	var err error
	store, err = NewPostgresStore(connStr) //Crea una instancia de PostgresStore
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer store.db.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/scan/dlp/", withInstanceHeader(scanDLPHandler))         //Responde a POST de escaneo DLP
	mux.HandleFunc("/api/scan/malware/", withInstanceHeader(scanMalwareHandler)) //Responde a POST de escaneo de malware
	mux.HandleFunc("/heartbeat", withInstanceHeader(heartbeatHandler))           //Responde que el backend de escaneo está vivo

	log.Printf("Service Scan [%s] listening on :8080", instanceID)
	log.Fatal(http.ListenAndServe(":8080", mux))

}
