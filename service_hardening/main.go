package main

import (
	"database/sql"  //Libreria para interactuar con bases de datos SQL
	"encoding/json" //Codificar y decodificar JSON
	"fmt"           //Formatear cadenas y errores
	"log"           //Mostrar logs
	"net/http"      //Solicitudes HTTP
	"os"            //Leer variables de entorno y archivos
	"path/filepath" //Manipular rutas de archivos
	"strings"       //Manipular cadenas de texto

	_ "github.com/lib/pq" //Driver de PostgreSQL para la libreria database/sql
)

type SystemConfig struct { // Estructura del archivo config.json de cada máquina
	MachineID    string `json:"machine_id"`
	OS           string `json:"os"`
	Antivirus    string `json:"antivirus"`
	Firewall     string `json:"firewall"`
	SSHRootLogin string `json:"ssh_root_login"`
	AutoUpdate   string `json:"auto_update"`
}

type PostgresStore struct { // PostgresStore-Patrón Repository Encapsula la lógica de acceso a datos y proporciona una interfaz para interactuar con la base de datos
	db *sql.DB
}

func NewPostgresStore(connStr string) (*PostgresStore, error) {
	db, err := sql.Open("postgres", connStr) // Abre conexión PostgreSQL usando la cadena de conexión brindada
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return &PostgresStore{db: db}, nil // Regresa la instancia de PostgresStore con la conexión abierta
}

// UpdateHardeningStatus actualiza el estado de la máquina en PostgreSQL
func (s *PostgresStore) UpdateHardeningStatus(id string, status string) error {
	query := `UPDATE machines SET hardening_status = $1 WHERE id = $2`
	_, err := s.db.Exec(query, status, id)
	return err
}

var store *PostgresStore

type HardeningResponse struct { //HardeningResponse estructura la respuesta JSON para el frontend
	MachineID string `json:"machine_id"`
	Status    string `json:"status"`
	Message   string `json:"message"`
}

func applyHardeningPolicy(machineID string) (bool, string, error) { //applyHardeningPolicy lee, evalúa y corrige el archivo config.json
	configPath := filepath.Join("/app/data", machineID, "config.json") //Construye la ruta al archivo config.json de la máquina específica
	fileData, err := os.ReadFile(configPath)                           //Lee el contenido del archivo config.json
	if err != nil {
		return false, "", fmt.Errorf("no se pudo leer config.json: %v", err)
	}

	var config SystemConfig
	if err := json.Unmarshal(fileData, &config); err != nil { //Parsea el contenido JSON del archivo config.json en la estructura SystemConfig
		return false, "", fmt.Errorf("error parseando json: %v", err)
	}

	modificado := false //Hardening
	if config.Antivirus != "Enabled" {
		config.Antivirus = "Enabled"
		modificado = true
	}
	if config.Firewall != "Active" {
		config.Firewall = "Active"
		modificado = true
	}
	if config.SSHRootLogin != "Disabled" {
		config.SSHRootLogin = "Disabled"
		modificado = true
	}
	if config.AutoUpdate != "Enabled" {
		config.AutoUpdate = "Enabled"
		modificado = true
	}

	if modificado { //Si la configuracuón no es la correcta se reescribe el JSON
		newData, err := json.MarshalIndent(config, "", "  ") //Codificación a JSON de Hardening correcto
		if err != nil {
			return false, "", fmt.Errorf("error serializando el nuevo json: %v", err)
		}

		if err := os.WriteFile(configPath, newData, 0644); err != nil { // Guardar con permisos restrictivos (644), osea lectura y escritura para el propietario, y solo lectura para otros
			return false, "", fmt.Errorf("error guardando config.json: %v", err)
		}
		return true, "Hardening aplicado: Se corrigieron vulnerabilidades en la configuración.", nil
	}

	return false, "Hardening auditado: El sistema ya cumple con la política de seguridad.", nil
}

func hardeningHandler(w http.ResponseWriter, r *http.Request) { //Si llega una solicitud POST hardening/machine_id, se aplica la política de hardening

	machineID := strings.TrimPrefix(r.URL.Path, "/api/hardening/") //Se toma el string que viene después de /api/hardening/ y se guarda en machineID
	if machineID == "" || machineID == "/api/hardening" {
		http.Error(w, "machine_id required in path", http.StatusBadRequest)
		return
	}

	// 1- Aplicar la política en los archivos
	_, msg, err := applyHardeningPolicy(machineID) //Se llama función para aplicar hardening y se guarda el mensaje de resultado en msg
	if err != nil {
		log.Printf("Error aplicando hardening a %s: %v", machineID, err)
		http.Error(w, "Error interno procesando archivo de configuración", http.StatusInternalServerError)
		return
	}

	// 2- Actualizar el estado en PostgreSQL a "OK"
	if err := store.UpdateHardeningStatus(machineID, "OK"); err != nil {
		log.Printf("Error actualizando DB para %s: %v", machineID, err)
		http.Error(w, "Error actualizando base de datos", http.StatusInternalServerError)
		return
	}

	// 3. Responder al Frontend
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(HardeningResponse{
		MachineID: machineID,
		Status:    "OK",
		Message:   msg,
	})
}

func heartbeatHandler(w http.ResponseWriter, r *http.Request) { //Responde a las solicitudes de heartbeat que el backend está vivo
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("hardening backend alive"))
}

var instanceID = "unknown"

func withInstanceHeader(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { //Header X-Instance-Id a todas las respuestas HTTP para identificar la instancia del servicio que está respondiendo
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

	var err error                          //Creamos variable error y no variable store porque queremos que store sea global y accesible en todo el paquete
	store, err = NewPostgresStore(connStr) //Crea una instancia de PostgresStore
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer store.db.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/hardening/", withInstanceHeader(hardeningHandler)) //Solicitudes POST para aplicar hardening a una máquina específica
	mux.HandleFunc("/heartbeat", withInstanceHeader(heartbeatHandler))      //Responde a las solicitudes de heartbeat indicando que el backend de hardening está vivo

	log.Printf("Service Hardening [%s] listening on :8080", instanceID)
	log.Fatal(http.ListenAndServe(":8080", mux))
}
