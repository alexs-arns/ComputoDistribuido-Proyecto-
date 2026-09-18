package main

import (
	"database/sql"  //Libreria para interactuar con bases de datos SQL
	"encoding/json" //Codificar y decodificar JSON
	"fmt"           //Formatear cadenas y errores
	"log"           //Mostrar logs
	"net/http"      //Solicitudes HTTP
	"os"            //Leer variables de entorno y archivos
	"strings"       //Manipular strings

	_ "github.com/lib/pq" // Driver de PostgreSQL
)

type Machine struct { // Estructura de la tabla machines en PostgreSQL
	ID                  string `json:"id"`
	HardeningStatus     string `json:"hardening_status"`
	HasConfidentialData bool   `json:"has_confidential_data"`
	IsOnline            bool   `json:"is_online"`
	IsBlocked           bool   `json:"is_blocked"`
}

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

func (s *PostgresStore) InitSchema() error { //Crea la tabla machines si no existe y agrega registros default
	query := `
	CREATE TABLE IF NOT EXISTS machines (
		id VARCHAR(50) PRIMARY KEY,
		hardening_status VARCHAR(20) DEFAULT 'FAIL',
		has_confidential_data BOOLEAN DEFAULT false,
		is_online BOOLEAN DEFAULT true,
		is_blocked BOOLEAN DEFAULT false
	);

	INSERT INTO machines (id, hardening_status) VALUES 
		('machine_1', 'FAIL'), 
		('machine_2', 'FAIL'), 
		('machine_3', 'FAIL') 
	ON CONFLICT (id) DO NOTHING;
	`
	_, err := s.db.Exec(query)
	return err
}

func (s *PostgresStore) GetAll() ([]Machine, error) { //Obtiene todas las máquinas de la base de datos y devuelve un slice de Machine
	rows, err := s.db.Query("SELECT id, hardening_status, has_confidential_data, is_online, is_blocked FROM machines ORDER BY id") //Consulta SQL para obtener todas las máquinas ordenadas por ID
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var machines []Machine
	for rows.Next() { //Itera sobre cada fila del resultado de la consulta y escanea los valores en una instancia de Machine
		var m Machine
		if err := rows.Scan(&m.ID, &m.HardeningStatus, &m.HasConfidentialData, &m.IsOnline, &m.IsBlocked); err != nil { //Escanea los valores de la fila actual en la estructura Machine
			return nil, err
		}
		machines = append(machines, m)
	}
	return machines, nil //Devuelve el slice de máquinas y un error (si lo hay)
}

func (s *PostgresStore) Get(id string) (Machine, bool) { //Devuelve una máquina por su ID
	var m Machine
	err := s.db.QueryRow("SELECT id, hardening_status, has_confidential_data, is_online, is_blocked FROM machines WHERE id = $1", id).
		Scan(&m.ID, &m.HardeningStatus, &m.HasConfidentialData, &m.IsOnline, &m.IsBlocked) //Consulta SQL para obtener una máquina por su ID
	if err != nil {
		if err == sql.ErrNoRows {
			return Machine{}, false
		}
		log.Printf("error getting machine %s: %v", id, err)
		return Machine{}, false
	}
	return m, true
}

// store Instancia global del repositorio
var store *PostgresStore

func machinesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		machines, err := store.GetAll()
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			log.Printf("DB error: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(machines)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func machineHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/machines/") //Extracción del ID de la URL, ej: /api/machines/machine_1

	if id == "" {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	switch r.Method { //GET para obtener información de una máquina específica
	case http.MethodGet:
		machine, ok := store.Get(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(machine)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func heartbeatHandler(w http.ResponseWriter, r *http.Request) { //Responde a las solicitudes que el backend está vivo
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("machines backend alive"))
}

var instanceID = "unknown"

func withInstanceHeader(next http.HandlerFunc) http.HandlerFunc { //Header X-Instance-Id para identificar la instancia del servicio que está respondiendo
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Instance-Id", instanceID)
		next(w, r)
	}
}

func main() {
	if v := os.Getenv("INSTANCE_ID"); v != "" {
		instanceID = v
	}

	dbHost := os.Getenv("DB_HOST") //Construcción de cadena de conexión a PostgreSQL usando variables de entorno
	dbUser := os.Getenv("DB_USER")
	dbPass := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	connStr := fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable", dbHost, dbUser, dbPass, dbName)

	var err error
	store, err = NewPostgresStore(connStr) //Inicialización de conexion PostgreSQL
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer store.db.Close()

	if err := store.InitSchema(); err != nil {
		log.Fatalf("Failed to initialize database schema: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/machines", withInstanceHeader(machinesHandler)) //Responde a solicitudes GET para obtener todas las máquinas
	mux.HandleFunc("/api/machines/", withInstanceHeader(machineHandler)) //Responde a solicitudes GET para obtener información de una máquina específica
	mux.HandleFunc("/heartbeat", withInstanceHeader(heartbeatHandler))   //Responde a solicitudes de heartbeat indicando que el backend de máquinas está vivo

	log.Printf("Service Machines [%s] listening on :8080", instanceID)
	log.Fatal(http.ListenAndServe(":8080", mux))
}
