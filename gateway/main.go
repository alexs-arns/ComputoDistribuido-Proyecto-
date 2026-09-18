package main

import (
	"encoding/json"     //Libreria para codificar y decodificar JSON
	"log"               //Libreria para registrar mensajes de log
	"net/http"          //Libreria para manejar solicitudes HTTP
	"net/http/httputil" //Libreria para crear un proxy inverso HTTP
	"net/url"           //Libreria para analizar y construir URLs
	"os"                //Libreria para interactuar con el sistema operativo
	"strings"           //Libreria para manipular cadenas de texto
	"sync"              //Libreria para manejar concurrencia y sincronización
	"sync/atomic"       //Libreria para operaciones atómicas en variables compartidas
	"time"              //Libreria para manejar tiempo y temporizadores
)

// RouteConfig es una entrada de routes.json: un prefijo de ruta asignado a un conjunto
// de URL de backend. Este es nuestro "descubrimiento de servicios estático": sin registro,
// solo un archivo que se lee al inicio.
type RouteConfig struct {
	Prefix  string   `json:"prefix"`
	Targets []string `json:"targets"`
}

type Backend struct { //Representa un backend, con su URL, proxy inverso y estado de salud.
	URL     *url.URL
	Proxy   *httputil.ReverseProxy
	healthy atomic.Bool
}

type RouteGroup struct { //Representa un grupo de rutas, con su prefijo, lista de backends y contador para round-robin.
	Prefix   string
	Backends []*Backend
	counter  uint64 // atomic; next index = counter % len(Backends)
}

func (rg *RouteGroup) next() *Backend { //Selecciona el siguiente backend en orden round-robin, omitiendo los que están marcados como no saludables
	n := len(rg.Backends)
	for i := 0; i < n; i++ {
		idx := atomic.AddUint64(&rg.counter, 1) % uint64(n) // Incrementa el contador de manera atómica y calcula el índice del siguiente backend
		b := rg.Backends[idx]                               //Se utiliza atomic.AddUint64 para modificar el contador sin riesgo de condiciones de carrera
		if b.healthy.Load() {
			return b
		}
	}
	return nil
}

type Gateway struct { //Gateway con sus grupos de rutas y un semáforo para limitar la concurrencia de solicitudes proxied
	groups []*RouteGroup
	sem    chan struct{} //Canal para limitar la concurrencia de solicitudes proxied
}

func loadRouteConfigs(path string) ([]RouteConfig, error) { //Carga la configuración de rutas desde un archivo estatico JSON.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfgs []RouteConfig                              //Variable para almacenar la configuración de rutas cargada desde el archivo JSON.
	if err := json.Unmarshal(data, &cfgs); err != nil { //Se ecodificaN los datos JSON en la variable cfgs.
		return nil, err
	}
	return cfgs, nil
}

func NewGateway(cfgs []RouteConfig, maxConcurrent int) *Gateway { //Para crear un Gateway con la configuración de rutas y el límite de concurrencia que le demos
	var groups []*RouteGroup

	for _, cfg := range cfgs { //Itera sobre cada configuración de ruta
		rg := &RouteGroup{Prefix: cfg.Prefix} //Le asigna el prefijo de ruta al grupo de rutas
		for _, t := range cfg.Targets {       //Itera sobre cada URL de backend en la configuración de ruta
			target, err := url.Parse(t) //Convierte el URL de backend en un objeto *url.URL
			if err != nil {
				log.Fatalf("invalid target url %s: %v", t, err)
			}
			b := &Backend{ //Crea un nuevo backend con  URL y proxy inverso brindados
				URL:   target,
				Proxy: httputil.NewSingleHostReverseProxy(target),
			}
			b.healthy.Store(true) //Asume que el backend es saludable hasta que la primera verificación de heartbeat diga lo contrario
			rg.Backends = append(rg.Backends, b)
		}
		groups = append(groups, rg)
	}

	return &Gateway{ //Regresa el gateway con los grupos de rutas y el canal para limitar la concurrencia
		groups: groups,
		sem:    make(chan struct{}, maxConcurrent),
	}
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) { //Manejador de solicitudes HTTP para el gateway
	// Permitir solicitudes desde cualquier origen
	w.Header().Set("Access-Control-Allow-Origin", "*")                                // Permitir solicitudes desde cualquier origen
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE") // Permitir métodos HTTP específicos
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")     // Permitir encabezados específicos

	if r.Method == http.MethodOptions { // Manejar solicitudes OPTIONS (CORS preflight)
		w.WriteHeader(http.StatusOK)
		return
	}
	g.sem <- struct{}{} //Se aumenta el contador de solicitudes concurrentes enviando un valor vacío al canal sem.
	// Si el canal está lleno, la goroutine se bloqueará hasta que haya espacio disponible.
	defer func() { <-g.sem }()

	for _, rg := range g.groups { // Itera sobre los grupos de rutas para encontrar el que coincida con el prefijo de la solicitud
		if !strings.HasPrefix(r.URL.Path, rg.Prefix) {
			continue
		}
		backend := rg.next()
		if backend == nil {
			http.Error(w, "no healthy backend available", http.StatusServiceUnavailable)
			return
		}
		log.Printf("[%s] %s -> %s (prefix %q)", r.Method, r.URL.Path, backend.URL, rg.Prefix)
		backend.Proxy.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

func (g *Gateway) startHeartbeatMonitor(interval time.Duration) { //Inicia el monitor heartbeat
	ticker := time.NewTicker(interval) //Crea un ticker que genera un evento en el canal C cada intervalo de tiempo especificado
	go func() {                        //Inicia una goroutine para ejecutar el monitor heartbeat de manera concurrente y en segundo plano
		for range ticker.C { //Cada vez que se cumple el intervalo de tiempo especificado
			var wg sync.WaitGroup
			for _, rg := range g.groups {
				for _, b := range rg.Backends { //Itera sobre cada backend en cada grupo de rutas
					wg.Add(1)             //Incrementa el contador del WaitGroup para esperar a que la verificación de heartbeat de este backend termine
					go func(b *Backend) { //Inicia una goroutine para verificar el heartbeat del backend de manera concurrente
						defer wg.Done()
						b.healthy.Store(checkHeartbeat(b.URL.String()))
					}(b)
				}
			}
			wg.Wait() //Espera a que todas las goroutines de heartbeat terminen antes de continuar con la siguiente iteración del ticker
		}
	}()
}

func checkHeartbeat(target string) bool {
	client := http.Client{Timeout: 2 * time.Second} //Crea un cliente HTTP con un tiempo de espera de 2 segundos para la solicitud
	resp, err := client.Get(target + "/heartbeat")  //Envía una solicitud GET al endpoint /heartbeat del backend
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (g *Gateway) statusHandler(w http.ResponseWriter, r *http.Request) {
	type backendStatus struct { //Estructura privada para representar el estado de un backend, con su URL y estado de salud,
		//con el proposito de codificarlo en JSON para la respuesta HTTP
		Target  string `json:"target"`
		Healthy bool   `json:"healthy"`
	}
	out := make(map[string][]backendStatus) //Mapa de backends agrupados por prefijo de ruta para guardar health status
	for _, rg := range g.groups {
		var list []backendStatus
		for _, b := range rg.Backends {
			list = append(list, backendStatus{Target: b.URL.String(), Healthy: b.healthy.Load()})
		}
		out[rg.Prefix] = list
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out) //Codifica el mapa de estado de backends en JSON y lo escribe en la respuesta HTTP
}

func heartbeatHandler(w http.ResponseWriter, r *http.Request) { //Responde a las solicitudes de hearbeat indicando que el gateway está vivo
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("gateway alive"))
}

func main() {
	cfgs, err := loadRouteConfigs("routes.json") //Carga la configuración de rutas desde el archivo routes.json
	if err != nil {
		log.Fatalf("failed to load routes.json: %v", err)
	}

	gw := NewGateway(cfgs, 10)                //Gateway con maximo 10 solicitudes concurrentes proxied
	gw.startHeartbeatMonitor(5 * time.Second) //Cada 5 segundos se verifica el estado de salud de los backends

	mux := http.NewServeMux()                      //Multiplexor de solicitudes HTTP
	mux.HandleFunc("/heartbeat", heartbeatHandler) //Responde a las solicitudes de heartbeat indicando que el gateway está vivo
	mux.HandleFunc("/status", gw.statusHandler)    //Responde a las solicitudes de status mostrando el estado de salud de los backends
	mux.Handle("/", gw)                            //Todas las demás solicitudes se manejan a través del gateway, que realiza el enrutamiento y balanceo de carga hacia los backends

	log.Println("gateway listening on :8000")
	log.Fatal(http.ListenAndServe(":8000", mux))
}
