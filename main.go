package main

import (
        "database/sql"
        "encoding/json"
        "log"
        "net/http"
        "os"
        "strings"
        "sync"
        "time"

        _ "modernc.org/sqlite"
        "golang.org/x/crypto/bcrypt"
)

var db *sql.DB

// unlockLimiter tracks failed password attempts per (ip, pasteID) pair.
// After 10 failed attempts within 10 minutes the endpoint returns 429.
var unlockLimiter = struct {
        mu      sync.Mutex
        entries map[string]*attemptEntry
}{entries: make(map[string]*attemptEntry)}

type attemptEntry struct {
        count     int
        windowEnd time.Time
}

func checkUnlockRate(ip, id string) bool {
        key := ip + "|" + id
        unlockLimiter.mu.Lock()
        defer unlockLimiter.mu.Unlock()

        now := time.Now()
        e, ok := unlockLimiter.entries[key]
        if !ok || now.After(e.windowEnd) {
                unlockLimiter.entries[key] = &attemptEntry{count: 1, windowEnd: now.Add(10 * time.Minute)}
                return true
        }
        e.count++
        return e.count <= 10
}

func recordUnlockSuccess(ip, id string) {
        key := ip + "|" + id
        unlockLimiter.mu.Lock()
        defer unlockLimiter.mu.Unlock()
        delete(unlockLimiter.entries, key)
}

func main() {
        var err error
        db, err = sql.Open("sqlite", "./devpaste.db")
        if err != nil {
                log.Fatal("Failed to open database:", err)
        }
        defer db.Close()

        if err := initDB(); err != nil {
                log.Fatal("Failed to initialize database:", err)
        }

        go cleanupExpired()

        mux := http.NewServeMux()

        fs := http.FileServer(http.Dir("./static"))
        mux.HandleFunc("/", serveHomePage)
        mux.HandleFunc("/new", serveNewPage)
        mux.HandleFunc("/view/", serveViewPage)
        mux.Handle("/style.css", fs)
        mux.Handle("/hero-bg.jpg", fs)
        mux.HandleFunc("/api/paste", handlePaste)
        mux.HandleFunc("/api/paste/", handlePasteByID)

        port := os.Getenv("PORT")
        if port == "" {
                port = "5000"
        }

        log.Printf("DevPaste server starting on :%s", port)
        if err := http.ListenAndServe(":"+port, securityHeaders(mux)); err != nil {
                log.Fatal(err)
        }
}

func securityHeaders(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                h := w.Header()

                // Only allow resources (scripts, styles, images, API calls) from this origin.
                // connect-src 'self' is critical: even if JS were tampered with, it cannot
                // send data to any external server.
                h.Set("Content-Security-Policy",
                        "default-src 'self'; "+
                                "script-src 'self' 'unsafe-inline'; "+
                                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
                                "img-src 'self' data:; "+
                                "font-src 'self' https://fonts.gstatic.com; "+
                                "connect-src 'self'; "+
                                "frame-ancestors 'none'; "+
                                "base-uri 'self'; "+
                                "form-action 'self'; "+
                                "object-src 'none'",
                )

                // Prevents the URL (including the #key fragment on view pages) from leaking
                // via the Referer header when users click outbound links.
                h.Set("Referrer-Policy", "no-referrer")

                // Prevent browsers from MIME-sniffing the content type.
                h.Set("X-Content-Type-Options", "nosniff")

                // Block this app from being embedded in iframes (clickjacking protection).
                h.Set("X-Frame-Options", "DENY")

                // Disable browser features this app does not use.
                h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")

                next.ServeHTTP(w, r)
        })
}

func initDB() error {
        _, err := db.Exec(`
                CREATE TABLE IF NOT EXISTS pastes (
                        id TEXT PRIMARY KEY,
                        encrypted_content TEXT NOT NULL,
                        iv TEXT NOT NULL,
                        password_hash TEXT,
                        expires_at INTEGER NOT NULL,
                        burn_after_read INTEGER NOT NULL DEFAULT 0,
                        read_at INTEGER,
                        created_at INTEGER NOT NULL
                )
        `)
        return err
}

func cleanupExpired() {
        ticker := time.NewTicker(5 * time.Minute)
        for range ticker.C {
                now := time.Now().Unix()
                res, err := db.Exec(`DELETE FROM pastes WHERE expires_at < ? OR (burn_after_read = 1 AND read_at IS NOT NULL AND read_at < ?)`, now, now-60)
                if err == nil {
                        n, _ := res.RowsAffected()
                        if n > 0 {
                                log.Printf("Cleaned up %d expired pastes", n)
                        }
                }
        }
}

func serveHomePage(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/" {
                http.NotFound(w, r)
                return
        }
        http.ServeFile(w, r, "./static/home.html")
}

func serveNewPage(w http.ResponseWriter, r *http.Request) {
        http.ServeFile(w, r, "./static/new.html")
}

func serveViewPage(w http.ResponseWriter, r *http.Request) {
        http.ServeFile(w, r, "./static/view.html")
}

type CreatePasteRequest struct {
        EncryptedContent string `json:"encrypted_content"`
        IV               string `json:"iv"`
        TTL              int64  `json:"ttl"`
        BurnAfterRead    bool   `json:"burn_after_read"`
        Password         string `json:"password"`
}

type CreatePasteResponse struct {
        ID string `json:"id"`
}

type PasteResponse struct {
        ID               string `json:"id"`
        EncryptedContent string `json:"encrypted_content"`
        IV               string `json:"iv"`
        HasPassword      bool   `json:"has_password"`
        BurnAfterRead    bool   `json:"burn_after_read"`
        ExpiresAt        int64  `json:"expires_at"`
}

func handlePaste(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        if r.Method != http.MethodPost {
                http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
                return
        }

        r.Body = http.MaxBytesReader(w, r.Body, 2<<20) // 2 MB max payload
        var req CreatePasteRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                http.Error(w, `{"error":"invalid request or payload too large"}`, http.StatusBadRequest)
                return
        }

        if req.EncryptedContent == "" || req.IV == "" {
                http.Error(w, `{"error":"missing content or IV"}`, http.StatusBadRequest)
                return
        }

        if req.TTL <= 0 {
                req.TTL = 86400
        }
        maxTTL := int64(30 * 24 * 3600)
        if req.TTL > maxTTL {
                req.TTL = maxTTL
        }

        expiresAt := time.Now().Unix() + req.TTL

        id := generateID()

        var passwordHash string
        if req.Password != "" {
                hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
                if err != nil {
                        http.Error(w, `{"error":"failed to hash password"}`, http.StatusInternalServerError)
                        return
                }
                passwordHash = string(hash)
        }

        burnInt := 0
        if req.BurnAfterRead {
                burnInt = 1
        }

        _, err := db.Exec(
                `INSERT INTO pastes (id, encrypted_content, iv, password_hash, expires_at, burn_after_read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                id, req.EncryptedContent, req.IV, nullableString(passwordHash), expiresAt, burnInt, time.Now().Unix(),
        )
        if err != nil {
                log.Println("DB insert error:", err)
                http.Error(w, `{"error":"failed to save paste"}`, http.StatusInternalServerError)
                return
        }

        json.NewEncoder(w).Encode(CreatePasteResponse{ID: id})
}

func handlePasteByID(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")

        path := strings.TrimPrefix(r.URL.Path, "/api/paste/")
        parts := strings.SplitN(path, "/", 2)
        id := parts[0]
        action := ""
        if len(parts) > 1 {
                action = parts[1]
        }

        if id == "" {
                http.Error(w, `{"error":"missing id"}`, http.StatusBadRequest)
                return
        }

        switch r.Method {
        case http.MethodGet:
                if action == "" {
                        getPaste(w, r, id)
                } else {
                        http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
                }
        case http.MethodPost:
                if action == "unlock" {
                        unlockPaste(w, r, id)
                } else {
                        http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
                }
        default:
                http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
        }
}

type pasteRow struct {
        id               string
        encryptedContent string
        iv               string
        passwordHash     sql.NullString
        expiresAt        int64
        burnAfterRead    int
        readAt           sql.NullInt64
}

func fetchPaste(id string) (*pasteRow, error) {
        row := db.QueryRow(
                `SELECT id, encrypted_content, iv, password_hash, expires_at, burn_after_read, read_at FROM pastes WHERE id = ?`,
                id,
        )
        var p pasteRow
        err := row.Scan(&p.id, &p.encryptedContent, &p.iv, &p.passwordHash, &p.expiresAt, &p.burnAfterRead, &p.readAt)
        return &p, err
}

func getPaste(w http.ResponseWriter, r *http.Request, id string) {
        p, err := fetchPaste(id)
        if err == sql.ErrNoRows {
                http.Error(w, `{"error":"paste not found"}`, http.StatusNotFound)
                return
        }
        if err != nil {
                http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
                return
        }

        now := time.Now().Unix()
        if p.expiresAt < now {
                db.Exec(`DELETE FROM pastes WHERE id = ?`, id)
                http.Error(w, `{"error":"paste has expired"}`, http.StatusGone)
                return
        }

        if p.burnAfterRead == 1 && p.readAt.Valid {
                db.Exec(`DELETE FROM pastes WHERE id = ?`, id)
                http.Error(w, `{"error":"paste has already been read"}`, http.StatusGone)
                return
        }

        if p.passwordHash.Valid {
                json.NewEncoder(w).Encode(map[string]interface{}{
                        "id":              p.id,
                        "has_password":    true,
                        "burn_after_read": p.burnAfterRead == 1,
                        "expires_at":      p.expiresAt,
                })
                return
        }

        if p.burnAfterRead == 1 {
                db.Exec(`UPDATE pastes SET read_at = ? WHERE id = ?`, now, id)
        }

        json.NewEncoder(w).Encode(PasteResponse{
                ID:               p.id,
                EncryptedContent: p.encryptedContent,
                IV:               p.iv,
                HasPassword:      false,
                BurnAfterRead:    p.burnAfterRead == 1,
                ExpiresAt:        p.expiresAt,
        })
}

type UnlockRequest struct {
        Password string `json:"password"`
}

func clientIP(r *http.Request) string {
        if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
                return strings.SplitN(fwd, ",", 2)[0]
        }
        return strings.SplitN(r.RemoteAddr, ":", 2)[0]
}

func unlockPaste(w http.ResponseWriter, r *http.Request, id string) {
        ip := clientIP(r)
        if !checkUnlockRate(ip, id) {
                http.Error(w, `{"error":"too many attempts, try again later"}`, http.StatusTooManyRequests)
                return
        }

        r.Body = http.MaxBytesReader(w, r.Body, 1<<10) // 1 KB max for password payload
        var req UnlockRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
                return
        }

        p, err := fetchPaste(id)
        if err == sql.ErrNoRows {
                http.Error(w, `{"error":"paste not found"}`, http.StatusNotFound)
                return
        }
        if err != nil {
                http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
                return
        }

        now := time.Now().Unix()
        if p.expiresAt < now {
                db.Exec(`DELETE FROM pastes WHERE id = ?`, id)
                http.Error(w, `{"error":"paste has expired"}`, http.StatusGone)
                return
        }

        if p.burnAfterRead == 1 && p.readAt.Valid {
                db.Exec(`DELETE FROM pastes WHERE id = ?`, id)
                http.Error(w, `{"error":"paste has already been read"}`, http.StatusGone)
                return
        }

        if !p.passwordHash.Valid {
                http.Error(w, `{"error":"paste is not password protected"}`, http.StatusBadRequest)
                return
        }

        if err := bcrypt.CompareHashAndPassword([]byte(p.passwordHash.String), []byte(req.Password)); err != nil {
                http.Error(w, `{"error":"incorrect password"}`, http.StatusUnauthorized)
                return
        }

        recordUnlockSuccess(ip, id) // clear attempt counter on success

        if p.burnAfterRead == 1 {
                db.Exec(`UPDATE pastes SET read_at = ? WHERE id = ?`, now, id)
        }

        json.NewEncoder(w).Encode(PasteResponse{
                ID:               p.id,
                EncryptedContent: p.encryptedContent,
                IV:               p.iv,
                HasPassword:      true,
                BurnAfterRead:    p.burnAfterRead == 1,
                ExpiresAt:        p.expiresAt,
        })
}

func nullableString(s string) interface{} {
        if s == "" {
                return nil
        }
        return s
}

func generateID() string {
        const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        b := make([]byte, 32)
        f, _ := os.Open("/dev/urandom")
        defer f.Close()
        f.Read(b)
        for i := range b {
                b[i] = charset[int(b[i])%len(charset)]
        }
        return string(b)
}
