// DELIBERATELY vulnerable code. Do not use in production.
package main

func handler(db *sql.DB, id string) {
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)) // INJ001
	exec.Command("sh", "-c", "ping "+id)                              // INJ003
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // CRY002
	_ = client
}
