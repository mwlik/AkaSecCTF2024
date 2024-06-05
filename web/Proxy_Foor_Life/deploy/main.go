package main

import (
    "io"
    "fmt"
    "net/http"
    _ "net/http/pprof"
    "html/template"
    "github.com/doyensec/safeurl"
)

var templates = template.Must(template.ParseGlob("templates/*.html"))

func indexHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        config := safeurl.GetConfigBuilder().
            Build()

        client := safeurl.Client(config)

        url := r.FormValue("url")

        _, err := client.Get(url)
        if err != nil {
            renderTemplate(w, "index", map[string]string{"error": "The URL you entered is dangerous and not allowed."})
            fmt.Println(err)
            return
        }

        resp, err := http.Get(url)
        if err != nil {
            fmt.Println(err)
            return
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(resp.Body)
        renderTemplate(w, "index", map[string]interface{}{"result": template.HTML(body)})
        return
    }

    renderTemplate(w, "index", nil)
}

// /flag
// function /flag -> return -> 
// {
// code flag commented => from args
// return "NO0"
//

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
    err := templates.ExecuteTemplate(w, tmpl+".html", data)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
    }
}

func main() {
    http.HandleFunc("/", indexHandler)
    http.ListenAndServe(":1337", nil)
}
