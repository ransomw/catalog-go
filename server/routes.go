package server

import (
	"bytes"
	"os"
	"io"
	"path/filepath"
	"html/template"
	"io/ioutil"
	"strings"
	"net/http"
	"errors"
	"sync"
	"net/url"
	"encoding/base64"
	"encoding/json"
	"crypto/rand"
	"strconv"
	"mime/multipart"
	"image"
	"image/jpeg"

	"fmt"

	"golang.org/x/crypto/bcrypt"
	"github.com/jinzhu/gorm"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"

	"sand/go-catalog/model"
)

/* templates are divided into "drivers" and "helpers" as in examples at
 * https://golang.org/pkg/text/template/
 * this prevents conflicts with inheritance -- e.g. both home.html
 * and items.html (drivers) can use "base" and "lists" (helpers)
 * without conflict, provided every driver gets its own copy of the
 * helpers.
 *
 * compare go templates to Jinja2:  here in go, the more specific
 * templates *invoke* the less specific templates (with redefs)
 * rather than *extending* them as in Jinja.  since blocks can be
 * redefed precisely once per `Template` pointer, we need a separate
 * dependency tree for every page that appears in the app.
 */
type appTemplates map[string]*template.Template

func (tmpl appTemplates) Exec(
	s *Server, r *http.Request,
	name string, w http.ResponseWriter, data interface{}) error {
	sess := s.sess.GetSession(w, r)
	loggedIn := sess.Get("user_id") != ""
	t, has := tmpl[name]
	if !has {
		return errors.New("can't find template '" + name + "'")
	}
	return t.Lookup("driver").Execute(w,
		struct{
			LoggedIn bool
			Data interface{}
		}{
			LoggedIn: loggedIn,
			Data: data,
		})
}

func loadTemplates() (appTemplates, error) {
	tmplH, err := template.ParseGlob(
		filepath.Join("tmpl", "helpers", "*.html"),
	)
	if err != nil {
		return nil, err
	}
	tmpl := make(map[string]*template.Template)
	driversPath := filepath.Join("tmpl", "drivers")
	files, err := ioutil.ReadDir(driversPath)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		filename := file.Name()
		if !strings.HasSuffix(filename, ".html") {
			continue
		}
		tmplHClone, err := tmplH.Clone()
		if err != nil {
			return tmpl, err
		}
		fileBytes, err := ioutil.ReadFile(
			filepath.Join(driversPath, file.Name()),
		)
		if err != nil {
			return tmpl, err
		}
		t, err := tmplHClone.New("driver").Parse(string(fileBytes))
		if err != nil {
			return tmpl, err
		}
		tmpl[filename] = t
	}
	return tmpl, nil
}

/* sessions impl
 * https://astaxie.gitbooks.io/build-web-application-with-golang/content/en/06.2.html
 */

type sessSession interface {
	Set(key, value string) error
	Get(key string) string
	Delete(key string) error
	SessionID() string
}

type sessMemMapSession struct{
	store map[string]string
	sid string
}

func (s sessMemMapSession) Set(k, v string) error {
	s.store[k] = v
	return nil
}

func (s sessMemMapSession) Get(k string) string {
	return s.store[k]
}

func (s sessMemMapSession) Delete(k string) error {
	delete(s.store, k)
	return nil
}

func (s sessMemMapSession) SessionID() string {
	return s.sid
}

type sessProvider interface {
	SessionInit(sid string) (sessSession, error)
	SessionRead(sid string) (sessSession, error)
	SessionDestroy(sid string) error
}

type sessMemMapProvider map[string]sessMemMapSession

func (sp sessMemMapProvider) SessionInit(
	sid string) (sessSession, error) {
	s := sessMemMapSession{
		store: make(map[string]string),
		sid: sid,
	}
	sp[sid] = s

	fmt.Printf("initialized session %v\n", s)

	return s, nil
}

func (sp sessMemMapProvider) SessionRead(
	sid string) (sessSession, error) {
	s, has := sp[sid]
	if !has {
		return nil, errors.New("session id '"+sid+"' not found")
	}
	return s, nil
}

func (sp sessMemMapProvider) SessionDestroy(
	sid string) error {
	delete(sp, sid)
	return nil
}

type sessManager struct {
	cookieName  string
	lock        sync.Mutex
	provider    sessProvider
}

func (manager *sessManager) sessionId() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}

func (manager *sessManager) GetSession(
	w http.ResponseWriter, r *http.Request) (session sessSession) {
	manager.lock.Lock()
	defer manager.lock.Unlock()
	cookie, err := r.Cookie(manager.cookieName)
	if err != nil || cookie.Value == "" {
		sid := manager.sessionId()
		session, _ = manager.provider.SessionInit(sid)
		cookie := http.Cookie{
			Name: manager.cookieName,
			Value: url.QueryEscape(sid),
			Path: "/",
			HttpOnly: true,
			// todo: garbage-collect cookies
			// MaxAge: int(manager.maxlifetime),
		}
		http.SetCookie(w, &cookie)
	} else {
		sid, _ := url.QueryUnescape(cookie.Value)
		session, _ = manager.provider.SessionRead(sid)
		// in case the browser has cookies set between server runs,
		// create a new session server-side for the existing cookie
		if session == nil {
			session, _ = manager.provider.SessionInit(sid)
		}
	}
	return
}

type Server struct {
	tmpl appTemplates
	db *gorm.DB
	sess *sessManager
}

func NewServer() (*Server, error) {
	tmpl, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	db, err := model.ConnDB()
	if err != nil {
		return nil, err
	}
	sess := &sessManager{
		provider: sessMemMapProvider(make(map[string]sessMemMapSession)),
		cookieName: "cat-c",
	}
	return &Server{tmpl: tmpl, db: db, sess: sess}, nil
}

/* handlers */

func (s *Server) HandleHome() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		var categories []model.Category
		if err = s.db.Find(&categories).Error; err != nil {
			panic(err)
		}
		// todo: sort items by last update timestamp
		// todo: limit items to some constant value
		var items []model.Item
		if err = s.db.Preload("Category").Find(&items).Error; err != nil {
			panic(err)
		}
		err = s.tmpl.Exec(s, r, "home.html", w, struct{
			Categories []model.Category
			Items []model.Item
		}{
			Categories: categories,
			Items: items,
		})
		if err != nil {
			panic(err)
		}
	}
}

/* error view object.
 * most view objects are inlined b/c the template is used
 * only once.
 */
type voError struct {
	Msg string
}

func (s *Server) HandleItemsList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		categoryName := chi.URLParam(r, "categoryName")
		var category model.Category
		resCategory := s.db.Where(
			&model.Category{Name: categoryName},
		).First(&category)
		if resCategory.RecordNotFound() {
			if err := s.tmpl.Exec(s, r, "err.html", w, voError{
				Msg: "catgory '" + categoryName + "' not found",
			}); err != nil {
				panic(err)
			}
			return
		} else if err := resCategory.Error; err != nil {
			panic(err)
		}
		var categories []model.Category
		if err := s.db.Find(&categories).Error; err != nil {
			panic(err)
		}
		var items []model.Item
		if err := s.db.Model(
			&category,
		).Preload("Category").Related(&items).Error; err != nil {
			panic(err)
		}
		if err := s.tmpl.Exec(s, r, "items.html", w, struct{
			Categories []model.Category
			Category model.Category
			Items []model.Item
		}{
			Categories: categories,
			Category: category,
			Items: items,
		}); err != nil {
			panic(err)
		}
	}
}

func (s *Server) HandleItemDetail() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		categoryName := chi.URLParam(r, "categoryName")
		itemTitle := chi.URLParam(r, "itemTitle")
		var category model.Category
		resCategory := s.db.Where(
			&model.Category{Name: categoryName},
		).First(&category)
		if resCategory.RecordNotFound() {
			if err := s.tmpl.Exec(s, r, "err.html", w, voError{
				Msg: "catgory '" + categoryName + "' not found",
			}); err != nil {
				panic(err)
			}
			return
		}
		if err := resCategory.Error; err != nil {
			panic(err)
		}
		var item model.Item
		if err := s.db.Where(
			&model.Item{
				CategoryID: category.ID,
				Title: itemTitle,
			}).First(&item).Error; err != nil {
				panic(err)
			}
		_, imgStatErr := os.Stat(item.GetImageFilepath())
		var hasImg bool
		if imgStatErr == nil {
			hasImg = true
		} else if os.IsNotExist(imgStatErr) {
			hasImg = false
		} else {
			panic(imgStatErr)
		}
		if err := s.tmpl.Exec(s, r, "item.html", w, struct{
			Item model.Item
			HasImg bool
			CanModify bool
			RandQ string
		}{
			Item: item,
			HasImg: hasImg,
			RandQ: "use timestamp, uuid, or randstring util", // todo
		}); err != nil {
			panic(err)
		}
	}
}

func (s *Server) HandleItemImg() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		itemIdStr := chi.URLParam(r, "itemId")
		itemId, err := strconv.Atoi(itemIdStr)
		if err != nil {
			panic(fmt.Errorf("itemId '%v' not an integer: %v", itemId, err))
		}
		var item model.Item
		resItem := s.db.First(&item, itemId)
		if resItem.RecordNotFound() {
			errJsonBytes, err := json.Marshal("contents not found")
			if err != nil {
				panic(fmt.Errorf("marshal json error: %v", err))
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(errJsonBytes)
			w.WriteHeader(401)
			return
		}
		if err := resItem.Error; err != nil {
			panic(err)
		}
		filePath := item.GetImageFilepath()
		pictureFile, err := os.Open(filePath)
		if err != nil {
			panic(err)
		}
		img, fmtName, err := image.Decode(pictureFile)
		if err != nil {
			panic(fmt.Errorf("error opening image file -- " +
				"filePath: %v fmt: %v, err: %v",
				filePath, fmtName, err))
		}
		var imgBytesBuf bytes.Buffer
		if err := jpeg.Encode(&imgBytesBuf, img, nil); err != nil {
			panic(err)
		}
		if err != nil {
			panic(err)
		}
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Content-Length", strconv.Itoa(imgBytesBuf.Len()))
		w.Header().Set("Content-Disposition",
			"attachment; filename="+item.Title+".jpeg")
		imgBytesBuf.WriteTo(w)
	}
}

func (s *Server) HandleLoginGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.tmpl.Exec(
			s, r, "login.html", w, struct{}{}); err != nil {
			panic(err)
		}
	}
}

func (s *Server) HandleLoginPost() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.sess.GetSession(w, r)
		if err := r.ParseForm(); err != nil {
			panic(err)
		}

		fmt.Printf("login form: %v\n", r.Form)

		_, hazSignIn := r.Form["sign-in"]
		_, hazSignUp := r.Form["sign-up"]

		if hazSignIn {
			email := r.Form.Get("email")
			password := r.Form.Get("password")
			var user model.User
			resUser := s.db.Where(
				&model.User{Email: email},
			).First(&user)
			if resUser.RecordNotFound() {
				w.WriteHeader(http.StatusUnauthorized)
				if err := s.tmpl.Exec(s, r, "err.html", w, voError{
					Msg: "no user record not found for email '" + email + "'",
				}); err != nil {
					panic(err)
				}
				return
			} else if err := resUser.Error; err != nil {
				panic(err)
			}
			err := bcrypt.CompareHashAndPassword(
				[]byte(user.Password), []byte(password),
			); if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				if err := s.tmpl.Exec(s, r, "err.html", w, voError{
					Msg: "incorrect password",
				}); err != nil {
					panic(err)
				}
				return
			}
			sess.Set("user_id", strconv.Itoa(int(user.ID)))
		} else if hazSignUp {
			password := r.Form.Get("password")
			passwordConfirm := r.Form.Get("password-confirm")
			email := r.Form.Get("email")
			name := r.Form.Get("name")
			if password != passwordConfirm {
				w.WriteHeader(http.StatusBadRequest)
				if err := s.tmpl.Exec(s, r, "err.html", w, voError{
					Msg: "passwords don't match",
				}); err != nil {
					panic(err)
				}
				return
			}
			if password == "" {
				w.WriteHeader(http.StatusBadRequest)
				if err := s.tmpl.Exec(s, r, "err.html", w, voError{
					Msg: "password may not be blank",
				}); err != nil {
					panic(err)
				}
				return
			}
			var user model.User
			resUser := s.db.Where(
				&model.User{Email: email},
			).First(&user)
			if resUser.RecordNotFound() {
				user = model.User{Email: email}
			} else if err := resUser.Error; err != nil {
				panic(err)
			}
			if user.Password != "" {
				w.WriteHeader(http.StatusUnauthorized)
				if err := s.tmpl.Exec(s, r, "err.html", w, voError{
					Msg: "user already registered",
				}); err != nil {
					panic(err)
				}
				return
			}
			hash, err := bcrypt.GenerateFromPassword(
				[]byte(password), bcrypt.DefaultCost)
			if err != nil {
				panic(err)
			}
			user.Password = string(hash)
			user.Name = name
			err = s.db.Create(&user).Error; if err != nil {
				panic(err)
			}
			if err := s.db.Where(
				&model.User{Email: email},
			).First(&user).Error; err != nil {
				panic(err)
			}
			sess.Set("user_id", strconv.Itoa(int(user.ID)))
		} else {
			w.Write([]byte("must specify sign-in or sign-up"))
			return
		}
		// todo: reverse routes on all redirects
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func (s *Server) HandleLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.sess.GetSession(w, r)
		sess.Delete("user_id")
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

type voNewItem struct {
	Item model.Item
	Categories []model.Category
	HasItem bool
}

func (s *Server) HandleNewItemGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var categories []model.Category
		if err := s.db.Find(&categories).Error; err != nil {
			panic(err)
		}
		if err := s.tmpl.Exec(s, r, "item_add.html", w, voNewItem{
			Categories: categories,
			HasItem: false,
		}); err != nil {
			panic(err)
		}
	}
}

func itemFromForm(form url.Values, db *gorm.DB,
	userID uint) (model.Item, string) {
	title, has := form["title"]
	if !has || len(title) == 0 {
		return model.Item{}, "missing title"
	}
	description, has := form["description"]
	if !has || len(description) == 0 {
		return model.Item{}, "missing description"
	}
	categoryIDStr, has := form["category"]
	if !has || len(categoryIDStr) == 0 {
		return model.Item{}, "missing category"
	}
	categoryID, err := strconv.Atoi(categoryIDStr[0])
	if err != nil {
		panic(err)
	}
	item := model.Item{
		Title: title[0],
		Description: description[0],
		CategoryID: uint(categoryID)}
// skip create.  this function is leftover as a url.Values demo.
/*
	if err := db.Create(&item).Error; err != nil {
		panic(err)
	}
*/
	return item, ""
}

func itemFromMultipartForm(form multipart.Form, db *gorm.DB,
	userID uint) (model.Item, string) {

	fmt.Printf("item multipart form: %v\n", form)

	title, has := form.Value["title"]
	if !has || len(title) == 0 {
		return model.Item{}, "missing title"
	}
	description, has := form.Value["description"]
	if !has || len(description) == 0 {
		return model.Item{}, "missing description"
	}
	categoryIDStr, has := form.Value["category"]
	if !has || len(categoryIDStr) == 0 {
		return model.Item{}, "missing category"
	}
	categoryID, err := strconv.Atoi(categoryIDStr[0])
	if err != nil {
		panic(err)
	}
	item := model.Item{
		Title: title[0],
		Description: description[0],
		CategoryID: uint(categoryID)}
	if err := db.Create(&item).Error; err != nil {
		panic(err)
	}
	pictures := form.File["picture"]
	if len(pictures) == 0 {
		return item, ""
	}
	if len(pictures) > 1 {
		panic(errors.New("expected precisely one picture upload"))
	}
	filePath := item.GetImageFilepath()
	pictureFile, err := pictures[0].Open()
	if err != nil {
		panic(err)
	}
	img, fmtName, err := image.Decode(pictureFile)
	if err != nil {
		fmt.Printf("fmt: %v, err: %v\n", fmtName, err)
		return model.Item{}, "uploaded file was not an image"
	}
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		if err := os.Remove(filePath); err != nil {
			panic(err)
		}
	}
	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		panic(err)
	}
	err = jpeg.Encode(file, img, nil)
	if err != nil {
		panic(err)
	}
	if err := file.Close(); err != nil {
		panic(err)
	}
	return item, ""
}

func (s *Server) HandleNewItemPost() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.sess.GetSession(w, r)
		// use up to 10mb of memory parsing the form.
		// todo: use MultipartReader() to parse as stream
		if err := r.ParseMultipartForm(10^7); err != nil {
			panic(err)
		}
		userIDStr := sess.Get("user_id")
		userID, err := strconv.Atoi(userIDStr)
		if err != nil {
			panic(err)
		}
		itemFromForm(r.Form, s.db, uint(userID))
		_, errMsgForm := itemFromMultipartForm(
			*r.MultipartForm, s.db, uint(userID))
		if errMsgForm != "" {
			if err := s.tmpl.Exec(s, r, "err.html", w, voError{
				Msg: errMsgForm,
			}); err != nil {
				panic(err)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func (s *Server) HandleItemDeleteGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		itemTitle := chi.URLParam(r, "itemTitle")
		var item model.Item
		resItem := s.db.Where(
			&model.Item{
				Title: itemTitle,
			}).First(&item)
		if resItem.RecordNotFound() {
			if err := s.tmpl.Exec(s, r, "err.html", w, voError{
				Msg: "item '" + itemTitle + "' not found",
			}); err != nil {
				panic(err)
			}
			return
		} else if err := resItem.Error; err != nil {
			panic(err)
		}
		if err := s.tmpl.Exec(s, r, "item_delete.html", w, struct{
			Item model.Item
		}{
			Item: item,
		}); err != nil {
			panic(err)
		}
	}
}

func (s *Server) HandleItemDeletePost() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		itemTitle := chi.URLParam(r, "itemTitle")
		var item model.Item
		resItem := s.db.Where(
			&model.Item{
				Title: itemTitle,
			}).First(&item)
		if resItem.RecordNotFound() {
			if err := s.tmpl.Exec(s, r, "err.html", w, voError{
				Msg: "item '" + itemTitle + "' not found",
			}); err != nil {
				panic(err)
			}
			return
		} else if err := resItem.Error; err != nil {
			panic(err)
		}
		if err := s.db.Delete(&item).Error; err != nil {
			panic(err)
		}
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

/* middleware */

func (s *Server) mwLoginRequired() func(http.Handler) http.Handler {
	return func (next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				sess := s.sess.GetSession(w, r)
				if sess.Get("user_id") == "" {
					http.Redirect(w, r, "/login", http.StatusFound)
				} else {
					next.ServeHTTP(w, r)
				}
			})
	}
}

func InitRouter(srv *Server) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/", srv.HandleHome())

	r.Route("/catalog/item/new", func(r chi.Router) {
		r.Use(srv.mwLoginRequired())
		r.Get("/", srv.HandleNewItemGet())
		r.Post("/", srv.HandleNewItemPost())
	})

	r.Route("/catalog/{itemTitle}/delete", func(r chi.Router) {
		r.Use(srv.mwLoginRequired())
		r.Get("/", srv.HandleItemDeleteGet())
		r.Post("/", srv.HandleItemDeletePost())
	})

	r.Get("/catalog/{categoryName}/items",
		srv.HandleItemsList())


	r.Get("/catalog/{categoryName}/{itemTitle}",
		srv.HandleItemDetail())

	r.Get("/catalog/item/{itemId}/img",
		srv.HandleItemImg())

	r.Route("/login", func(r chi.Router) {
		r.Get("/", srv.HandleLoginGet())
		r.Post("/", srv.HandleLoginPost())
	})

	r.Get("/logout", srv.HandleLogout())

	fileServer(r, "/assets", http.Dir("./public/assets"))

	return r
}

// sets up a http.FileServer handler to serve
// static files from a http.FileSystem.
func fileServer(r chi.Router, path string, root http.FileSystem) {
	if strings.ContainsAny(path, "{}*") {
		panic("FileServer does not permit URL parameters.")
	}

	fs := http.StripPrefix(path, http.FileServer(root))

	if path != "/" && path[len(path)-1] != '/' {
		r.Get(path, http.RedirectHandler(path+"/", 301).ServeHTTP)
		path += "/"
	}
	path += "*"

	r.Get(path, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			fs.ServeHTTP(w, r)
		}))
}
