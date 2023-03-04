package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"log"
	"math/big"
	"net/http"
	"server/myaes"
)

var connectionsList map[string]*websocket.Conn

var UP = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// var userKey map[string]string = map[string]string{"admin": "202cb962ac59075b964b07152d234b70"}
var SessionKeyList map[string][]byte

func myPow(M *big.Int, E *big.Int, N *big.Int) *big.Int {
	var c big.Int
	c.Exp(M, E, N)

	return &c
}

type msg_to_server struct {
	ID      string `json:"ID"`
	Payload string `json:"Payload"`
}

type DHExchange struct {
	P        *big.Int
	G        *big.Int
	A        *big.Int
	B        *big.Int
	Username string
}

func testkey() {
	//userKey["user1"] = "202cb962ac59075b964b07152d234b70"

	g, _ := rand.Prime(rand.Reader, 100)
	p, _ := rand.Prime(rand.Reader, 128)
	a, _ := rand.Prime(rand.Reader, 10)
	b, _ := rand.Prime(rand.Reader, 10)
	fmt.Println(g, p, a, b)
	fmt.Println(myPow(big.NewInt(2), big.NewInt(2), big.NewInt(10)))
	bigA := myPow(g, a, p)
	bigB := myPow(g, b, p)
	k1 := myPow(bigB, a, p)
	k2 := myPow(bigA, b, p)
	fmt.Println(k1)
	fmt.Println(k2)
	tmphash := md5.New()
	tmphash.Write(k1.Bytes())
	shearedKey := tmphash.Sum(nil)
	fmt.Println(hex.EncodeToString(shearedKey))

}
func initkey(conn *websocket.Conn) (string, []byte) {

	G, _ := rand.Prime(rand.Reader, 100)
	P, _ := rand.Prime(rand.Reader, 128)
	a, _ := rand.Prime(rand.Reader, 10)
	bigA := myPow(G, a, P)
	server_hello := &DHExchange{
		P,
		G,
		bigA,
		nil,
		"",
	}

	//send server hello
	plaintext, _ := json.Marshal(&server_hello)
	conn.WriteMessage(websocket.TextMessage, plaintext)

	// recv client hello
	var client_hello DHExchange
	_, plaintext, _ = conn.ReadMessage()
	_ = json.Unmarshal(plaintext, &client_hello)

	//compelet key
	bigB := client_hello.B
	k2 := myPow(bigB, a, P)
	tmphash := md5.New()
	tmphash.Write(k2.Bytes())

	//存储秘钥
	var shearedkey []byte
	shearedkey = tmphash.Sum(nil)

	//SessionKeys[client_hello.Username] = shearedkey
	//test aes
	checkEnc := myaes.EncryptecbMode_withPadding([]byte("hello"), shearedkey)
	conn.WriteMessage(websocket.TextMessage, checkEnc)
	fmt.Println("done")
	return client_hello.Username, shearedkey

}
func handler(w http.ResponseWriter, r *http.Request) {
	//testkey()

	conn, err := UP.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}

	SessionID, _ := initkey(conn)
	fmt.Println(SessionID, "加入会话")
	//os.Exit(0)
	//connectionsList = append(connectionsList, conn)
	connectionsList[SessionID] = conn
	SessionKeyList["user1"] = []byte("1111111111111111")
	SessionKeyList["user2"] = []byte("2222222222222222")

	for {
		var recv_json msg_to_server

		//targetConn := conn
		_, data, err := conn.ReadMessage()
		_ = json.Unmarshal(data, &recv_json)

		targetKey := SessionKeyList[recv_json.ID]
		//fmt.Println("base64文本", recv_json.Payload)
		encBytes, _ := base64.StdEncoding.DecodeString(recv_json.Payload)
		fmt.Println("发送者", recv_json.ID)
		fmt.Println("对应密钥", string(targetKey))

		plaintext := myaes.DecryptecbMode_withUnpadding(encBytes, targetKey)

		if err != nil {
			break
		}

		for key, _ := range connectionsList { //[朴实无华的广播功能
			fmt.Println("向" + key + "加密并传送消息")
			data := myaes.EncryptecbMode_withPadding(plaintext, SessionKeyList[key])
			connectionsList[key].WriteMessage(websocket.TextMessage, data)
		}
		fmt.Println("广播完成")

		//conn.WriteMessage(websocket.TextMessage, []byte("你说得对"))
	}
	log.Println("未收到消息 client 客户端关闭")
}
func main() {
	connectionsList = make(map[string]*websocket.Conn)
	SessionKeyList = make(map[string][]byte)
	port := "9999"

	fmt.Println("server start on port" + port)
	http.HandleFunc("/", handler)
	http.ListenAndServe(":"+port, nil)

}
